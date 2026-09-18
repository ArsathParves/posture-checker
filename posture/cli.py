"""CLI renderer."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .checks import SECTIONS, grade, run

console = Console()

STATUS_STYLE = {
    "PASS": ("[bold green]PASS[/]", "green"),
    "WARN": ("[bold yellow]WARN[/]", "yellow"),
    "FAIL": ("[bold red]FAIL[/]", "red"),
    "INFO": ("[dim]INFO[/]", "dim"),
    "UNKNOWN": ("[bold magenta] ?  [/]", "magenta"),
}

GRADE_COLOR = {"A": "bold green", "B": "green", "C": "yellow", "D": "orange3",
               "F": "bold red", "—": "dim"}

# Each failing finding maps to the VergeCloud capability that addresses it.
REMEDIATION = {
    "DNSSEC status": "VergeCloud ADNS supports one-click DNSSEC signing with managed key rollover.",
    "Nameserver count": "VergeCloud ADNS provides a redundant anycast nameserver set by default.",
    "Parent delegation vs zone NS": "VergeCloud onboarding validates parent-side delegation against the served zone.",
    "Nameserver reachability": "VergeCloud anycast removes single-node reachability failure.",
    "Network diversity": "VergeCloud ADNS runs across a distributed anycast network.",
    "CAA record": "VergeCloud ADNS lets you publish CAA policy from the same control panel.",
    "SPF": "VergeCloud DNS management simplifies SPF record maintenance.",
    "SPF DNS lookup count": "SPF flattening keeps you inside the 10-lookup RFC limit.",
    "DMARC policy": "VergeCloud can host DMARC records and aggregate reporting endpoints.",
    "AAAA record (IPv6)": "VergeCloud ADNS is dual-stack (IPv4 + IPv6) by default.",
    "IPv6 (AAAA) on nameservers": "VergeCloud nameservers are dual-stack.",
    "CNAME at apex": "VergeCloud ADNS supports apex aliasing without violating RFC 1034.",
    "Expiry": "Renewal is handled at your registrar — VergeCloud can alert on approaching expiry.",
}


def render(rep, show_info=True, as_json=False):
    if as_json:
        payload = {
            "domain": rep.domain, "punycode": rep.punycode,
            "checked_at": datetime.fromtimestamp(rep.checked_at, timezone.utc).isoformat(),
            "grades": grade(rep),
            "degraded_modules": rep.degraded,
            "findings": [f.__dict__ for f in rep.findings],
            "data": _jsonable(rep.data),
        }
        print(json.dumps(payload, indent=2, default=str))
        return

    g = grade(rep)
    ts = datetime.fromtimestamp(rep.checked_at, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ---- header
    name = rep.domain
    if rep.punycode != rep.domain:
        name = f"{rep.domain}  ({rep.punycode})"
    header = Text()
    header.append(f"{name}\n", style="bold white")
    header.append("Overall posture: ", style="dim")
    header.append(f"{g['overall']}", style=GRADE_COLOR[g["overall"]])
    if g.get("correctness_grade") and g["correctness_grade"] != "—":
        header.append("    Correctness: ", style="dim")
        header.append(f"{g['correctness_grade']}",
                      style=GRADE_COLOR.get(g["correctness_grade"], "white"))
    if g.get("hardening_grade") and g["hardening_grade"] != "—":
        header.append("    Hardening: ", style="dim")
        header.append(f"{g['hardening_grade']}",
                      style=GRADE_COLOR.get(g["hardening_grade"], "white"))
    if g.get("provisional"):
        header.append("  (provisional)", style="yellow")
    header.append(f"\nChecked as of {ts}", style="dim")
    if rep.degraded:
        header.append(f"\n⚠ Degraded modules (incomplete data): {', '.join(rep.degraded)}",
                      style="yellow")
    if g.get("ungraded_sections"):
        header.append(f"\n⚠ Not graded (excluded from overall): "
                      f"{', '.join(g['ungraded_sections'])}", style="yellow")
    if g.get("unknown_in"):
        header.append(f"\n⚠ Unresolved checks in: {', '.join(g['unknown_in'])}",
                      style="yellow")
    console.print(Panel(header, title="Domain Posture Check", border_style="cyan"))

    # ---- sections
    for sec in SECTIONS:
        findings = rep.section(sec)
        if not findings:
            continue
        if not show_info:
            findings = [f for f in findings if f.status != "INFO"]
            if not findings:
                continue
        band, _ = g["sections"].get(sec, ("—", None))
        t = Table(show_header=True, header_style="bold", box=None, padding=(0, 1),
                  expand=False)
        t.add_column("", width=6)
        t.add_column("Check", style="white", width=32)
        t.add_column("Detail", overflow="fold")
        for f in findings:
            mark = STATUS_STYLE[f.status][0]
            detail = f.detail
            if f.why:
                detail += f"\n[dim]{f.why}[/dim]"
            t.add_row(mark, f.label, detail)
        console.print(Panel(t, title=f"[bold]{sec}[/]  ·  grade [{GRADE_COLOR[band]}]{band}[/]",
                            title_align="left", border_style="grey37"))

    # ---- findings summary, worst first
    issues = [f for f in rep.findings if f.status in ("FAIL", "WARN")]
    issues.sort(key=lambda f: 0 if f.status == "FAIL" else 1)
    if issues:
        t = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        t.add_column("", width=6)
        t.add_column("Issue", width=34)
        t.add_column("What it means / next step", overflow="fold")
        for f in issues:
            fix = REMEDIATION.get(f.label, "")
            txt = f.why or f.detail
            if fix:
                txt += f"\n[cyan]→ {fix}[/cyan]"
            t.add_row(STATUS_STYLE[f.status][0], f.label, txt)
        console.print(Panel(t, title="[bold]Findings — worst first[/]", title_align="left",
                            border_style="red"))
    else:
        console.print(Panel("No issues detected in the checks performed.",
                            border_style="green"))

    console.print(
        "[dim]Prototype. Results are a point-in-time snapshot of public DNS/RDAP data. "
        "DKIM 'not found' means not found under common selectors, not that DKIM is absent. "
        "Performance benchmarking (RIPE Atlas) is not included in this build.[/dim]")


def _jsonable(d):
    try:
        json.dumps(d, default=str)
        return d
    except Exception:
        return {k: str(v) for k, v in d.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="posture", description="VergeCloud domain posture checker (CLI prototype)")
    ap.add_argument("domain", help="domain to check, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-info", action="store_true", help="hide INFO rows")
    ap.add_argument("--dkim-selector", action="append", default=[],
                    help="additional DKIM selector to probe (repeatable)")
    ap.add_argument("--skip-asn", action="store_true",
                    help="skip IP-RDAP/ASN operator lookups (faster)")
    args = ap.parse_args(argv)

    try:
        rep = run(args.domain, dkim_selectors=args.dkim_selector, skip_asn=args.skip_asn)
    except ValueError as e:
        console.print(f"[bold red]Input error:[/] {e}")
        return 2
    except Exception as e:
        console.print(f"[bold red]Unexpected failure:[/] {type(e).__name__}: {e}")
        return 1

    render(rep, show_info=not args.no_info, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
