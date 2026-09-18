"""Tests for DNSSEC fixes (N1 and related)."""
import pytest
import dns.query
import dns.message
import dns.flags
import dns.rdatatype
import dns.name
from unittest.mock import patch, MagicMock

from posture.dnsmod import dnssec_status


class TestDNSSECADBitFallback:
    """Test N1: AD-bit query should fallback through multiple resolvers."""

    def test_ad_bit_uses_fallback_when_primary_fails(self):
        """Test that AD-bit check retries on primary resolver failure."""
        # Mock dns.query.udp to fail on first resolver (8.8.8.8)
        # but succeed on second (1.1.1.1)
        call_count = 0

        def mock_udp(q, ip, timeout=None):
            nonlocal call_count
            call_count += 1
            if ip == "8.8.8.8":
                # Primary fails
                raise Exception("Primary resolver unavailable")
            elif ip == "1.1.1.1":
                # Secondary succeeds with AD bit set
                resp = MagicMock()
                resp.rcode.return_value = 0  # NOERROR
                resp.flags = dns.flags.AD  # AD bit set
                resp.answer = []
                return resp
            raise Exception(f"Unexpected resolver: {ip}")

        with patch('posture.dnsmod.dns.query.udp', side_effect=mock_udp):
            result = dnssec_status("cloudflare.com")

            # Should have made at least 2 calls (tried fallback)
            assert call_count >= 2, f"Expected at least 2 resolver calls, got {call_count}"
            # AD should be determined (not inconclusive)
            assert result["ad_authenticated"] is not None, "AD-bit should be determined via fallback"
            assert result["ad_authenticated"] is True, "AD should be True when secondary resolver confirms"

    def test_ad_bit_marks_inconclusive_when_all_fail(self):
        """Test that AD-bit check is marked inconclusive when all resolvers fail."""
        def mock_udp(q, ip, timeout=None):
            # All resolvers fail
            raise Exception(f"Resolver {ip} unavailable")

        with patch('posture.dnsmod.dns.query.udp', side_effect=mock_udp):
            result = dnssec_status("cloudflare.com")

            # AD should be None (inconclusive) not False
            assert result["ad_authenticated"] is None, "AD-bit should be None when all resolvers fail"
            # Should have a note about the failure
            assert any("inconclusive" in note.lower() for note in result["notes"]), \
                "Should note that AD-bit check was inconclusive"

    def test_ad_bit_detects_servfail(self):
        """Test that SERVFAIL response is detected correctly."""
        def mock_udp(q, ip, timeout=None):
            resp = MagicMock()
            resp.rcode.return_value = 1  # SERVFAIL
            resp.flags = 0
            resp.answer = []
            return resp

        with patch('posture.dnsmod.dns.query.udp', side_effect=mock_udp):
            result = dnssec_status("dnssec-failed.org")  # Known broken DNSSEC

            # SERVFAIL should be detected as false (not authenticated)
            assert result["ad_authenticated"] is False, "SERVFAIL should result in ad_authenticated=False"
            assert any("SERVFAIL" in note for note in result["notes"]), \
                "Should note SERVFAIL in the result"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
