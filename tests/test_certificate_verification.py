import socket
import ssl
import unittest
from unittest.mock import Mock, patch

import app


class FakeTLSConnection:
    def __init__(self, certificate):
        self.certificate = certificate

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def getpeercert(self):
        return self.certificate

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def version(self):
        return "TLSv1.3"


class CertificateVerificationTests(unittest.TestCase):
    def test_context_requires_chain_and_san_hostname_verification(self):
        context = app._create_verification_context()

        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertFalse(context.hostname_checks_common_name)

    def test_verified_handshake_returns_all_sans_including_youtube_at_position_55(self):
        san_entries = [
            ("DNS", f"host-{index}.example.com")
            for index in range(1, 55)
        ]
        san_entries.append(("DNS", "youtube.com"))
        certificate = {
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2030 GMT",
            "subjectAltName": tuple(san_entries),
        }
        tls = FakeTLSConnection(certificate)
        context = Mock()
        context.wrap_socket.return_value = tls
        raw = Mock()
        address = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            ("203.0.113.10", 443),
        )

        with (
            patch("app._create_verification_context", return_value=context),
            patch("app.public_addresses", return_value=[address]),
            patch("app.socket.socket", return_value=raw),
        ):
            result = app.inspect_certificate("youtube.com")

        context.wrap_socket.assert_called_once_with(
            raw, server_hostname="youtube.com"
        )
        self.assertEqual(result["subject_alt_names"], [value for _, value in san_entries])
        self.assertEqual(result["subject_alt_names_count"], 55)
        self.assertEqual(result["subject_alt_names"][54], "youtube.com")
        self.assertTrue(result["domain_verified"])
        self.assertTrue(result["certificate_verified"])

    def test_hostname_verification_failure_never_returns_verified_result(self):
        context = Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "hostname mismatch"
        )
        raw = Mock()
        address = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            ("203.0.113.10", 443),
        )

        with (
            patch("app._create_verification_context", return_value=context),
            patch("app.public_addresses", return_value=[address]),
            patch("app.socket.socket", return_value=raw),
        ):
            with self.assertRaisesRegex(RuntimeError, "Certificate verification failed"):
                app.inspect_certificate("wrong.example.com")

        raw.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
