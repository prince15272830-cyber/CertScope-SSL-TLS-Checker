import ipaddress
import socket
import ssl
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024  # small JSON requests only


def normalize_domain(raw: str) -> str:
    """Accept a hostname only; do not accept URLs, ports, paths, or IP literals."""
    value = (raw or "").strip().lower()
    if value.startswith(("https://", "http://")):
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in value:
        raise ValueError("Enter only a domain name without a port.")
    value = value.rstrip(".")
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        raise ValueError("Enter a valid domain, such as example.com.")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")

    try:
        hostname = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain name is not valid.") from exc

    labels = hostname.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63
        or label.startswith("-") or label.endswith("-")
        or not all(c.isalnum() or c == "-" for c in label)
        for label in labels
    ):
        raise ValueError("Enter a fully qualified domain, such as example.com.")
    return hostname


def public_addresses(hostname: str):
    """Resolve the host and reject private, loopback, link-local and reserved IPs."""
    try:
        records = socket.getaddrinfo(
            hostname, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise RuntimeError("The domain could not be resolved. Check its spelling.") from exc

    results = []
    seen = set()
    for family, socktype, proto, canonname, sockaddr in records:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            raise RuntimeError(
                "This domain resolves to a non-public address. Private or local targets are blocked."
            )
        key = (family, socktype, proto, sockaddr)
        if key not in seen:
            seen.add(key)
            results.append(key)
    if not results:
        raise RuntimeError("No public address was found for this domain.")
    return results


def decode_name(name_parts):
    values = []
    for group in name_parts or ():
        for key, value in group:
            values.append(f"{key}={value}")
    return ", ".join(values) or "Not provided"


def _create_verification_context():
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.hostname_checks_common_name = False
    return context


def inspect_certificate(hostname: str):
    context = _create_verification_context()
    addresses = public_addresses(hostname)
    last_error = None

    for family, socktype, proto, sockaddr in addresses:
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(8)
        try:
            # Connect to the already-validated resolved address. SNI still uses
            # the original hostname, and the default context verifies the cert.
            raw.connect(sockaddr)
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                if not cert:
                    raise ssl.SSLError("The server did not provide a readable certificate.")

                not_before_ts = ssl.cert_time_to_seconds(cert["notBefore"])
                not_after_ts = ssl.cert_time_to_seconds(cert["notAfter"])
                now = datetime.now(timezone.utc)
                valid_from = datetime.fromtimestamp(not_before_ts, timezone.utc)
                valid_until = datetime.fromtimestamp(not_after_ts, timezone.utc)
                days_left = (valid_until - now).days

                cipher = tls.cipher()
                sans = [
                    value for kind, value in cert.get("subjectAltName", ())
                    if kind in ("DNS", "IP Address")
                ]

                return {
                    "domain": hostname,
                    "status": "Valid" if days_left >= 0 else "Expired",
                    "issuer": decode_name(cert.get("issuer")),
                    "subject": decode_name(cert.get("subject")),
                    "valid_from": valid_from.strftime("%d %b %Y %H:%M:%S UTC"),
                    "expiry_date": valid_until.strftime("%d %b %Y %H:%M:%S UTC"),
                    "days_remaining": days_left,
                    "tls_version": tls.version() or "Unknown",
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "cipher_bits": cipher[2] if cipher else None,
                    "subject_alt_names": sans,
                    "subject_alt_names_count": len(sans),
                    "domain_verified": True,
                    "certificate_verified": True,
                }
        except Exception as exc:
            last_error = exc
            try:
                raw.close()
            except OSError:
                pass

    if isinstance(last_error, ssl.SSLCertVerificationError):
        raise RuntimeError(
            "Certificate verification failed. The certificate may be expired, "
            "untrusted, or issued for a different hostname."
        )
    if isinstance(last_error, (socket.timeout, TimeoutError)):
        raise RuntimeError("The connection timed out.")
    if isinstance(last_error, ssl.SSLError):
        raise RuntimeError(f"TLS connection failed: {last_error}")
    raise RuntimeError(f"Could not connect to this website: {last_error or 'unknown error'}")


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/check")
def api_check():
    try:
        payload = request.get_json(force=False, silent=False)
        if not isinstance(payload, dict):
            raise ValueError("Send a JSON object containing a domain.")
        domain = normalize_domain(payload.get("domain", ""))
        result = inspect_certificate(domain)
        days = result["days_remaining"]
        if days < 0:
            result["warning"] = f"Certificate expired {-days} day(s) ago."
            result["severity"] = "danger"
        elif days <= 7:
            result["warning"] = f"Urgent: certificate expires in {days} day(s)."
            result["severity"] = "danger"
        elif days <= 30:
            result["warning"] = f"Certificate expires soon — {days} day(s) remaining."
            result["severity"] = "warning"
        else:
            result["warning"] = f"Certificate is valid — {days} day(s) remaining."
            result["severity"] = "success"
        return jsonify({"ok": True, "result": result})
    except (ValueError, BadRequest) as exc:
        return jsonify({"ok": False, "error": str(exc) or "Invalid request."}), 400
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 422


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
