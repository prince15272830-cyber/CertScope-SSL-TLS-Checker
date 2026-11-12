import ssl
import socket
from datetime import datetime, timezone


def check_certificate(domain):
    print("\nChecking SSL/TLS certificate...")
    print("-" * 45)

    try:
        # Create a secure connection with certificate verification
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:

                # Get certificate information
                certificate = secure_sock.getpeercert()

                # Get the TLS version
                tls_version = secure_sock.version()

                # Get the certificate issuer
                issuer_parts = certificate.get("issuer", ())
                issuer = ", ".join(
                    f"{key}={value}"
                    for group in issuer_parts
                    for key, value in group
                )

                # Get the expiry date
                expiry_text = certificate.get("notAfter")

                if expiry_text:
                    expiry_date = datetime.strptime(
                        expiry_text, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    days_left = (expiry_date - datetime.now(timezone.utc)).days
                else:
                    expiry_date = None
                    days_left = None

                # Display results
                print(f"Website: {domain}")
                print(f"Certificate issuer: {issuer or 'Not available'}")
                print(f"TLS version: {tls_version or 'Not available'}")

                if expiry_date:
                    print(f"Expiry date (UTC): {expiry_date}")
                    print(f"Days until expiry: {days_left}")

                    if days_left < 0:
                        print("Status: EXPIRED")
                    elif days_left <= 30:
                        print("Status: WARNING - Certificate expires soon")
                    else:
                        print("Status: Certificate is not expired")
                else:
                    print("Status: Expiry date unavailable")

                print("-" * 45)

    except ssl.SSLCertVerificationError:
        print("ERROR: Certificate verification failed.")
        print("The certificate may be invalid, expired, or untrusted.")

    except socket.gaierror:
        print("ERROR: Domain not found. Check the website name.")

    except (socket.timeout, TimeoutError):
        print("ERROR: Connection timed out.")

    except ConnectionRefusedError:
        print("ERROR: Connection refused by the server.")

    except OSError as error:
        print(f"Connection error: {error}")

    except ssl.SSLError as error:
        print(f"SSL/TLS error: {error}")


def main():
    print("=" * 45)
    print("       SSL/TLS CERTIFICATE CHECKER")
    print("=" * 45)

    domain = input("Enter website domain (example: google.com): ").strip()

    # Remove an accidental HTTPS prefix or trailing slash
    domain = domain.removeprefix("https://")
    domain = domain.removeprefix("http://")
    domain = domain.split("/")[0].split(":")[0]

    if not domain or any(char.isspace() for char in domain):
        print("ERROR: Please enter a valid domain name.")
        return

    check_certificate(domain)


if __name__ == "__main__":
    main()