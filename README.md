# CertScope — SSL/TLS Certificate Checker (Website)

A full-stack website version of the SSL/TLS Certificate Checker project. Visitors enter a public domain and the Python backend connects to its HTTPS endpoint (port 443), verifies the server certificate, and displays certificate details.

## Features

- Domain input and live certificate scan
- Certificate issuer and subject
- Valid-from and expiry timestamps
- Remaining days and expiry warnings
- Negotiated TLS version
- Cipher suite and key-exchange cipher strength (as reported by Python)
- Subject Alternative Names (SAN)
- Responsive dark cybersecurity dashboard

## Technology

- Frontend: HTML, CSS, JavaScript
- Backend: Python and Flask
- Certificate inspection: Python `ssl` and `socket`
- Deployment: Render with Gunicorn

## Run on Windows

1. Install Python 3.10 or newer.
2. Extract this project folder.
3. Open the folder in VS Code.
4. Open Terminal → New Terminal.
5. (Recommended) Create a virtual environment:

   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   ```

6. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

7. Start the website:

   ```powershell
   py app.py
   ```

8. Open `http://127.0.0.1:5000` in your browser.

## Deploy on Render

1. Create a **new GitHub repository** for this website version (keep your existing Tkinter desktop repository unchanged).
2. Upload all files and folders from this project, preserving the `templates` and `static` folders.
3. In Render, create a new **Web Service** and connect the new GitHub repository.
4. Render can detect `render.yaml`; otherwise use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
5. Deploy. Render will provide a public HTTPS URL.

## Security and limitations

- The checker accepts domain names only and uses HTTPS port 443.
- It rejects hostnames that resolve to non-public IP addresses to reduce server-side request forgery (SSRF) risk.
- The backend connects to the validated resolved IP address and uses the original hostname for TLS SNI and certificate hostname verification.
- Python's default trust store is used to verify the certificate.
- This is an educational certificate-inspection tool, not a full vulnerability scanner or penetration test.
- Do not expose this service as an unrestricted high-volume scanning service. Add rate limiting and monitoring before production use.

## Project author

Prince E S  
BCA — East Point College of Higher Education
