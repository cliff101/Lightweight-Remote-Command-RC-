"""
SSL Certificate Generator
--------------------------
Generates a self-signed X.509 certificate (+ private key) for the server.
The same certificate acts as the CA certificate the client uses to verify
the server – copy server.crt to every client machine.

Usage:
    python gen_certs.py                           # uses 'localhost'
    python gen_certs.py --hostname 192.168.1.10
    python gen_certs.py --hostname myserver.local
"""

import argparse
import datetime
import ipaddress
import os
import sys


def generate(hostname: str, cert_out: str, key_out: str):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("[ERROR] 'cryptography' package not installed.")
        print("        Run: pip install cryptography")
        sys.exit(1)

    print(f"Generating 2048-bit RSA key pair for '{hostname}' ...")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,            "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,  "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "Remote Command Server"),
        x509.NameAttribute(NameOID.COMMON_NAME,             hostname),
    ])

    # Build Subject Alternative Names so TLS clients can verify by IP or hostname
    san: list = [x509.DNSName("localhost"),
                 x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
    try:
        san.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        if hostname != "localhost":
            san.append(x509.DNSName(hostname))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(san),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    with open(cert_out, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_out, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    print(f"  [OK] Certificate : {cert_out}")
    print(f"  [OK] Private key : {key_out}")
    print(f"  [OK] Valid for 10 years, SANs: {[str(s) for s in san]}")
    print()
    print("IMPORTANT: Copy  server.crt  to every client machine.")
    print("           Keep  server.key  private – never share it.")


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))

    ap = argparse.ArgumentParser(description="Generate self-signed SSL certificate")
    ap.add_argument("--hostname", default="localhost",
                    help="Server hostname or IP address (default: localhost)")
    ap.add_argument("--cert", default=os.path.join(base, "server.crt"),
                    help="Output path for certificate (default: server.crt)")
    ap.add_argument("--key",  default=os.path.join(base, "server.key"),
                    help="Output path for private key (default: server.key)")
    args = ap.parse_args()

    generate(args.hostname, args.cert, args.key)
