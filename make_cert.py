"""Create a self-signed HTTPS certificate for the lab (agents -> server traffic encryption).

    pip install cryptography
    python make_cert.py                       # localhost + 127.0.0.1
    python make_cert.py 192.168.56.1 mysiem   # extra IPs / hostnames the agents will use

Then add to .env:   SSL_CERTFILE=cert.pem   SSL_KEYFILE=key.pem   (and HOST=0.0.0.0), run  python run.py
Agent config (agent_config.yaml):  server_url: https://<ip>:8000   and   ca_cert: cert.pem"""
import datetime
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

out = os.path.dirname(os.path.abspath(__file__))      # key.pem + cert.pem are written next to this script
os.makedirs(out, exist_ok=True)
names, ips = {"localhost"}, {"127.0.0.1"}
for a in sys.argv[1:]:
    try:
        ips.add(str(ipaddress.ip_address(a)))
    except ValueError:
        names.add(a)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mini-siem")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sorted(names)] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]), critical=False)
        .sign(key, hashes.SHA256()))
with open(os.path.join(out, "key.pem"), "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
with open(os.path.join(out, "cert.pem"), "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("written to", os.path.abspath(out), "- valid for", sorted(names), sorted(ips))
