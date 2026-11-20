import asyncio
import datetime
import socket
import ssl
from typing import Any, Dict, List


def _sync_tls_handshake(host: str, port: int = 443) -> Dict[str, Any]:
    clean_host = host.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    cert_info: Dict[str, Any] = {
        "subject": f"CN={clean_host} (Self-Signed / Unverified or Plaintext)",
        "issuer": "Unknown / No TLS Listener Detected",
        "validDays": 0,
        "sans": [clean_host],
        "protocol": "None",
        "cipher": "None",
        "key_bits": 0,
        "tls_available": False,
    }

    try:
        with socket.create_connection((clean_host, port), timeout=5.0) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=clean_host) as tls_sock:
                cert_info["tls_available"] = True
                cert_info["protocol"] = tls_sock.version() or "TLSv1.2"
                cipher_tuple = tls_sock.cipher()
                if cipher_tuple:
                    cert_info["cipher"] = cipher_tuple[0]
                    cert_info["key_bits"] = cipher_tuple[2]

                # Retrieve decoded certificate via verified context if possible, fallback to binary DER
                der_cert = tls_sock.getpeercert(binary_form=True)
                if der_cert:
                    from cryptography import x509

                    parsed = x509.load_der_x509_certificate(der_cert)
                    cert_info["subject"] = parsed.subject.rfc4514_string()
                    cert_info["issuer"] = parsed.issuer.rfc4514_string()
                    now = datetime.datetime.now(datetime.timezone.utc)
                    delta = parsed.not_valid_after_utc - now
                    cert_info["validDays"] = max(0, delta.days)

                    try:
                        ext = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        sans: List[str] = ext.value.get_values_for_type(x509.DNSName)
                        if sans:
                            cert_info["sans"] = sans
                    except Exception:
                        pass
    except Exception as exc:
        cert_info["error"] = str(exc)

    return cert_info


async def run_ssl_audit(host: str, port: int = 443) -> Dict[str, Any]:
    return await asyncio.to_thread(_sync_tls_handshake, host, port)