from __future__ import annotations

import asyncio
import importlib
import os
import ssl

from cryptography import x509
from hypercorn.asyncio import serve
from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.config import Config
from cryptography.x509.oid import ExtensionOID

from services.management.app import app
from services.management.commands import public_key_from_private


class VerifiedClientTCPServer(TCPServer):
    """Copy the TLS-authenticated SPIFFE identity into per-connection ASGI state.

    Hypercorn 0.17 verifies client certificates but does not expose its SSLObject in
    the ASGI scope. This adapter reads the already-verified peer certificate after the
    handshake and passes only a single SPIFFE URI to the application.
    """

    def __init__(self, app, loop, config, context, state, reader, writer):
        connection_state = dict(state)
        ssl_object = writer.get_extra_info("ssl_object")
        certificate_der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if certificate_der:
            certificate = x509.load_der_x509_certificate(certificate_der)
            try:
                sans = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                identities = [
                    str(uri)
                    for uri in sans.get_values_for_type(x509.UniformResourceIdentifier)
                    if str(uri).startswith("spiffe://")
                ]
            except x509.ExtensionNotFound:
                identities = []
            if len(identities) == 1:
                connection_state["vigil.verified_spiffe_id"] = identities[0]
        super().__init__(app, loop, config, context, connection_state, reader, writer)


def required(name: str) -> str:
    value = os.getenv(name, "")
    if not value:
        raise RuntimeError(f"{name} is required for the management service")
    return value


def configuration() -> Config:
    required("MANAGEMENT_DATABASE_URL")
    required("VIGIL_MANAGEMENT_AUTH_ISSUER")
    required("VIGIL_MANAGEMENT_AUTH_AUDIENCE")
    required("VIGIL_MANAGEMENT_AUTH_PUBLIC_KEY")
    if required("VIGIL_MANAGEMENT_AUTH_ALGORITHM") not in {"EdDSA", "RS256"}:
        raise RuntimeError("VIGIL_MANAGEMENT_AUTH_ALGORITHM must be EdDSA or RS256")
    public_key_from_private(required("VIGIL_MANAGEMENT_COMMAND_PRIVATE_KEY"))

    config = Config()
    config.bind = [os.getenv("VIGIL_MANAGEMENT_BIND", "0.0.0.0:8443")]
    config.certfile = required("VIGIL_MANAGEMENT_TLS_CERT")
    config.keyfile = required("VIGIL_MANAGEMENT_TLS_KEY")
    config.ca_certs = required("VIGIL_MANAGEMENT_CLIENT_CA")
    config.verify_mode = ssl.CERT_REQUIRED
    config.alpn_protocols = ["h2", "http/1.1"]
    config.accesslog = "-"
    config.errorlog = "-"
    config.graceful_timeout = 30
    config.keep_alive_timeout = 5
    return config


if __name__ == "__main__":
    # worker_serve resolves TCPServer from this module global at connection time.
    importlib.import_module("hypercorn.asyncio.run").TCPServer = VerifiedClientTCPServer
    asyncio.run(serve(app, configuration()))
