from __future__ import annotations

import asyncio
import os
import ssl

from hypercorn.asyncio import serve
from hypercorn.config import Config

from services.management.app import app
from services.management.commands import public_key_from_private


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
    asyncio.run(serve(app, configuration()))
