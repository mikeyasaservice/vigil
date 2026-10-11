"""Shared tenant-local authority for managed admission and gateway calls.

The API and gateway import the same authority adapter in the local process. A
deployed topology runs this module in the dedicated security service instead;
the wire contract and fail-closed checks are unchanged.
"""

from __future__ import annotations

import base64
import os

from core.agents.managed_execution import Ed25519Signer, Ed25519Verifier, ManagedAuthority


def _build() -> ManagedAuthority:
    raw = os.getenv("VIGIL_MANAGED_AUTHORITY_PRIVATE_KEY", "")
    public_raw = os.getenv("VIGIL_MANAGED_AUTHORITY_PUBLIC_KEY", "")
    if os.getenv("VIGIL_EXECUTION_PROFILE", "standalone").lower() == "managed" and not (raw or public_raw):
        raise RuntimeError("managed authority trust material is unavailable")
    if not raw and public_raw:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        padded = public_raw + "=" * (-len(public_raw) % 4)
        public = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(padded))
        return ManagedAuthority(verifier=Ed25519Verifier(public, "managed-authority"))
    if not raw:
        return ManagedAuthority()
    padded = raw + "=" * (-len(raw) % 4)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(padded))
    return ManagedAuthority(signer=Ed25519Signer(private))


authority = _build()
