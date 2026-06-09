"""CapAuth token validator for WebRTC signaling authentication.

Validates CapAuth PGP-signed bearer tokens used to authenticate agents
on the WebSocket signaling endpoint. Returns the PGP fingerprint of the
authenticated agent, or None on failure.

**Production token format**::

    <FINGERPRINT>.<UNIX_TIMESTAMP>.<BASE64URL_DETACHED_PGP_SIG>

The detached PGP signature covers the UTF-8 string::

    capauth:<FINGERPRINT>:<UNIX_TIMESTAMP>

A ±300-second window is accepted to tolerate clock skew while preventing
replay attacks. The signer's public key is resolved from:

1. ``~/.skcomm/keys/<FINGERPRINT>.asc`` — SKComm per-agent keystore
2. ``gpg --export --armor <FINGERPRINT>`` — system GPG keyring

**Remote validation** is available by setting ``capauth_url`` to a
CapAuth API base URL. Remote is tried first; on unreachable server the
validator falls back to local PGP verification.

**Dev-mode** (``require_auth=False``): a plain 40-hex fingerprint with no
timestamp or signature is accepted. This bypasses ALL cryptographic
guarantees and should only be used in isolated development environments.
Set ``SKCOMM_DEV_AUTH=1`` as a reminder to yourself that auth is disabled.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

logger = logging.getLogger("skcomm.capauth_validator")

# PGP fingerprint: 40 hex characters
_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")

# Replay-prevention window: tokens older than this (or future-dated beyond
# this) are rejected.
_TOKEN_WINDOW_SECS = 300  # ±5 minutes


class CapAuthValidator:
    """Validates CapAuth bearer tokens for WebRTC signaling authentication.

    Supports three validation modes:

    - **Remote** (highest trust): calls the CapAuth API endpoint to verify
      the token signature. Set ``capauth_url`` to enable.
    - **Local PGP** (default): verifies the detached PGP signature embedded
      in the token against the signer's public key. Requires ``pgpy`` and
      either ``~/.skcomm/keys/<FINGERPRINT>.asc`` or GPG keyring.
    - **Dev mode** (no auth): ``require_auth=False`` accepts a plain
      40-hex fingerprint with no signature. **Never use in production.**

    Args:
        capauth_url: Optional CapAuth API base URL for remote validation
            (e.g. ``https://capauth.skworld.io``). If None, uses local mode.
        require_auth: If True (default), reject connections with no/invalid
            token. Set to False **only in development** to allow
            unauthenticated peers (they get an "anonymous" pseudo-fingerprint
            or a dev-mode plain-fingerprint bypass).
    """

    def __init__(
        self,
        capauth_url: Optional[str] = None,
        require_auth: bool = True,
    ):
        self._capauth_url = capauth_url
        self._require_auth = require_auth

    def validate(self, token: Optional[str]) -> Optional[str]:
        """Validate a CapAuth bearer token and return the PGP fingerprint.

        Args:
            token: Raw token string from ``Authorization: Bearer <token>``.
                May be None if no Authorization header was provided.

        Returns:
            PGP fingerprint (40 uppercase hex chars) if valid.
            ``"anonymous"`` if ``require_auth`` is False and token is missing.
            None if validation fails and ``require_auth`` is True.
        """
        if not token:
            if self._require_auth:
                logger.warning("WebRTC signaling: no auth token — rejecting connection")
                return None
            return "anonymous"

        if self._capauth_url:
            return self._validate_remote(token)

        return self._validate_local(token)

    def _validate_local(self, token: str) -> Optional[str]:
        """Local validation: verify PGP signature in the CapAuth token.

        **Token format (production)**::

            <FINGERPRINT>.<UNIX_TIMESTAMP>.<BASE64URL_DETACHED_PGP_SIG>

        The detached PGP signature covers the UTF-8 string::

            capauth:<FINGERPRINT>:<UNIX_TIMESTAMP>

        A ±300-second window is accepted to tolerate clock skew while
        preventing replay attacks. The signer's public key is loaded from
        ``~/.skcomm/keys/<FINGERPRINT>.asc`` or the system GPG keyring.

        **Dev-mode shortcut** — when ``require_auth=False`` a plain
        40-hex fingerprint (no dots) is accepted without any signature.
        This is useful during local development when agents haven't
        exchanged keys yet. Set ``SKCOMM_DEV_AUTH=1`` in the environment
        as a visible reminder that authentication is disabled.

        .. warning::
            ``require_auth=False`` disables all cryptographic guarantees.
            Any peer that knows a valid fingerprint string can connect as
            that agent. **Never use in production.**

        Args:
            token: Bearer token string.

        Returns:
            Uppercase PGP fingerprint, or None if validation fails and
            ``require_auth`` is True.
        """
        parts = token.split(".", 2)
        fingerprint_raw = parts[0].upper()

        # ------------------------------------------------------------------ #
        # Dev-mode shortcut: plain fingerprint only (no sig, no timestamp).  #
        # Accepted ONLY when require_auth is False.                           #
        # ------------------------------------------------------------------ #
        if len(parts) == 1:
            if not self._require_auth and _FINGERPRINT_RE.match(fingerprint_raw):
                logger.debug(
                    "CapAuth local: dev-mode plain fingerprint accepted for %s",
                    fingerprint_raw,
                )
                return fingerprint_raw
            logger.warning("CapAuth local: expected 3-part token (fingerprint.ts.sig), got 1 part")
            return None

        # ------------------------------------------------------------------ #
        # Validate the fingerprint portion.                                   #
        # ------------------------------------------------------------------ #
        if not _FINGERPRINT_RE.match(fingerprint_raw):
            logger.warning("CapAuth local: fingerprint part is not valid 40-hex: %.12s…", token)
            return None

        # ------------------------------------------------------------------ #
        # Require exactly 3 parts for signed tokens.                          #
        # ------------------------------------------------------------------ #
        if len(parts) != 3:
            logger.warning(
                "CapAuth local: expected fingerprint.timestamp.sig, got %d parts",
                len(parts),
            )
            return None if self._require_auth else fingerprint_raw

        fingerprint, timestamp_str, sig_b64url = fingerprint_raw, parts[1], parts[2]

        # ------------------------------------------------------------------ #
        # Timestamp / replay-prevention check.                                #
        # ------------------------------------------------------------------ #
        try:
            token_ts = int(timestamp_str)
        except ValueError:
            logger.warning("CapAuth local: timestamp part is not an integer")
            return None

        skew = abs(int(time.time()) - token_ts)
        if skew > _TOKEN_WINDOW_SECS:
            logger.warning(
                "CapAuth local: token expired or future-dated (skew=%ds, max=%ds) for %s",
                skew,
                _TOKEN_WINDOW_SECS,
                fingerprint,
            )
            return None

        # ------------------------------------------------------------------ #
        # PGP signature verification via pgpy.                                #
        # ------------------------------------------------------------------ #
        try:
            import base64

            import pgpy  # type: ignore[import]

            sig_bytes = base64.urlsafe_b64decode(sig_b64url + "==")
            sig = pgpy.PGPSignature.from_blob(sig_bytes)

            pub_key = self._load_public_key(fingerprint)
            if pub_key is None:
                logger.warning("CapAuth local: public key not found for %s", fingerprint)
                return None if self._require_auth else fingerprint

            # The message that was signed: "capauth:<FINGERPRINT>:<TIMESTAMP>"
            signed_text = f"capauth:{fingerprint}:{timestamp_str}"
            result = pub_key.verify(signed_text, sig)
            if bool(result):
                logger.debug("CapAuth local: PGP sig valid for %s", fingerprint)
                return fingerprint

            logger.warning("CapAuth local: PGP signature INVALID for %s", fingerprint)
            return None

        except ImportError:
            logger.warning(
                "pgpy not installed — skipping PGP signature check. "
                "Install skcomm[crypto] for full CapAuth PGP verification."
            )
            # Without pgpy we cannot verify; in strict mode this is a hard
            # failure. In permissive mode we pass the fingerprint through
            # (format already validated above).
            return None if self._require_auth else fingerprint

        except Exception as exc:
            logger.error("CapAuth local: PGP verification error for %s: %s", fingerprint, exc)
            return None if self._require_auth else fingerprint

    def _load_public_key(self, fingerprint: str) -> "Optional[pgpy.PGPKey]":
        """Load a PGP public key by fingerprint.

        Search order:

        1. ``~/.skcomm/keys/<FINGERPRINT>.asc`` — SKComm per-agent keystore
        2. ``gpg --export --armor <FINGERPRINT>`` — system GPG keyring

        Args:
            fingerprint: 40-char uppercase hex PGP fingerprint.

        Returns:
            A loaded :class:`pgpy.PGPKey`, or None if the key cannot be found.
        """
        from pathlib import Path

        import pgpy  # type: ignore[import]

        # 1. SKComm local key store
        key_path = Path.home() / ".skcomm" / "keys" / f"{fingerprint}.asc"
        if key_path.exists():
            try:
                key, _ = pgpy.PGPKey.from_file(str(key_path))
                logger.debug("CapAuth: loaded key for %s from %s", fingerprint, key_path)
                return key
            except Exception as exc:
                logger.debug("CapAuth: failed to parse key at %s: %s", key_path, exc)

        # 2. System GPG keyring
        try:
            import subprocess

            result = subprocess.run(
                ["gpg", "--export", "--armor", fingerprint],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                key, _ = pgpy.PGPKey.from_blob(result.stdout)
                logger.debug("CapAuth: loaded key for %s from system GPG keyring", fingerprint)
                return key
        except FileNotFoundError:
            logger.debug("CapAuth: gpg binary not found; skipping system keyring lookup")
        except Exception as exc:
            logger.debug("CapAuth: GPG keyring lookup failed for %s: %s", fingerprint, exc)

        return None

    def verify_detached(
        self,
        signed_payload: str,
        sig: str,
        claimed_fp: str,
    ) -> bool:
        """Verify a detached PGP signature over an arbitrary payload.

        Used by the WebRTC transport to authenticate SDP payloads inside the
        ``capauth`` wrapper. The signature may be ASCII-armored PGP or
        base64url-encoded raw DER bytes.

        Args:
            signed_payload: The UTF-8 text that was signed.
            sig: The detached PGP signature, either as ASCII armor
                (``-----BEGIN PGP SIGNATURE-----``) or as a base64url-encoded
                raw signature blob.
            claimed_fp: 40-hex fingerprint of the expected signer.

        Returns:
            True if the signature is valid and the signer matches
            ``claimed_fp``.  False on any failure (bad sig, unknown key,
            missing deps, etc.).
        """
        fingerprint = claimed_fp.upper().strip()
        if not _FINGERPRINT_RE.match(fingerprint):
            logger.warning(
                "verify_detached: claimed fingerprint is not valid 40-hex: %s",
                fingerprint,
            )
            return False

        try:
            import base64

            import pgpy  # type: ignore[import]

            # Accept either ASCII-armored PGP signature or base64url bytes.
            if sig.strip().startswith("-----BEGIN PGP SIGNATURE-----"):
                pgp_sig = pgpy.PGPSignature.from_blob(sig)
            else:
                # Pad to a multiple of 4 before decoding
                sig_bytes = base64.urlsafe_b64decode(sig + "==")
                pgp_sig = pgpy.PGPSignature.from_blob(sig_bytes)

            pub_key = self._load_public_key(fingerprint)
            if pub_key is None:
                logger.warning("verify_detached: public key not found for %s", fingerprint)
                return False

            result = pub_key.verify(signed_payload, pgp_sig)
            if not bool(result):
                logger.warning("verify_detached: PGP signature INVALID for %s", fingerprint)
                return False

            logger.debug("verify_detached: PGP sig valid for %s", fingerprint)
            return True

        except ImportError:
            logger.warning(
                "pgpy not installed — cannot verify SDP signature. "
                "Install skcomm[crypto] for full CapAuth PGP verification."
            )
            return False
        except Exception as exc:
            logger.warning(
                "verify_detached: signature verification error for %s: %s",
                fingerprint,
                exc,
            )
            return False

    def _validate_remote(self, token: str) -> Optional[str]:
        """Remote validation via CapAuth API.

        Calls ``POST {capauth_url}/api/v1/verify`` with the bearer token.
        The API should return ``{"fingerprint": "<40-hex>", "valid": true}``.
        Falls back to local PGP validation if the remote is unreachable.

        Args:
            token: Bearer token string.

        Returns:
            Fingerprint from CapAuth response, or None on failure.
        """
        import json as _json
        import urllib.request

        try:
            req = urllib.request.Request(
                f"{self._capauth_url}/api/v1/verify",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read())
                fp = data.get("fingerprint")
                if fp and _FINGERPRINT_RE.match(str(fp).upper()):
                    return str(fp).upper()
                logger.warning("CapAuth response missing fingerprint: %s", data)
                return None
        except Exception as exc:
            logger.error("CapAuth remote validation failed: %s", exc)
            if self._require_auth:
                return None
            # Fallback to local validation if remote is unreachable
            return self._validate_local(token)
