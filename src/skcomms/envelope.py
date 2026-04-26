"""Envelope v1 — PGP-signed message protocol.

Implementation lands in coord task T5 (``38b146c6``).

Pydantic model fields:
``envelope_version``, ``msg_id`` (ULID), ``from``, ``to``, ``in_reply_to``,
``sent_at``, ``body_format``, ``body``, ``attachments``,
``signature {alg, fingerprint, sig}``.

Signature covers ``from || to || sent_at || msg_id || body``.
"""
