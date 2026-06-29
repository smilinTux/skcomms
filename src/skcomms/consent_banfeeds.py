"""Subscribable signed ban/policy feeds — consent gate 3 (Matrix MSC2313 model).

The third gate in the SKFed delivery stack (``docs/skfed-consent-design.md``):
**reputation / ban feed**. Matrix's genuinely good idea is *subscribable shared
policy/ban lists* — community moderation that scales **without** central control.
Anyone publishes a feed; anyone subscribes to + blends any number of feeds; there
is **no central blocklist**.

This module is the sovereign, federated analogue:

* A :class:`BanFeed` is a list of :class:`BanEntry` recommendations
  (``entity`` glob, ``recommendation``, ``reason``) **CapAuth-signed by its
  publisher** over a stable canonical serialization
  (:meth:`BanFeed.signing_bytes`), reusing the proven
  :class:`skcomms.signing.EnvelopeSigner` / :class:`~skcomms.signing.EnvelopeVerifier`
  primitives (same crypto path as the SKFed directory — no parallel scheme).
* A :class:`FeedSubscription` holds multiple **verified** feeds and blends them:
  :meth:`~FeedSubscription.is_banned` glob-matches an FQID across every subscribed
  feed (banned if *any* feed recommends a ban).

**Fail-closed, per-publisher pinning.** A feed is only blended in if it verifies
against the verifier the subscriber pins for that feed (so a publisher can only
speak for feeds it actually signed). An unverified / unsigned / tampered feed is
**ignored entirely** — it never influences :meth:`is_banned`. This mirrors the
design's "subscribe + blend, no central control" while keeping authenticity
sovereign: I decide whose ban feeds I trust, and a forged feed is silently dropped.

The ``entity`` field is a shell-style glob (``*`` and ``?`` supported via
:mod:`fnmatch`), so a publisher can ban a single FQID (``evil@attacker.realm``)
or a whole realm (``*@attacker.realm``).

Pure-additive: this module imports the existing signing primitives and is wired
into the gate stack by the composition layer (it does NOT edit
:mod:`skcomms.consent`).
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Union

from pydantic import BaseModel, Field

from .signing import EnvelopeSigner, EnvelopeVerifier

logger = logging.getLogger("skcomms.consent_banfeeds")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BanEntry(BaseModel):
    """A single ban/policy recommendation within a feed.

    Attributes:
        entity: The target the recommendation applies to — an FQID or a
            shell-style glob (``*`` / ``?``). ``evil@attacker.realm`` bans one
            agent; ``*@attacker.realm`` bans a whole realm.
        recommendation: The policy verb. ``"ban"`` (the only one that affects
            :meth:`FeedSubscription.is_banned`); other verbs (e.g. ``"warn"``)
            are carried but not acted on by the ban blend.
        reason: Free-text human-readable justification (moderation transparency).
    """

    entity: str
    recommendation: str = "ban"
    reason: str = ""


class BanFeed(BaseModel):
    """A publisher's signed list of ban/policy recommendations.

    Attributes:
        publisher: The publishing identity (the verifier key label). A
            subscriber pins a verifier holding this publisher's public key.
        entries: The :class:`BanEntry` recommendations.
        signed_at: UTC ISO-8601 of when the feed was last (re-)signed.
        sig: ASCII-armored PGP detached signature over :meth:`signing_bytes`.
        signer_fingerprint: 40-char hex fingerprint of the signing key.
    """

    publisher: str
    entries: list[BanEntry] = Field(default_factory=list)
    signed_at: str = Field(default_factory=_utc_now_iso)
    sig: str = ""
    signer_fingerprint: str = ""

    # -- canonicalization ---------------------------------------------------

    def signing_bytes(self) -> bytes:
        """Stable bytes the signature covers: ``{publisher, signed_at, entries}``.

        Entries are sorted by ``entity`` and keys are sorted/compact so the bytes
        are deterministic regardless of insertion order. ``sig`` /
        ``signer_fingerprint`` are excluded (they are *about* the signature).
        Mirrors :meth:`skcomms.skfed_directory.SignedDirectory.signing_bytes`.
        """
        payload = {
            "publisher": self.publisher,
            "signed_at": self.signed_at,
            "entries": [
                e.model_dump(mode="json")
                for e in sorted(self.entries, key=lambda x: x.entity)
            ],
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    # -- build / sign / verify ---------------------------------------------

    @classmethod
    def build(
        cls,
        *,
        publisher: str,
        entries: list[Union[BanEntry, dict]],
        signer: EnvelopeSigner,
        signed_at: Optional[str] = None,
    ) -> "BanFeed":
        """Construct a feed and CapAuth-sign it with *signer*.

        Args:
            publisher: Publisher identity label (the verifier key label).
            entries: :class:`BanEntry` records (or plain dicts coerced to them).
            signer: The publisher's :class:`~skcomms.signing.EnvelopeSigner`.
            signed_at: Override the signing timestamp (defaults to now).

        Returns:
            BanFeed: with ``sig`` + ``signer_fingerprint`` populated.
        """
        coerced = [e if isinstance(e, BanEntry) else BanEntry(**e) for e in entries]
        feed = cls(
            publisher=publisher,
            entries=coerced,
            signed_at=signed_at or _utc_now_iso(),
        )
        feed.signer_fingerprint = signer.fingerprint
        feed.sig = signer.sign_bytes(feed.signing_bytes())
        return feed

    def verify(self, verifier: EnvelopeVerifier) -> bool:
        """Verify the publisher signature against a preloaded *verifier*.

        The verifier must hold the publisher's public key (registered under the
        ``publisher`` label and/or the ``signer_fingerprint``). Fails closed: an
        unsigned, wrong-key, or tampered feed returns ``False``.

        Returns:
            bool: ``True`` only if the publisher validly signed this feed.
        """
        if not self.sig:
            return False
        return verifier.verify_bytes(
            self.signing_bytes(),
            self.sig,
            identity=self.publisher,
            fingerprint=self.signer_fingerprint or None,
        )

    def matches(self, fqid: str) -> Optional[BanEntry]:
        """Return the first ``ban`` entry whose glob matches *fqid*, else ``None``.

        Uses case-sensitive shell-glob matching (:func:`fnmatch.fnmatchcase`), so
        ``*`` matches any run of chars and ``?`` matches exactly one. Only entries
        with ``recommendation == "ban"`` are considered.
        """
        for entry in self.entries:
            if entry.recommendation != "ban":
                continue
            if fnmatch.fnmatchcase(fqid, entry.entity):
                return entry
        return None

    # -- wire format --------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize the signed feed to pretty UTF-8 JSON bytes."""
        return self.model_dump_json(indent=2).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "BanFeed":
        """Deserialize a signed feed from UTF-8 JSON bytes."""
        return cls.model_validate_json(data)


class FeedSubscription:
    """Holds multiple **verified** ban feeds and blends them (no central control).

    A subscriber adds feeds with :meth:`subscribe`, **pinning the verifier** that
    must validate each feed's publisher signature. Only verified feeds are kept;
    an unverified / unsigned / tampered feed is rejected and ignored (fail-closed).

    :meth:`is_banned` returns ``True`` if *any* subscribed feed has a ``ban``
    entry whose glob matches the FQID — the Matrix MSC2313 "subscribe + blend"
    semantics, made sovereign by per-publisher verifier pinning.
    """

    def __init__(self) -> None:
        self._feeds: list[BanFeed] = []

    @property
    def feed_count(self) -> int:
        """Number of verified feeds currently blended."""
        return len(self._feeds)

    def subscribe(self, feed: BanFeed, verifier: EnvelopeVerifier) -> bool:
        """Subscribe to *feed*, pinning *verifier* for its publisher signature.

        The feed is blended **only if** it verifies against *verifier*
        (fail-closed). Returns whether it was accepted.

        Args:
            feed: The publisher's :class:`BanFeed`.
            verifier: A verifier holding the publisher's public key (pinned).

        Returns:
            bool: ``True`` if the feed verified and was added; ``False`` if it
            was rejected (unverified / unsigned / wrong-key / tampered) and thus
            ignored.
        """
        if not feed.verify(verifier):
            logger.info(
                "ban feed from %r rejected (failed verification) — ignored",
                feed.publisher,
            )
            return False
        self._feeds.append(feed)
        return True

    def is_banned(self, fqid: str) -> bool:
        """Whether *fqid* is banned by any subscribed (verified) feed.

        Glob-matches *fqid* against every ``ban`` entry across all blended feeds.
        """
        return any(feed.matches(fqid) is not None for feed in self._feeds)

    def reasons(self, fqid: str) -> list[tuple[str, str]]:
        """All ``(publisher, reason)`` pairs banning *fqid* across blended feeds.

        Moderation transparency: lets a node show *who* recommended the ban and
        *why*, instead of an opaque drop.
        """
        out: list[tuple[str, str]] = []
        for feed in self._feeds:
            entry = feed.matches(fqid)
            if entry is not None:
                out.append((feed.publisher, entry.reason))
        return out
