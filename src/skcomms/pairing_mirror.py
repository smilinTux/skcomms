"""Mirror skcomms' accepted pairings into capauth.pairing (M2 pairing fold).

When the pairing kernel is enabled (``SKCOMMS_PAIRING_KERNEL``, default ON), every
peer accepted via :func:`skcomms.pairing.accept_pairing` is ALSO recorded in
``capauth.pairing`` as a TOFU enrollment, so the kernel becomes the durable,
cross-front-door record of who is paired (the source the authz PDP reads), while
skcomms' own peer store keeps serving its reads byte-identically as the local cache.

This is the third front door folded into the one pairing kernel (after skchat's
guest store and window semantics). skcomms is the cleanest of the three: it holds
BOTH the peer's ``fqid`` and its real armored public key at accept time, so the
mirrored enrollment carries the actual key (subject = the peer's fqid).

Every mirror call is BEST-EFFORT: any capauth error is logged at debug and
swallowed, so a mirror failure can NEVER break a live pairing. This is the safe
first stage of the fold (dual-write, the skcomms peer store still authoritative
for reads); retiring it as the source of truth is a later stage once
capauth-vs-peer-store parity is proven.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("skcomms.pairing_mirror")

#: Default scopes a paired peer is granted (chat read/send). The authz PDP can
#: later require a minimum enrollment mode per scope; the mode carries the trust.
_DEFAULT_SCOPES = ["chat.read", "chat.send"]


def kernel_enabled() -> bool:
    """Whether accepted pairings are mirrored into the capauth.pairing kernel.

    Defaults ON (the M2 flip). An explicit ``SKCOMMS_PAIRING_KERNEL`` of
    ``0``/``false``/``off``/``no`` disables the mirror (legacy peer-store-only).
    """
    val = os.getenv("SKCOMMS_PAIRING_KERNEL")
    if val is None:
        return True
    return val.strip().lower() not in ("0", "false", "off", "no")


def _base() -> Optional[str]:
    """Capauth storage root for the mirror, or None for the capauth default.

    ``SKCOMMS_PAIRING_KERNEL_BASE`` lets tests point the mirror at a tmp home so
    they never touch the real ``~/.skcapstone`` pairing store.
    """
    return os.getenv("SKCOMMS_PAIRING_KERNEL_BASE") or None


def mirror_pairing(fqid: str, pubkey: str) -> None:
    """Record an accepted peer as a TOFU enrollment in capauth.pairing.

    Idempotent per (subject, key): re-mirroring an already-enrolled key is a
    no-op. Without that guard every accept minted ANOTHER approved DeviceRecord,
    and because each accept presents a freshly generated key, TOFU pinned
    nothing: the subject simply accumulated approved devices. Observed on
    ``opus@chef.skworld``, 22 records in one afternoon, every one a distinct
    fingerprint, in pairs because both :func:`skcomms.pairing.accept_pairing`
    and the public-pairing path mirror the same accept.

    Enrollments are NOT deduped by content upstream (``enroll_device`` +
    ``approve`` always create), so the check belongs here at the call site.

    Best-effort: gated on the kernel flag, and any capauth error is logged at
    debug and swallowed so it can never break :func:`accept_pairing`.
    """
    if not kernel_enabled() or not fqid or not pubkey:
        return
    try:
        from capauth.pairing import approve, enroll_device, list_devices

        base = _base()

        # Trust on FIRST use: if this subject already has a live device for this
        # key, keep the existing record rather than minting a second one. A
        # revoked record is deliberately not resurrected here; re-enrolling a
        # revoked key must be an explicit operator action, not a side effect of
        # a peer re-accept.
        if _already_enrolled(fqid, pubkey, base):
            logger.debug("pairing mirror: %s already enrolled for this key, skipping", fqid)
            return

        enr = enroll_device(
            pubkey,
            list(_DEFAULT_SCOPES),
            mode="tofu",
            subject=fqid,
            base_dir=base,
        )
        approve(enr.enrollment_id, "skcomms", base_dir=base)
    except Exception:
        logger.debug("capauth pairing mirror failed", exc_info=True)


def _already_enrolled(fqid: str, pubkey: str, base) -> bool:
    """Whether *fqid* already has a live capauth device carrying *pubkey*.

    Compares the armored public key stored on the DeviceRecord. A record with
    no stored key never matches, so it enrolls rather than silently treating an
    unknown key as already trusted. Any lookup failure also returns False: a
    duplicate record is far better than dropping a real pairing.
    """
    from capauth.pairing import list_devices

    try:
        existing = list_devices(fqid, base_dir=base, include_revoked=False)
    except Exception:
        logger.debug("pairing mirror: device lookup failed, enrolling anyway", exc_info=True)
        return False

    presented = (pubkey or "").strip()
    for dev in existing:
        stored = (getattr(dev, "pubkey", None) or "").strip()
        if stored and stored == presented:
            return True
    return False


def mirror_revocation(fqid: str) -> None:
    """Revoke every non-revoked capauth device whose subject is this peer's fqid.

    The symmetric counterpart to :func:`mirror_pairing`: when a peer is removed
    (untrusted) in skcomms, the durable capauth.pairing record for that fqid must
    stop being live, otherwise a peer removed here would stay authoritative in the
    kernel the authz PDP reads.

    Best-effort: gated on the kernel flag, and any capauth error is logged at
    debug and swallowed so it can never break the peer removal that triggered it.
    """
    if not kernel_enabled() or not fqid:
        return
    try:
        from capauth.pairing import list_devices, revoke

        base = _base()
        for dev in list_devices(subject=fqid, base_dir=base):
            if not dev.revoked:
                revoke(dev.device_id, "skcomms peer removed", base_dir=base)
    except Exception:
        logger.debug("capauth pairing mirror (revocation) failed", exc_info=True)


__all__ = ["kernel_enabled", "mirror_pairing", "mirror_revocation"]
