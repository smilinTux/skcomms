"""Syncthing rail provisioning + share-health (coord ``2c103c2d``).

The file/syncthing failover rail is a **sneakernet transport**: envelopes are
plain files dropped into the realm message tree (:mod:`skcomms.home`) and
Syncthing replicates them between machines. ``peers.json``
(:mod:`skcomms.peers`) records the FQID -> Syncthing-device-id -> PGP-key
binding; :doc:`docs/SYNCTHING_TOPOLOGY` describes the Send-Only-self /
Receive-Only-per-peer folder topology those device ids drive.

Two gaps this module closes (found by an adversarial pass):

1. **No provisioning.** A wiped machine gets a *new* Syncthing device id and an
   empty config. Until every folder is re-created and every peer device is
   re-shared, the rail writes files locally that never leave the box. Nothing
   in bootstrap stood the shares up from ``peers.json``. :func:`provision_rail`
   reads the existing Syncthing config (via the REST API) and *idempotently*
   creates/updates the self Send-Only folder + one Receive-Only folder per peer
   operator, adding each peer's device and sharing the right folders with it.

2. **No health signal.** After the honest-delivery fix a queued envelope with a
   *disconnected* transport underneath it just says "queued forever" — the
   "get two" redundancy silently collapses to one rail with no alarm.
   :func:`check_share_health` verifies the comms folder is present, shared with
   the expected peer devices, that those devices are connected, that sync is up
   to date, and that no ``*.sync-conflict-*`` files (which corrupt the tree)
   are present, plus a stale-outbox age alarm distinct from raw queue depth.

Design for testability: the decision logic is pure functions over plain dicts
(the Syncthing ``/rest/config`` and ``/rest/system/connections`` shapes) and the
local filesystem. The live REST client (:class:`SyncthingRest`) is injected, so
tests never touch a running daemon or mutate a real Syncthing config — a fake
client supplying config/connections/completion drives every state.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("skcomms.syncthing_rail")

# Folder types Syncthing understands (docs/SYNCTHING_TOPOLOGY.md §2).
FOLDER_SENDONLY = "sendonly"
FOLDER_RECEIVEONLY = "receiveonly"

# Default stale-outbox threshold: an outbox envelope still on disk past this age
# means the transport under the queue is very likely disconnected (AC3 —
# "unsynced past a threshold age, distinct from ordinary queue depth").
DEFAULT_STALE_OUTBOX_HOURS = 6.0

# Syncthing writes conflict copies as ``<name>.sync-conflict-<ts>-<dev>.<ext>``.
CONFLICT_GLOB = "*.sync-conflict-*"


# ---------------------------------------------------------------------------
# FQID + folder-id conventions (docs/SYNCTHING_TOPOLOGY.md §3)
# ---------------------------------------------------------------------------


def fqid_parts(fqid: str) -> tuple[str, str, str]:
    """Split an FQID into ``(agent, operator, realm)``.

    Args:
        fqid: ``<agent>@<operator>.<realm>`` handle.

    Returns:
        The ``(agent, operator, realm)`` triple.

    Raises:
        ValueError: If *fqid* is not a well-formed ``a@o.r`` handle.
    """
    if not isinstance(fqid, str) or "@" not in fqid:
        raise ValueError(f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)")
    agent, rest = fqid.split("@", 1)
    if not agent or "." not in rest:
        raise ValueError(f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)")
    operator, realm = rest.split(".", 1)
    if not operator or not realm:
        raise ValueError(f"invalid fqid: {fqid!r} (expected <agent>@<operator>.<realm>)")
    return agent, operator, realm


def folder_id(realm: str, operator: str) -> str:
    """Return the path-safe Syncthing Folder ID for an operator subtree.

    ``skcomms-<realm>-<operator>`` — identical on the publisher (Send-Only) and
    every subscriber (Receive-Only) of that operator's tree, as Syncthing
    requires the Folder ID to match across a share.
    """
    return f"skcomms-{realm}-{operator}"


def folder_label(operator: str, realm: str) -> str:
    """Return the human folder Label ``skcomms:<operator>.<realm>``."""
    return f"skcomms:{operator}.{realm}"


# ---------------------------------------------------------------------------
# Desired topology (pure)
# ---------------------------------------------------------------------------


@dataclass
class RailFolder:
    """One desired Syncthing folder in the comms rail."""

    id: str
    label: str
    path: str
    type: str  # FOLDER_SENDONLY | FOLDER_RECEIVEONLY
    device_ids: list[str] = field(default_factory=list)
    role: str = ""  # "self" | "peer" (bookkeeping/reporting only)


@dataclass
class RailTopology:
    """The desired Syncthing folder + device layout derived from peers.json."""

    self_folder: RailFolder
    peer_folders: list[RailFolder] = field(default_factory=list)
    devices: dict[str, str] = field(default_factory=dict)  # device_id -> friendly name

    @property
    def folders(self) -> list[RailFolder]:
        return [self_f for self_f in (self.self_folder,)] + list(self.peer_folders)


def build_topology(
    realm: str,
    operator: str,
    home: Path,
    peers: dict,
) -> RailTopology:
    """Compute the desired folder/device topology from local identity + peers.

    Mirrors docs/SYNCTHING_TOPOLOGY.md: one Send-Only folder publishing this
    operator's own subtree (shared with *every* peer device), and one
    Receive-Only folder per *distinct peer operator* subscribing to their
    subtree (shared with that operator's device(s)).

    Args:
        realm: This node's realm (e.g. ``skworld``).
        operator: This node's operator (e.g. ``chef``).
        home: The skcomms home root (``skcomms_home()``).
        peers: The ``peers.json`` ``fqid -> entry`` mapping
            (:func:`skcomms.peers.list_peers`).

    Returns:
        A :class:`RailTopology`. Peers without a ``syncthing_device_id`` are
        skipped for device-sharing (they cannot replicate) but still shape the
        Receive-Only folder for their operator.
    """
    home = Path(home)
    devices: dict[str, str] = {}
    all_peer_device_ids: list[str] = []
    # peer operator subtree -> (realm, operator, device_ids)
    peer_ops: dict[tuple[str, str], list[str]] = {}

    for fqid, entry in sorted(peers.items()):
        try:
            _agent, p_operator, p_realm = fqid_parts(fqid)
        except ValueError:
            logger.warning("skipping malformed peer fqid in peers.json: %r", fqid)
            continue
        dev = (entry or {}).get("syncthing_device_id") or ""
        dev = dev.strip()
        key = (p_realm, p_operator)
        peer_ops.setdefault(key, [])
        if dev:
            if dev not in devices:
                # Friendly name: the operator handle is stable + human-readable.
                devices[dev] = p_operator
            if dev not in all_peer_device_ids:
                all_peer_device_ids.append(dev)
            if dev not in peer_ops[key]:
                peer_ops[key].append(dev)

    self_folder = RailFolder(
        id=folder_id(realm, operator),
        label=folder_label(operator, realm),
        path=str(home / realm / operator),
        type=FOLDER_SENDONLY,
        device_ids=list(all_peer_device_ids),
        role="self",
    )

    peer_folders: list[RailFolder] = []
    for (p_realm, p_operator), dev_ids in sorted(peer_ops.items()):
        peer_folders.append(
            RailFolder(
                id=folder_id(p_realm, p_operator),
                label=folder_label(p_operator, p_realm),
                path=str(home / "peers" / p_realm / p_operator),
                type=FOLDER_RECEIVEONLY,
                device_ids=list(dev_ids),
                role="peer",
            )
        )

    return RailTopology(self_folder=self_folder, peer_folders=peer_folders, devices=devices)


# ---------------------------------------------------------------------------
# Live REST client (injected; never hit in tests)
# ---------------------------------------------------------------------------


class SyncthingRestError(RuntimeError):
    """A Syncthing REST call failed (network, auth, or bad status)."""


# Config.xml search path (per-node; does NOT sync — see topology doc §8).
_CONFIG_XML_CANDIDATES = (
    "~/.local/state/syncthing/config.xml",  # modern default
    "~/.config/syncthing/config.xml",  # legacy default
    "~/Library/Application Support/Syncthing/config.xml",  # macOS
)


def _discover_api_credentials() -> tuple[str, str]:
    """Resolve the Syncthing REST base URL + API key.

    Order (env overrides win so ops can pin a remote/tunnel'd daemon):

    1. ``SKCOMMS_SYNCTHING_URL`` / ``SKCOMMS_SYNCTHING_APIKEY`` env, else
    2. parse ``<gui>`` ``<address>`` + ``<apikey>`` out of the local
       ``config.xml`` (first path that exists).

    Returns:
        ``(base_url, api_key)``.

    Raises:
        SyncthingRestError: If no credentials can be resolved.
    """
    env_url = (os.environ.get("SKCOMMS_SYNCTHING_URL") or "").strip()
    env_key = (os.environ.get("SKCOMMS_SYNCTHING_APIKEY") or "").strip()
    if env_url and env_key:
        return env_url.rstrip("/"), env_key

    import xml.etree.ElementTree as ET

    override = (os.environ.get("SKCOMMS_SYNCTHING_CONFIG") or "").strip()
    candidates = [override] if override else list(_CONFIG_XML_CANDIDATES)
    for cand in candidates:
        if not cand:
            continue
        path = Path(cand).expanduser()
        if not path.exists():
            continue
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:
            logger.warning("cannot parse syncthing config.xml at %s: %s", path, exc)
            continue
        gui = root.find("gui")
        if gui is None:
            continue
        apikey = (gui.findtext("apikey") or "").strip()
        address = (gui.findtext("address") or "127.0.0.1:8384").strip()
        if not apikey:
            continue
        tls = (gui.get("tls") or "").lower() in ("true", "1", "yes")
        scheme = "https" if tls else "http"
        base = env_url or f"{scheme}://{address}"
        return base.rstrip("/"), env_key or apikey

    raise SyncthingRestError(
        "no Syncthing API credentials: set SKCOMMS_SYNCTHING_URL + "
        "SKCOMMS_SYNCTHING_APIKEY, or ensure a readable config.xml exists"
    )


class SyncthingRest:
    """Thin Syncthing REST API client (stdlib urllib, no extra deps).

    The HTTP call is funneled through a single injectable ``requester`` so tests
    can stub every response without a live daemon. ``from_local()`` builds a
    real client from env/config.xml credentials.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        requester: Optional[Callable[[str, str, Optional[bytes]], bytes]] = None,
        timeout: float = 5.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._requester = requester or self._urllib_request

    @classmethod
    def from_local(
        cls, requester: Optional[Callable[[str, str, Optional[bytes]], bytes]] = None
    ) -> "SyncthingRest":
        """Build a client from ``SKCOMMS_SYNCTHING_*`` env / local config.xml."""
        base, key = _discover_api_credentials()
        return cls(base, key, requester=requester)

    def _urllib_request(self, method: str, url: str, body: Optional[bytes]) -> bytes:
        req = Request(url, data=body, method=method)
        req.add_header("X-API-Key", self.api_key)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (trusted local URL)
                return resp.read()
        except HTTPError as exc:
            raise SyncthingRestError(f"{method} {url} -> HTTP {exc.code}: {exc.reason}") from exc
        except URLError as exc:
            raise SyncthingRestError(f"{method} {url} failed: {exc.reason}") from exc

    def _call(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        body: Optional[dict] = None,
    ) -> object:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        raw = self._requester(
            method, url, json.dumps(body).encode("utf-8") if body is not None else None
        )
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SyncthingRestError(f"{method} {path}: non-JSON response") from exc

    # -- reads ------------------------------------------------------------
    def get_config(self) -> dict:
        """Full config (``GET /rest/config``): ``{folders:[...], devices:[...]}``."""
        cfg = self._call("GET", "/rest/config")
        return cfg if isinstance(cfg, dict) else {}

    def connections(self) -> dict:
        """Device connection map (``GET /rest/system/connections``)."""
        conns = self._call("GET", "/rest/system/connections")
        return conns if isinstance(conns, dict) else {}

    def my_id(self) -> str:
        """This node's own device id (``GET /rest/system/status`` ``.myID``)."""
        status = self._call("GET", "/rest/system/status")
        return str(status.get("myID", "")) if isinstance(status, dict) else ""

    def completion(self, folder: str, device: str) -> dict:
        """Sync completion for a (folder, device) pair (``GET /rest/db/completion``)."""
        comp = self._call("GET", "/rest/db/completion", params={"folder": folder, "device": device})
        return comp if isinstance(comp, dict) else {}

    # -- writes (provisioning) -------------------------------------------
    def put_device(self, device: dict) -> None:
        """Create/replace a device (``PUT /rest/config/devices/<id>``)."""
        self._call("PUT", f"/rest/config/devices/{device['deviceID']}", body=device)

    def put_folder(self, folder: dict) -> None:
        """Create/replace a folder (``PUT /rest/config/folders/<id>``)."""
        self._call("PUT", f"/rest/config/folders/{folder['id']}", body=folder)


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------


@dataclass
class ProvisionResult:
    """Outcome of a :func:`provision_rail` call."""

    applied: bool
    added_devices: list[str] = field(default_factory=list)
    added_folders: list[str] = field(default_factory=list)
    shared: list[str] = field(default_factory=list)  # "<folder_id>+<device_id>"
    type_mismatches: list[str] = field(default_factory=list)  # existing folder wrong type
    unchanged: bool = True

    def as_dict(self) -> dict:
        return {
            "applied": self.applied,
            "added_devices": self.added_devices,
            "added_folders": self.added_folders,
            "shared": self.shared,
            "type_mismatches": self.type_mismatches,
            "unchanged": self.unchanged,
        }


def _index_config(config: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    """Return ``(devices_by_id, folders_by_id)`` from a ``/rest/config`` dict."""
    devices = {d.get("deviceID"): d for d in config.get("devices", []) if d.get("deviceID")}
    folders = {f.get("id"): f for f in config.get("folders", []) if f.get("id")}
    return devices, folders


def plan_provision(topology: RailTopology, config: dict) -> ProvisionResult:
    """Diff the desired *topology* against an existing Syncthing *config*.

    Pure: computes what would change without mutating anything. Idempotent — a
    config that already satisfies the topology yields ``unchanged=True`` and no
    actions.

    Args:
        topology: Desired layout from :func:`build_topology`.
        config: The current ``/rest/config`` dict.

    Returns:
        A :class:`ProvisionResult` describing the *needed* changes
        (``applied=False``).
    """
    existing_devices, existing_folders = _index_config(config)
    result = ProvisionResult(applied=False)

    # Devices to add.
    for dev_id in topology.devices:
        if dev_id not in existing_devices:
            result.added_devices.append(dev_id)

    # Folders to add + shares to extend + type mismatches to flag.
    for folder in topology.folders:
        existing = existing_folders.get(folder.id)
        if existing is None:
            result.added_folders.append(folder.id)
            for dev_id in folder.device_ids:
                result.shared.append(f"{folder.id}+{dev_id}")
            continue
        # Folder exists: never silently flip its type (a self Send-Only folder
        # accidentally created Receive-Only would revert this node's own
        # authored messages). Report the mismatch for an operator to resolve.
        if existing.get("type") and existing.get("type") != folder.type:
            result.type_mismatches.append(
                f"{folder.id}: config={existing.get('type')} expected={folder.type}"
            )
        shared_ids = {d.get("deviceID") for d in existing.get("devices", [])}
        for dev_id in folder.device_ids:
            if dev_id not in shared_ids:
                result.shared.append(f"{folder.id}+{dev_id}")

    result.unchanged = not (result.added_devices or result.added_folders or result.shared)
    return result


def _folder_payload(folder: RailFolder, my_id: str) -> dict:
    """Build the ``PUT /rest/config/folders/<id>`` body for *folder*.

    A Syncthing folder's device list must always include this node itself, then
    each peer device the folder is shared with.
    """
    device_entries = [{"deviceID": my_id}] if my_id else []
    for dev_id in folder.device_ids:
        device_entries.append({"deviceID": dev_id})
    return {
        "id": folder.id,
        "label": folder.label,
        "path": folder.path,
        "type": folder.type,
        "devices": device_entries,
    }


def provision_rail(
    rest: SyncthingRest,
    home: Optional[Path] = None,
    peers: Optional[dict] = None,
    realm: Optional[str] = None,
    operator: Optional[str] = None,
    apply: bool = True,
) -> ProvisionResult:
    """Provision (idempotently) the Syncthing comms rail from ``peers.json``.

    Reads the *existing* Syncthing config, computes the desired Send-Only-self /
    Receive-Only-per-peer topology (docs/SYNCTHING_TOPOLOGY.md), and — when
    *apply* — creates any missing peer devices and creates/extends the folders
    so each is shared with the right peer device(s). Re-running once the rail is
    in place is a no-op (``unchanged=True``).

    Args:
        rest: An injected :class:`SyncthingRest` (real or fake).
        home: skcomms home root; defaults to :func:`skcomms.home.skcomms_home`.
        peers: ``peers.json`` mapping; defaults to :func:`skcomms.peers.list_peers`.
        realm: This node's realm; defaults to :func:`skcomms.cluster.get_realm`.
        operator: This node's operator; defaults to
            :func:`skcomms.cluster.get_operator`.
        apply: When ``False``, only compute + return the plan (no writes).

    Returns:
        A :class:`ProvisionResult`. ``type_mismatches`` are always reported and
        never auto-corrected (a wrong-type existing folder needs an operator).
    """
    if home is None:
        from .home import skcomms_home

        home = skcomms_home()
    if realm is None:
        from .cluster import get_realm

        realm = get_realm()
    if operator is None:
        from .cluster import get_operator

        operator = get_operator()
    if peers is None:
        from .peers import list_peers

        peers = list_peers()

    topology = build_topology(realm, operator, home, peers)
    config = rest.get_config()
    plan = plan_provision(topology, config)

    if not apply or plan.unchanged:
        plan.applied = False
        return plan

    my_id = ""
    try:
        my_id = rest.my_id()
    except SyncthingRestError as exc:
        logger.warning("could not read local device id (%s); folders will omit self", exc)

    # 1) Add missing devices first (a folder can only be shared with a known device).
    for dev_id in plan.added_devices:
        name = topology.devices.get(dev_id, dev_id[:7])
        rest.put_device({"deviceID": dev_id, "name": name})
        logger.info("provisioned syncthing device %s (%s)", dev_id[:7], name)

    # 2) Create/replace each folder that is new or under-shared. We PUT the full
    #    desired folder (idempotent replace) whenever it is missing a share or is
    #    absent entirely; existing well-shared folders are left untouched.
    touched_folders = {s.split("+", 1)[0] for s in plan.shared} | set(plan.added_folders)
    for folder in topology.folders:
        if folder.id in touched_folders:
            rest.put_folder(_folder_payload(folder, my_id))
            logger.info("provisioned syncthing folder %s (%s)", folder.id, folder.type)

    plan.applied = True
    return plan


# ---------------------------------------------------------------------------
# Share-health
# ---------------------------------------------------------------------------


class RailStatus(str, Enum):
    """Tri-state health verdict, ordered OK < WARN < FAIL for aggregation."""

    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"

    @property
    def _rank(self) -> int:
        return {"OK": 0, "WARN": 1, "FAIL": 2}[self.value]

    @classmethod
    def worst(cls, statuses) -> "RailStatus":
        out = cls.OK
        for s in statuses:
            if s._rank > out._rank:
                out = s
        return out


@dataclass
class HealthCheck:
    """One named share-health check result."""

    name: str
    status: RailStatus
    detail: str
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "data": self.data,
        }


@dataclass
class ShareHealth:
    """Aggregate share-health report for the Syncthing rail."""

    status: RailStatus
    checks: list[HealthCheck] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"status": self.status.value, "checks": [c.as_dict() for c in self.checks]}

    def summary(self) -> str:
        counts = {RailStatus.OK: 0, RailStatus.WARN: 0, RailStatus.FAIL: 0}
        for c in self.checks:
            counts[c.status] += 1
        return (
            f"{self.status.value} "
            f"({counts[RailStatus.FAIL]} fail, {counts[RailStatus.WARN]} warn, "
            f"{counts[RailStatus.OK]} ok)"
        )


def find_conflict_files(home: Path) -> list[Path]:
    """Return all Syncthing ``*.sync-conflict-*`` files under *home*.

    Conflict copies mean two writers touched the same path — for the message
    tree that is data corruption of the rail (the Send-Only/Receive-Only split
    exists precisely to make them impossible), so any hit is a FAIL signal.
    """
    home = Path(home)
    if not home.exists():
        return []
    return sorted(home.rglob(CONFLICT_GLOB))


def find_stale_outbox(
    home: Path,
    realm: str,
    operator: str,
    max_age_hours: float = DEFAULT_STALE_OUTBOX_HOURS,
) -> list[Path]:
    """Return outbox envelope files older than *max_age_hours* (unsynced alarm).

    Scans this operator's own published subtree
    (``<home>/<realm>/<operator>/<agent>/outbox/*.json``). An envelope still
    sitting there past the threshold means Syncthing has not carried it off the
    box — the transport under the queue is disconnected. This is distinct from
    ordinary queue depth (AC3): a deep-but-fresh queue is fine; an *aged* queue
    is the silent-collapse signal.
    """
    home = Path(home)
    op_root = home / realm / operator
    if not op_root.exists():
        return []
    cutoff = time.time() - (max_age_hours * 3600.0)
    stale: list[Path] = []
    for outbox in op_root.glob("*/outbox"):
        if not outbox.is_dir():
            continue
        for env in outbox.glob("*.json"):
            if env.name.startswith("."):
                continue
            try:
                if env.stat().st_mtime < cutoff:
                    stale.append(env)
            except OSError:
                continue
    return sorted(stale)


def check_share_health(
    rest: Optional[SyncthingRest] = None,
    home: Optional[Path] = None,
    peers: Optional[dict] = None,
    realm: Optional[str] = None,
    operator: Optional[str] = None,
    stale_outbox_hours: float = DEFAULT_STALE_OUTBOX_HOURS,
) -> ShareHealth:
    """Verify the Syncthing comms rail is actually shared, connected, and syncing.

    Checks (overall status = worst of all):

    - ``rail_provisioned`` — the self Send-Only folder exists in the Syncthing
      config. Missing => **FAIL** (a wiped box that never re-provisioned).
    - ``peers_declared`` — ``peers.json`` has at least one peer with a device
      id. None => **FAIL** (the "get two" rail has collapsed to zero).
    - ``folder_shared`` — the self folder is shared with every expected peer
      device. A missing share => **FAIL** (that peer never receives).
    - ``peers_connected`` — expected peer devices are currently connected. Zero
      connected => **FAIL**; some-but-not-all => **WARN**.
    - ``sync_progress`` — per (self-folder, peer-device) completion is 100%.
      Anything in flight => **WARN** (informational, not a failure).
    - ``conflicts`` — any ``*.sync-conflict-*`` file under home => **FAIL**.
    - ``stale_outbox`` — outbox envelopes older than *stale_outbox_hours* =>
      **WARN** (unsynced-age alarm, distinct from queue depth).

    ``rest=None`` degrades gracefully: the network/config checks report **WARN**
    (unknown — daemon unreachable) rather than failing, and the filesystem
    checks (conflicts, stale outbox) still run.

    Returns:
        A :class:`ShareHealth` aggregate.
    """
    if home is None:
        from .home import skcomms_home

        home = skcomms_home()
    if realm is None:
        from .cluster import get_realm

        realm = get_realm()
    if operator is None:
        from .cluster import get_operator

        operator = get_operator()
    if peers is None:
        from .peers import list_peers

        peers = list_peers()

    home = Path(home)
    topology = build_topology(realm, operator, home, peers)
    self_id = topology.self_folder.id
    expected_devices = list(topology.self_folder.device_ids)
    checks: list[HealthCheck] = []

    # --- peers_declared -------------------------------------------------
    if not expected_devices:
        checks.append(
            HealthCheck(
                "peers_declared",
                RailStatus.FAIL,
                "no peers with a Syncthing device id in peers.json — the rail "
                "has no second machine to replicate to (get-two collapsed to one)",
                {"peer_count": len(peers)},
            )
        )
    else:
        checks.append(
            HealthCheck(
                "peers_declared",
                RailStatus.OK,
                f"{len(expected_devices)} peer device(s) declared",
                {"devices": expected_devices},
            )
        )

    # --- config-dependent checks ---------------------------------------
    config: Optional[dict] = None
    if rest is not None:
        try:
            config = rest.get_config()
        except SyncthingRestError as exc:
            checks.append(
                HealthCheck(
                    "rail_provisioned",
                    RailStatus.WARN,
                    f"Syncthing REST unreachable: {exc}",
                    {},
                )
            )

    if config is not None:
        _, folders_by_id = _index_config(config)
        self_cfg = folders_by_id.get(self_id)
        if self_cfg is None:
            checks.append(
                HealthCheck(
                    "rail_provisioned",
                    RailStatus.FAIL,
                    f"self folder {self_id!r} is not configured in Syncthing — "
                    "run `skcomms rail provision`; files are written locally but "
                    "never leave this box",
                    {"folder_id": self_id},
                )
            )
        else:
            checks.append(
                HealthCheck(
                    "rail_provisioned",
                    RailStatus.OK,
                    f"self folder {self_id!r} configured ({self_cfg.get('type')})",
                    {"folder_id": self_id, "type": self_cfg.get("type")},
                )
            )
            # folder_shared: is every expected peer device on the folder?
            shared_ids = {d.get("deviceID") for d in self_cfg.get("devices", [])}
            missing = [d for d in expected_devices if d not in shared_ids]
            if missing:
                checks.append(
                    HealthCheck(
                        "folder_shared",
                        RailStatus.FAIL,
                        f"self folder not shared with {len(missing)} expected peer "
                        f"device(s) — they will never receive",
                        {"missing_devices": missing},
                    )
                )
            elif expected_devices:
                checks.append(
                    HealthCheck(
                        "folder_shared",
                        RailStatus.OK,
                        f"self folder shared with all {len(expected_devices)} peer device(s)",
                        {},
                    )
                )

    elif rest is None:
        checks.append(
            HealthCheck(
                "rail_provisioned",
                RailStatus.WARN,
                "no Syncthing REST client supplied — folder/connection state "
                "not verified (filesystem checks only)",
                {},
            )
        )

    # --- peers_connected + sync_progress (need a live daemon) ----------
    if rest is not None and config is not None and expected_devices:
        try:
            conns = rest.connections().get("connections", {})
        except SyncthingRestError as exc:
            conns = {}
            logger.warning("connections() failed: %s", exc)
        connected = [d for d in expected_devices if conns.get(d, {}).get("connected")]
        if not connected:
            checks.append(
                HealthCheck(
                    "peers_connected",
                    RailStatus.FAIL,
                    "no expected peer device is connected — the rail is writing "
                    "locally with nothing on the other end",
                    {"connected": [], "expected": expected_devices},
                )
            )
        elif len(connected) < len(expected_devices):
            checks.append(
                HealthCheck(
                    "peers_connected",
                    RailStatus.WARN,
                    f"{len(connected)}/{len(expected_devices)} peer device(s) connected",
                    {"connected": connected, "expected": expected_devices},
                )
            )
        else:
            checks.append(
                HealthCheck(
                    "peers_connected",
                    RailStatus.OK,
                    f"all {len(expected_devices)} peer device(s) connected",
                    {"connected": connected},
                )
            )

        # sync_progress: completion of the self folder toward each peer.
        behind: list[str] = []
        for dev_id in connected:
            try:
                comp = rest.completion(self_id, dev_id)
            except SyncthingRestError:
                continue
            pct = comp.get("completion")
            need = comp.get("needItems", 0) or comp.get("needBytes", 0)
            if (pct is not None and pct < 100) or need:
                behind.append(f"{dev_id[:7]}={pct}%")
        if behind:
            checks.append(
                HealthCheck(
                    "sync_progress",
                    RailStatus.WARN,
                    f"sync in flight to {len(behind)} peer(s): {', '.join(behind)}",
                    {"behind": behind},
                )
            )
        else:
            checks.append(
                HealthCheck(
                    "sync_progress",
                    RailStatus.OK,
                    "self folder fully synced to all connected peers",
                    {},
                )
            )

    # --- conflicts (filesystem; always run) -----------------------------
    conflicts = find_conflict_files(home)
    if conflicts:
        checks.append(
            HealthCheck(
                "conflicts",
                RailStatus.FAIL,
                f"{len(conflicts)} Syncthing sync-conflict file(s) in the message "
                "tree — the rail is corrupted; resolve/delete them",
                {"files": [str(p) for p in conflicts[:20]], "count": len(conflicts)},
            )
        )
    else:
        checks.append(
            HealthCheck("conflicts", RailStatus.OK, "no sync-conflict files", {})
        )

    # --- stale_outbox (filesystem; always run) --------------------------
    stale = find_stale_outbox(home, realm, operator, stale_outbox_hours)
    if stale:
        checks.append(
            HealthCheck(
                "stale_outbox",
                RailStatus.WARN,
                f"{len(stale)} outbox envelope(s) unsynced > {stale_outbox_hours:g}h — "
                "the transport under the queue is likely disconnected",
                {"files": [str(p) for p in stale[:20]], "count": len(stale)},
            )
        )
    else:
        checks.append(
            HealthCheck(
                "stale_outbox",
                RailStatus.OK,
                f"no outbox envelope older than {stale_outbox_hours:g}h",
                {},
            )
        )

    overall = RailStatus.worst(c.status for c in checks)
    return ShareHealth(status=overall, checks=checks)
