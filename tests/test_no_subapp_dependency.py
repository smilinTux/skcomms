"""Gate: skcomms CORE must import free of every higher-layer subapp.

skcomms is an L0 core package (capauth / skcomms / skmemory are the shared
core).  It may be composed WITH the higher-layer subapps (skcapstone, skchat,
skos, skharness), but importing the core transport / pairing / peers surface
must never PULL one of them into ``sys.modules``.  Each core -> subapp coupling
is either inverted, lazily guarded, or degrades gracefully; this test locks
that in.

The proof runs in a CLEAN interpreter subprocess (not the pytest process, which
has already imported plenty), imports the core surface, and asserts NONE of the
subapps entered ``sys.modules``.  The subapps ARE installed in this venv, so a
green result means the core genuinely does not touch them, not merely that they
are absent.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

# The higher-layer subapps that skcomms L0 must never import as a side effect of
# a core import.  (capauth and skmemory are L0 peers, not subapps, so they are
# intentionally out of scope here.)
SUBAPPS = ("skcapstone", "skchat", "skos", "skharness")

# The skcomms CORE surface (transport / pairing / peers kernel), each imported
# explicitly.  ``import skcomms`` (package __init__) loads .core -> .integration,
# so the bare import is the strictest single case, but we import the named core
# modules too so a future refactor cannot quietly reintroduce a leak off-__init__.
CORE_MODULES = (
    "skcomms",
    "skcomms.core",
    "skcomms.transport",
    "skcomms.pairing",
    "skcomms.peers",
    "skcomms.pairing_mirror",
    "skcomms.integration",
)


def _clean_import_leaks(modules: tuple[str, ...]) -> list[str]:
    """Import ``modules`` in a fresh interpreter; return any leaked subapps.

    Returns the sorted list of subapp names that entered ``sys.modules`` as a
    side effect of importing the given modules.  An empty list is the pass
    condition.
    """
    script = textwrap.dedent(f"""
        import sys
        for _m in {modules!r}:
            __import__(_m)
        _subapps = {SUBAPPS!r}
        _leaked = sorted(
            s for s in _subapps
            if any(k == s or k.startswith(s + ".") for k in sys.modules)
        )
        print(",".join(_leaked))
        """)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    out = proc.stdout.strip()
    return out.split(",") if out else []


def test_core_import_pulls_no_subapp():
    """Importing the whole skcomms core surface leaks zero subapps."""
    leaked = _clean_import_leaks(CORE_MODULES)
    assert leaked == [], (
        f"skcomms core import pulled in subapps: {leaked}. "
        "The L0 core must not depend on any higher-layer subapp."
    )


def test_bare_skcomms_import_pulls_no_subapp():
    """Even a bare ``import skcomms`` (package __init__ -> core) leaks zero subapps."""
    leaked = _clean_import_leaks(("skcomms",))
    assert leaked == [], f"`import skcomms` pulled in subapps: {leaked}"


def test_integration_module_import_is_lazy():
    """Importing the skcapstone bridge module must not eagerly load skcapstone.

    ``skcomms.integration`` legitimately bridges to skcapstone, but the import
    is resolved lazily on first use, so merely importing the module (which a
    bare ``import skcomms`` does, via ``skcomms.core``) never pulls skcapstone
    into ``sys.modules``.
    """
    leaked = _clean_import_leaks(("skcomms.integration",))
    assert leaked == [], (
        f"`import skcomms.integration` eagerly pulled in subapps: {leaked}. "
        "The skcapstone import must be lazy (deferred to first use)."
    )


def test_api_module_import_is_lazy():
    """Importing the HTTP API module must not eagerly load skcapstone.

    ``skcomms.api`` bridges to ``skcapstone.snapshots`` for the consciousness
    endpoints, but that import is deferred to first use (``_load_snapshots``),
    so importing the module never pulls skcapstone into ``sys.modules``.
    """
    leaked = _clean_import_leaks(("skcomms.api",))
    assert leaked == [], (
        f"`import skcomms.api` eagerly pulled in subapps: {leaked}. "
        "The skcapstone.snapshots import must be lazy (deferred to first use)."
    )
