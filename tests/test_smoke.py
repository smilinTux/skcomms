"""Smoke tests — package imports and exposes a version."""

import skcomms


def test_import():
    assert skcomms is not None


def test_version():
    assert hasattr(skcomms, "__version__")
    assert skcomms.__version__ == "0.0.1"


def test_stub_modules_importable():
    """T1-T13 will fill these in; for the scaffold they just need to import."""
    from skcomms import cluster, envelope, identity, realm  # noqa: F401
