"""Smoke tests — package imports and exposes a version."""

import skcomms


def test_import():
    assert skcomms is not None


def test_version():
    assert hasattr(skcomms, "__version__")
    # Robust: don't pin a literal (brittle across bumps) — require a non-empty
    # dotted version string.
    assert isinstance(skcomms.__version__, str) and skcomms.__version__.count(".") >= 1


def test_stub_modules_importable():
    """T1-T13 will fill these in; for the scaffold they just need to import."""
    from skcomms import cluster, envelope, identity, realm  # noqa: F401


def test_version_matches_installed_distribution():
    from importlib.metadata import version

    assert skcomms.__version__ == version("skcomms")


def test_cli_version_reports_the_distribution(tmp_path):
    from importlib.metadata import version

    from click.testing import CliRunner

    from skcomms.cli import main

    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert version("skcomms") in result.output
