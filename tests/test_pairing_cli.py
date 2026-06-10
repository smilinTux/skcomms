from click.testing import CliRunner
from skcomms import cli


def test_pair_show_prints_uri(monkeypatch):
    import skcomms.pairing as P
    monkeypatch.setattr(P, "bundle_from_self",
        lambda agent=None, embed_key=False: P.PairingBundle(fqid="a@b.c", fingerprint="AB"*20))
    r = CliRunner().invoke(cli.main, ["pair", "show"])
    assert r.exit_code == 0, r.output
    assert "skp://pair?" in r.output


def test_pair_accept_invokes_accept(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import skcomms.pairing as P
    seen = {}

    def _fake_accept(src, **kw):
        seen["src"] = src
        return {"fqid": "x@y.z", "fingerprint": "F"}

    monkeypatch.setattr(P, "accept_pairing", _fake_accept)
    r = CliRunner().invoke(cli.main, ["pair", "accept", "skp://pair?v=1&fqid=x@y.z&fp=F"])
    assert r.exit_code == 0, r.output
    assert seen["src"].startswith("skp://pair?")
    assert "x@y.z" in r.output
