"""The missing-cluster.json send failure must name the searched paths.

mailbox.send_message used to raise ``cannot resolve sender fqid
(cluster.json missing?)`` with no hint about WHERE the resolver looked.
The upstream fix names the env override and every default search path so
the failure is self-diagnosing.
"""

from __future__ import annotations

import pytest

import skcomms.mailbox as mailbox
from skcomms.cluster import CLUSTER_ENV_VAR, CLUSTER_LOOKUP_PATHS


def test_fqid_error_names_every_searched_path(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        mailbox,
        "resolve_self_identity",
        lambda agent=None: {
            "agent": "lumina",
            "capauth_uri": "capauth:lumina@mesh",
            "fqid": None,
            "fingerprint": "",
        },
    )
    monkeypatch.setattr(mailbox, "skcomms_home", lambda: tmp_path)
    with pytest.raises(ValueError) as caught:
        mailbox.send_message("opus@chef.skworld.io", "hello")
    message = str(caught.value)
    assert "cannot resolve sender fqid" in message
    assert CLUSTER_ENV_VAR in message
    for path in CLUSTER_LOOKUP_PATHS:
        assert str(path) in message
