"""cluster.json schema + reader helper.

Implementation lands in coord task T1 (``76d9b519``).

Expected schema::

    {
      "realm": "skworld",
      "operator": "chef",
      "operator_pubkey_fingerprint": "<40-hex>",
      "created_at": "<iso8601>"
    }

Lookup order:
1. ``/etc/skcapstone/cluster.json``
2. ``~/.skcapstone/cluster.json``
"""
