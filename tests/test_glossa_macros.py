from skcomms.glossa.macros import MacroLexicon, default_macro_lexicon


def test_expand_and_version():
    lex = MacroLexicon({"GTD-sweep": "review open tasks, reprioritize by the 4 C's, "
                                     "flag blockers, propose next actions"})
    assert lex.expand("GTD-sweep").startswith("review open tasks")
    assert lex.expand("nope") is None
    assert len(lex.version) == 12


def test_version_is_order_independent():
    a = MacroLexicon({"x": "ex", "y": "why"})
    b = MacroLexicon({"y": "why", "x": "ex"})
    assert a.version == b.version
    assert MacroLexicon({"x": "ex"}).version != a.version


def test_default_lexicon_has_validated_slot_typed_macros():
    lex = default_macro_lexicon()
    # the experiment's disambiguating macros (host vs version, next-action vs region)
    assert lex.expand("GTD-sweep") is not None
    assert lex.expand("ROLLBACK <host> prev") is not None
    assert lex.expand("NEXT-DO mine") is not None
    assert lex.expand("P0 <svc> down <host>") is not None
    # a definition that pins the slot type (the fidelity fix)
    assert "host" in lex.expand("ROLLBACK <host> prev").lower()
