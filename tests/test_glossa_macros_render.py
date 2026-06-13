from skcomms.glossa.macros import (
    MacroLexicon,
    default_macro_lexicon,
    expand_macros,
)


def test_prompt_block_lists_macros_with_definitions():
    block = default_macro_lexicon().render_prompt_block()
    assert "GTD-sweep" in block
    assert "review all open coord tasks" in block
    # an instruction so the model expands rather than guesses on UNKNOWN shorthand
    assert "ask" in block.lower() or "do not guess" in block.lower()


def test_expand_macros_does_literal_audit_substitution():
    lex = default_macro_lexicon()
    text = "GTD-sweep then ROLLBACK <host> prev"
    out = expand_macros(text, lex)
    assert "review all open coord tasks" in out      # GTD-sweep expanded
    assert "roll back the deployment ON HOST" in out  # the host-pinning expansion


def test_expand_macros_leaves_unknown_text_untouched():
    lex = default_macro_lexicon()
    assert expand_macros("just plain words", lex) == "just plain words"


def test_expand_macros_is_single_pass_no_reexpansion():
    # "main" occurs INSIDE ship's definition; single-pass substitution must NOT
    # rewrite that inserted definition text on a later phrase.
    lex = MacroLexicon({"ship": "rebase onto main then push",
                        "main": "MAIN-BRANCH-REF"})
    out = expand_macros("ship", lex)
    assert out == "(rebase onto main then push)"
    # the outer macro still expands, and the definition's "main" is preserved
    assert "MAIN-BRANCH-REF" not in out
    # a standalone "main" elsewhere DOES still expand
    assert expand_macros("ship and main", lex) == \
        "(rebase onto main then push) and (MAIN-BRANCH-REF)"
