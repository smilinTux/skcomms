"""P7 integration — register_builtin_tools wires A3 knowledge + A4 file tools into the A2 registry."""
from __future__ import annotations
import asyncio
from skcomms.access import register_builtin_tools, AccessRegistry


def test_registers_all_ten_tools():
    reg = AccessRegistry()
    names = register_builtin_tools(registry=reg)
    assert set(names) == {
        "pg_search", "pg_locate", "graph_query", "corpus_stats",
        "file_read", "file_write", "file_patch", "file_list", "file_stat", "list_roots",
    }
    assert len(reg.names()) == 10


def test_scopes_mapped():
    reg = AccessRegistry()
    register_builtin_tools(registry=reg)
    assert reg.get("file_write").scope.value == "write"
    assert reg.get("file_patch").scope.value == "write"
    assert reg.get("pg_search").scope.value == "read"
    assert reg.get("file_read").scope.value == "read"


def test_adapter_invokes_direct_arg_callable(tmp_path):
    # list_roots takes no args; the (arguments, ctx) adapter must call it cleanly
    reg = AccessRegistry()
    register_builtin_tools(registry=reg)
    tool = reg.get("list_roots")
    out = asyncio.get_event_loop().run_until_complete(tool.invoke({}, None))
    assert isinstance(out, list)


def test_idempotent_reregister():
    reg = AccessRegistry()
    register_builtin_tools(registry=reg)
    register_builtin_tools(registry=reg)  # replace=True -> no dup/raise
    assert len(reg.names()) == 10
