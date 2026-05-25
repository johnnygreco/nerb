from __future__ import annotations

import sys

import pytest

from nerb import mcp_server


def test_mcp_server_module_imports_on_all_supported_core_python_versions():
    assert callable(mcp_server.main)


def test_unavailable_mcp_stub_has_clear_error():
    unavailable_mcp = mcp_server._UnavailableMcp()

    with pytest.raises(mcp_server.NerbMcpUnavailableError, match="requires Python 3.10 or newer"):
        unavailable_mcp.run()


@pytest.mark.skipif(sys.version_info >= mcp_server.MCP_PYTHON_REQUIRES, reason="Only unsupported Python exits early.")
def test_nerb_mcp_main_reports_clear_error_on_unsupported_python(capsys):
    with pytest.raises(SystemExit) as exc_info:
        mcp_server.main([])

    assert exc_info.value.code == 1
    assert "Error: NERB MCP support requires Python 3.10 or newer" in capsys.readouterr().err
