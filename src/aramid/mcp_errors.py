"""Shared MCP exception type -- kept out of aramid.mcp itself.

`python -m aramid.mcp` (the product's real launch command, `agent_mcp.py`'s
MCP_COMMAND) executes mcp.py as `__main__`. `aramid.mcp_tools` then does
`from aramid.mcp import ...`, which imports mcp.py a SECOND time under its
proper dotted name -- Python has no way to know the `__main__` module
already running IS aramid.mcp. That gives two independent module objects,
each with its own class statements: a class defined in mcp.py is not the
same object as the one `mcp_tools.py` sees, so
`except InvalidParams` in mcp.py's handle_message no longer matches an
instance raised via the copy mcp_tools.py imported -- every invalid-params
tool call silently degraded to a generic -32603 instead of -32602.
Reproduced by executing mcp.py under `runpy`-style `__main__` aliasing and
comparing `id()` of the class seen from each side: they differed.

A module that is only ever reached by its own dotted name -- never
executed as `__main__` -- is imported exactly once, so both `aramid.mcp`
and `aramid.mcp_tools` end up holding the same class object regardless of
which of them Python loads first. That is the only property this module
exists for: keep it free of anything that would make it, or anything it
imports, get run as a script.
"""


class InvalidParams(Exception):
    """Raised by tool handlers for missing/invalid arguments -> -32602."""
