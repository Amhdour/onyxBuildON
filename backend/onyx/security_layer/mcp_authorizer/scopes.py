from __future__ import annotations

from enum import Enum


class MCPScope(str, Enum):
    USE = "mcp:use"
    SEARCH = "mcp:search"
    READ_DOCUMENT = "mcp:read_document"
    WEB_SEARCH = "mcp:web_search"
    OPEN_URL = "mcp:open_url"
    FILE_READ = "mcp:file_read"
    FILE_WRITE = "mcp:file_write"
    CODE_EXECUTE = "mcp:code_execute"
    ADMIN = "mcp:admin"


ACTION_SCOPE_MAP: dict[str, MCPScope] = {
    "search_indexed_documents": MCPScope.SEARCH,
    "search_web": MCPScope.WEB_SEARCH,
    "open_urls": MCPScope.OPEN_URL,
    "read_document": MCPScope.READ_DOCUMENT,
    "file_read": MCPScope.FILE_READ,
    "file_write": MCPScope.FILE_WRITE,
    "code_execute": MCPScope.CODE_EXECUTE,
    "admin": MCPScope.ADMIN,
}


def required_scope_for_action(action: str) -> MCPScope:
    return ACTION_SCOPE_MAP.get(action, MCPScope.USE)
