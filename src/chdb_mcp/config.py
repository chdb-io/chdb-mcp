"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_MAX_RESULT_BYTES = 1024 * 1024  # 1 MiB
DEFAULT_QUERY_TIMEOUT_SEC = 30


@dataclass(frozen=True)
class Config:
    readonly: bool
    max_result_bytes: int
    query_timeout_sec: int
    file_allowlist: tuple[str, ...]
    session_path: str | None

    @classmethod
    def from_env(cls) -> Config:
        write_enabled = os.getenv("CHDB_MCP_WRITE", "").lower() in {"1", "true", "yes", "on"}
        allowlist_raw = os.getenv("CHDB_MCP_FILE_ALLOWLIST", "")
        return cls(
            readonly=not write_enabled,
            max_result_bytes=int(
                os.getenv("CHDB_MCP_MAX_RESULT_BYTES", str(DEFAULT_MAX_RESULT_BYTES))
            ),
            query_timeout_sec=int(
                os.getenv("CHDB_MCP_QUERY_TIMEOUT_SEC", str(DEFAULT_QUERY_TIMEOUT_SEC))
            ),
            file_allowlist=tuple(p.strip() for p in allowlist_raw.split(":") if p.strip()),
            session_path=os.getenv("CHDB_MCP_SESSION_PATH") or None,
        )
