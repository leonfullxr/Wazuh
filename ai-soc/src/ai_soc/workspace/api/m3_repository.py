"""M3 transaction modes for candidate and incident reads."""

from __future__ import annotations

import sys
from typing import Any, cast

import psycopg

from ai_soc.workspace.api.repository import WorkspaceRepository
from ai_soc.workspace.db import site_transaction


class _M3Repository(WorkspaceRepository):
    @classmethod
    def open(cls, dsn: str, site_id: str, *, readonly: bool) -> WorkspaceRepository:
        """Open one site-scoped transaction for an M3 request."""
        conn = cast(psycopg.Connection[Any], psycopg.connect(dsn))
        repository = cls(conn, site_id)
        repository._site_context = site_transaction(
            conn,
            site_id,
            frozenset({site_id}),
            readonly=readonly,
            repeatable_read=readonly,
        )
        try:
            repository._site_context.__enter__()
        except Exception:
            conn.close()
            raise
        return repository

    def close(self) -> None:
        error_info = sys.exc_info()
        context, self._site_context = self._site_context, None
        try:
            if context is not None:
                context.__exit__(*error_info)
        except Exception:
            if error_info[1] is None:
                raise
        finally:
            self.conn.close()


def connect_read_repository(dsn: str, site_id: str) -> WorkspaceRepository:
    return _M3Repository.open(dsn, site_id, readonly=True)


def connect_write_repository(dsn: str, site_id: str) -> WorkspaceRepository:
    return _M3Repository.open(dsn, site_id, readonly=False)
