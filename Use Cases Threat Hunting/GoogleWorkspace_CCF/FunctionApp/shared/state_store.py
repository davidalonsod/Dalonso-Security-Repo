"""Cursor persistence in Azure Table Storage.

Stores the highest ``createTime`` seen as a single row so the next run only
fetches newer alerts. Falls back to ``now - lookback`` if no row exists.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.data.tables import TableServiceClient

log = logging.getLogger(__name__)


class CursorStore:
    def __init__(
        self,
        connection_string: str,
        table_name: str,
        partition_key: str,
        row_key: str,
    ):
        self._svc = TableServiceClient.from_connection_string(connection_string)
        self._table_name = table_name
        self._pk = partition_key
        self._rk = row_key
        self._ensure_table()

    def _ensure_table(self) -> None:
        # Check existence first to avoid noisy 409 in logs every invocation.
        existing = self._svc.query_tables(
            f"TableName eq '{self._table_name}'"
        )
        if any(t.name == self._table_name for t in existing):
            return
        try:
            self._svc.create_table(self._table_name)
        except ResourceExistsError:
            pass

    def _client(self):
        return self._svc.get_table_client(self._table_name)

    def get(self, default_lookback_minutes: int) -> str:
        try:
            entity = self._client().get_entity(
                partition_key=self._pk, row_key=self._rk
            )
            return str(entity["cursor"])
        except ResourceNotFoundError:
            fallback = datetime.now(timezone.utc) - timedelta(
                minutes=default_lookback_minutes
            )
            iso = fallback.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            log.info("no cursor row, using fallback=%s", iso)
            return iso

    def set(self, cursor: str) -> None:
        self._client().upsert_entity(
            {
                "PartitionKey": self._pk,
                "RowKey": self._rk,
                "cursor": cursor,
            }
        )
