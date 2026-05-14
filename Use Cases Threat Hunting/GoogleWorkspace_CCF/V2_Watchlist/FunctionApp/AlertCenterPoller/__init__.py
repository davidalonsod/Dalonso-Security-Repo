"""Timer-triggered poller: Google Alert Center -> Sentinel custom table.

Every 5 minutes:
1. Read cursor (highest ``createTime`` previously seen) from Table Storage.
2. Page through ``alerts.list`` filtered by ``createTime > cursor``.
3. Reshape each alert to the DCR stream columns and upload via Logs Ingestion.
4. Persist the new max ``createTime`` as the next cursor.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import azure.functions as func

from shared.google_alertcenter import iter_alerts
from shared.ingest import DcrIngestor
from shared.state_store import CursorStore

log = logging.getLogger(__name__)


def _required(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"missing required env var: {name}")
    return v


def _shape(alert: dict[str, Any]) -> dict[str, Any]:
    """Map Alert Center JSON to the DCR ``Custom-GWSAlerts_CL`` stream columns."""
    return {
        "customerId": alert.get("customerId", ""),
        "alertId": alert.get("alertId", ""),
        "createTime": alert.get("createTime", ""),
        "startTime": alert.get("startTime", ""),
        "endTime": alert.get("endTime", ""),
        "alertType": alert.get("type", ""),  # API field is `type`, column is `alertType`
        "source": alert.get("source", ""),
        "data": alert.get("data") or {},
        "securityInvestigationToolLink": alert.get("securityInvestigationToolLink", ""),
        "deleted": bool(alert.get("deleted", False)),
        "metadata": alert.get("metadata") or {},
        "updateTime": alert.get("updateTime", ""),
        "etag": alert.get("etag", ""),
    }


def main(timer: func.TimerRequest) -> None:
    sa_json = _required("GOOGLE_SA_JSON")
    subject = _required("GWS_IMPERSONATE_SUBJECT")
    storage_conn = _required("AzureWebJobsStorage")
    dce_endpoint = _required("DCE_LOGS_INGESTION_ENDPOINT")
    dcr_id = _required("DCR_IMMUTABLE_ID")
    stream = os.environ.get("DCR_STREAM_NAME", "Custom-GWSAlerts_CL")

    page_size = int(os.environ.get("GWS_PAGE_SIZE", "1000"))
    lookback = int(os.environ.get("GWS_ALERT_FILTER_LOOKBACK_MINUTES", "60"))

    table_name = os.environ.get("STATE_TABLE_NAME", "gwsalertstate")
    pk = os.environ.get("STATE_PARTITION_KEY", "alertcenter")
    rk = os.environ.get("STATE_ROW_KEY", "cursor")

    cursor_store = CursorStore(storage_conn, table_name, pk, rk)
    cursor = cursor_store.get(default_lookback_minutes=lookback)
    log.info("start cursor=%s", cursor)

    ingestor = DcrIngestor(dce_endpoint, dcr_id, stream)

    max_seen = cursor
    batch: list[dict[str, Any]] = []
    BATCH = 500
    total = 0

    for raw in iter_alerts(sa_json, subject, cursor, page_size=page_size):
        ct = raw.get("createTime") or ""
        if ct and ct > max_seen:
            max_seen = ct
        batch.append(_shape(raw))
        if len(batch) >= BATCH:
            total += ingestor.upload(batch)
            batch = []

    if batch:
        total += ingestor.upload(batch)

    if max_seen != cursor:
        cursor_store.set(max_seen)
        log.info("cursor advanced=%s ingested=%d", max_seen, total)
    else:
        log.info("no new alerts, cursor unchanged ingested=%d", total)
