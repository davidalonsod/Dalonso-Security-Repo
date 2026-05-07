"""Push alerts to a Log Analytics custom table via DCE/DCR (Logs Ingestion API).

The Function's managed identity needs ``Monitoring Metrics Publisher`` on the
Data Collection Rule. Stream name and DCR immutable id come from env vars.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

log = logging.getLogger(__name__)

# Logs Ingestion API documents a 1 MB limit per upload call. Chunk well below
# that to be safe and to keep retries cheap.
DEFAULT_BATCH_SIZE = 500


class DcrIngestor:
    def __init__(self, endpoint: str, dcr_immutable_id: str, stream_name: str):
        self._dcr_id = dcr_immutable_id
        self._stream = stream_name
        self._client = LogsIngestionClient(
            endpoint=endpoint,
            credential=DefaultAzureCredential(),
            logging_enable=False,
        )

    def upload(
        self, alerts: Iterable[dict[str, Any]], batch_size: int = DEFAULT_BATCH_SIZE
    ) -> int:
        sent = 0
        batch: list[dict[str, Any]] = []
        for a in alerts:
            batch.append(a)
            if len(batch) >= batch_size:
                self._send(batch)
                sent += len(batch)
                batch = []
        if batch:
            self._send(batch)
            sent += len(batch)
        return sent

    def _send(self, batch: list[dict[str, Any]]) -> None:
        self._client.upload(
            rule_id=self._dcr_id, stream_name=self._stream, logs=batch
        )
        log.info("ingested batch=%d stream=%s", len(batch), self._stream)
