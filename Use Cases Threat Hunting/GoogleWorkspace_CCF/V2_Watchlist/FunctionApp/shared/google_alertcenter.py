"""Google Workspace Alert Center API client.

Uses domain-wide delegated service-account credentials (the only auth method
Google supports for ``alertcenter.googleapis.com``). The OAuth user-flow
returns ``invalid_scope`` for ``apps.alerts``, which is why this connector is
codeful instead of CCF.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

import requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleAuthRequest

ALERT_CENTER_BASE = "https://alertcenter.googleapis.com/v1beta1/alerts"
SCOPES = ["https://www.googleapis.com/auth/apps.alerts"]
DEFAULT_TIMEOUT = 60

log = logging.getLogger(__name__)


def _load_credentials(sa_json: str, subject: str) -> service_account.Credentials:
    info = json.loads(sa_json)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=SCOPES, subject=subject
    )
    return creds


def _refresh_token(creds: service_account.Credentials) -> str:
    creds.refresh(GoogleAuthRequest())
    return creds.token


def iter_alerts(
    sa_json: str,
    subject: str,
    create_time_gt: str,
    page_size: int = 1000,
) -> Iterator[dict[str, Any]]:
    """Yield alerts created strictly after ``create_time_gt`` (RFC3339 UTC).

    The API ``filter`` operator ``>`` is supported on ``createTime``. We order
    ascending so the cursor advances monotonically and we can resume safely.
    """
    creds = _load_credentials(sa_json, subject)
    token = _refresh_token(creds)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    params: dict[str, str] = {
        "pageSize": str(page_size),
        "orderBy": "createTime asc",
        "filter": f'createTime > "{create_time_gt}"',
    }

    page = 0
    total = 0
    while True:
        page += 1
        resp = requests.get(
            ALERT_CENTER_BASE, headers=headers, params=params, timeout=DEFAULT_TIMEOUT
        )
        if resp.status_code == 401:
            # Token may have expired mid-pagination on a slow run.
            token = _refresh_token(creds)
            headers["Authorization"] = f"Bearer {token}"
            resp = requests.get(
                ALERT_CENTER_BASE, headers=headers, params=params, timeout=DEFAULT_TIMEOUT
            )
        resp.raise_for_status()
        body = resp.json()
        alerts = body.get("alerts") or []
        total += len(alerts)
        log.info("alertcenter page=%d alerts=%d", page, len(alerts))
        for a in alerts:
            yield a
        next_token = body.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token
    log.info("alertcenter total alerts fetched=%d", total)
