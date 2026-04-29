import argparse
import sqlite3
import time
from typing import Dict

import config

try:
    from prometheus_client import Gauge, start_http_server
except ImportError as exc:
    raise RuntimeError(
        "prometheus_client is required for this exporter. Install with: pip install prometheus-client"
    ) from exc


GAUGES: Dict[str, Gauge] = {}


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_gauge(name: str) -> Gauge:
    safe = "darkspace_" + "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name.lower())
    if safe not in GAUGES:
        GAUGES[safe] = Gauge(safe, f"DARKSPACE metric: {name}", ["module", "unit"])
    return GAUGES[safe]


def scrape_once() -> int:
    conn = _get_conn()
    rows = conn.execute(
        """
        SELECT metric_name, metric_value, COALESCE(metric_unit, '') AS metric_unit, COALESCE(module, '') AS module
        FROM security_metrics
        WHERE id IN (
            SELECT MAX(id)
            FROM security_metrics
            GROUP BY metric_name, COALESCE(module, ''), COALESCE(metric_unit, '')
        )
        """
    ).fetchall()
    conn.close()

    for row in rows:
        g = _ensure_gauge(row["metric_name"])
        g.labels(module=row["module"], unit=row["metric_unit"]).set(float(row["metric_value"]))
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export DARKSPACE security_metrics to Prometheus")
    parser.add_argument("--port", type=int, default=9109, help="Prometheus exporter port")
    parser.add_argument("--interval", type=int, default=15, help="Scrape interval seconds")
    args = parser.parse_args()

    start_http_server(args.port)
    print(f"[PROM] DARKSPACE exporter listening on :{args.port}")

    while True:
        count = scrape_once()
        print(f"[PROM] exported {count} metric series")
        time.sleep(args.interval)
