import json
import logging
import sqlite3
import time
import uuid
from datetime import datetime, timezone

import config


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "correlation_id"):
            payload["correlation_id"] = record.correlation_id
        if hasattr(record, "module_name"):
            payload["module"] = record.module_name
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "metadata"):
            payload["metadata"] = record.metadata
        return json.dumps(payload, ensure_ascii=True)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def new_correlation_id(prefix: str = "ds") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def record_metric(metric_name: str, metric_value: float, metric_unit: str = "",
                  module: str = "", correlation_id: str = "", metadata: dict | None = None):
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
            metric_name     TEXT NOT NULL,
            metric_value    REAL NOT NULL,
            metric_unit     TEXT,
            module          TEXT,
            correlation_id  TEXT,
            metadata_json   TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO security_metrics "
        "(metric_name, metric_value, metric_unit, module, correlation_id, metadata_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            metric_name,
            float(metric_value),
            metric_unit,
            module,
            correlation_id,
            json.dumps(metadata or {}),
        ),
    )
    conn.commit()
    conn.close()


class Timer:
    def __init__(self):
        self._start = time.perf_counter()

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0
