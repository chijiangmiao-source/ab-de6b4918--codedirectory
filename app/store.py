"""冻结审计记录的持久化存储（每个标识一个 JSON 文件，原子写入）。"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse


class AuditStore:
    def __init__(self, directory: str):
        self._dir = directory
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, audit_id: str) -> str:
        return os.path.join(self._dir, urllib.parse.quote(audit_id, safe="") + ".json")

    def get(self, audit_id: str) -> dict | None:
        try:
            with open(self._path(audit_id), "r", encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, ValueError):
            return None
        return record if isinstance(record, dict) else None

    def put_if_absent(self, record: dict) -> tuple[dict, bool]:
        """原子写入；若标识已存在则原样返回既有记录，created=False。"""
        with self._lock:
            existing = self.get(record["audit_id"])
            if existing is not None:
                return existing, False
            path = self._path(record["audit_id"])
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(record, fh, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp, path)
            return record, True

    def list_summaries(self) -> list[dict]:
        out = []
        for name in sorted(os.listdir(self._dir)):
            if not name.endswith(".json"):
                continue
            audit_id = urllib.parse.unquote(name[:-5])
            record = self.get(audit_id)
            if record is None:
                continue
            out.append({
                "audit_id": record.get("audit_id"),
                "verdict": record.get("verdict"),
                "created_at": record.get("created_at"),
                "payload_sha256": record.get("payload_sha256"),
                "payload_size": record.get("payload_size"),
            })
        return out

    def count(self) -> int:
        return sum(1 for n in os.listdir(self._dir) if n.endswith(".json"))
