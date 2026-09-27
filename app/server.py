"""HTTP 服务：健康状态、审计提交/查询、审计页面。仅用标准库。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .codedir import MAX_PAYLOAD_BYTES, verify_payload
from .store import AuditStore

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_B64_LEN = ((MAX_PAYLOAD_BYTES + 2) // 3) * 4
MAX_BODY_BYTES = MAX_B64_LEN + 8192  # JSON 包装余量

INDEX_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "static", "index.html")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AuditHandler(BaseHTTPRequestHandler):
    store: AuditStore = None  # 由 make_handler 注入
    server_version = "SealAudit/1.0"
    protocol_version = "HTTP/1.1"

    # ---- 基础工具 -----------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: A003 - 标准库命名
        import sys
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, body: bytes, status: int, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, status: int = 200):
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   status, "application/json; charset=utf-8")

    def _error(self, status: int, code: str, message: str):
        self._send_json({"error": code, "message": message}, status)

    # ---- 路由 ---------------------------------------------------------
    def do_GET(self):  # noqa: N802 - 标准库命名
        path = urllib.parse.urlparse(self.path).path
        if path == "/health":
            self._send_json({"status": "ok", "audits": self.store.count()})
        elif path == "/" or path == "/index.html":
            try:
                with open(INDEX_HTML, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._error(500, "index_missing", "页面文件缺失")
                return
            self._send(body, 200, "text/html; charset=utf-8")
        elif path == "/api/audits":
            self._send_json({"audits": self.store.list_summaries()})
        elif path.startswith("/api/audits/"):
            audit_id = urllib.parse.unquote(path[len("/api/audits/"):])
            record = self.store.get(audit_id)
            if record is None:
                self._error(404, "not_found", "审计标识 %r 不存在" % audit_id)
            else:
                self._send_json({"audit": record})
        else:
            self._error(404, "not_found", "未知路径")

    def do_POST(self):  # noqa: N802 - 标准库命名
        path = urllib.parse.urlparse(self.path).path
        if path != "/api/audits":
            self._error(404, "not_found", "未知路径")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            self._error(400, "empty_body", "请求体为空")
            return
        if length > MAX_BODY_BYTES:
            self._error(413, "payload_too_large", "请求体超过 2 MiB 载荷上限")
            return
        body = self.rfile.read(length)
        try:
            request = json.loads(body)
        except ValueError:
            self._error(400, "invalid_json", "请求体不是合法 JSON")
            return
        if not isinstance(request, dict):
            self._error(400, "invalid_json", "请求体必须是 JSON 对象")
            return
        self._handle_submit(request)

    # ---- 审计提交 -----------------------------------------------------
    def _handle_submit(self, request: dict):
        audit_id = request.get("audit_id")
        payload_b64 = request.get("payload_b64")
        if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id):
            self._error(400, "invalid_audit_id",
                        "审计标识须为 1-128 位字母数字开头，可含 . _ : -")
            return
        if not isinstance(payload_b64, str):
            self._error(400, "invalid_payload", "payload_b64 必须是 Base64 字符串")
            return
        compact = re.sub(r"\s+", "", payload_b64)
        if len(compact) > MAX_B64_LEN:
            self._error(413, "payload_too_large", "解码后载荷超过 2 MiB 上限")
            return
        try:
            raw = base64.b64decode(compact, validate=True)
        except binascii.Error:
            self._error(400, "invalid_base64", "payload_b64 不是合法 Base64")
            return
        if not raw:
            self._error(400, "empty_payload", "载荷为空")
            return
        if len(raw) > MAX_PAYLOAD_BYTES:
            self._error(413, "payload_too_large", "解码后载荷超过 2 MiB 上限")
            return

        digest = hashlib.sha256(raw).hexdigest()
        existing = self.store.get(audit_id)
        if existing is not None:
            if existing.get("payload_sha256") == digest:
                # 完全相同载荷的重传：返回原冻结审计（幂等）
                self._send_json({"created": False, "audit": existing}, 200)
            else:
                # 复用标识但更换字节：拒绝并保留既有记录
                self._send_json({
                    "error": "audit_id_conflict",
                    "message": "审计标识 %r 已冻结于不同载荷，拒绝覆盖" % audit_id,
                    "existing_payload_sha256": existing.get("payload_sha256"),
                    "submitted_payload_sha256": digest,
                }, 409)
            return

        result = verify_payload(raw)
        record = {
            "audit_id": audit_id,
            "payload_sha256": digest,
            "payload_size": len(raw),
            "created_at": _utcnow(),
            **result,
        }
        stored, created = self.store.put_if_absent(record)
        self._send_json({"created": created, "audit": stored},
                        201 if created else 200)


def make_handler(store: AuditStore):
    class BoundHandler(AuditHandler):
        pass
    BoundHandler.store = store
    return BoundHandler


def create_server(host: str, port: int, store: AuditStore) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(store))


def main():
    port = int(os.environ.get("PORT", "8080"))
    store_dir = os.environ.get("AUDIT_STORE_DIR",
                               os.path.join(os.getcwd(), "data"))
    store = AuditStore(store_dir)
    httpd = create_server("0.0.0.0", port, store)
    print("seal-audit  listening on :%d  store=%s" % (port, store_dir), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
