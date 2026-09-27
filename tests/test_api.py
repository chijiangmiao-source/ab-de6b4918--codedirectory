"""HTTP API 行为测试：冻结、幂等、冲突拒绝、失败不留成功结论。"""

from __future__ import annotations

import base64
import http.client
import json
import os
import shutil
import tempfile
import threading
import unittest

from app.server import create_server
from app.store import AuditStore
from tests.fixtures import build_payload


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="seal-audit-test-")
        cls.server = create_server("127.0.0.1", 0, AuditStore(cls.tmpdir))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    # ---- 工具 ---------------------------------------------------------
    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        try:
            return resp.status, json.loads(data)
        except ValueError:
            return resp.status, None

    def submit(self, audit_id, payload):
        return self.request("POST", "/api/audits", {
            "audit_id": audit_id,
            "payload_b64": base64.b64encode(payload).decode(),
        })

    # ---- 用例 ---------------------------------------------------------
    def test_health(self):
        status, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_index_page_served(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("签封审计".encode(), body)

    def test_submit_valid_then_frozen(self):
        payload, info = build_payload()
        status, body = self.submit("api-valid", payload)
        self.assertEqual(status, 201)
        self.assertTrue(body["created"])
        audit = body["audit"]
        self.assertEqual(audit["verdict"], "pass")
        self.assertEqual(len(audit["pages"]), info["n_code_slots"])
        # 读取冻结审计：逐字节一致
        status, body2 = self.request("GET", "/api/audits/api-valid")
        self.assertEqual(status, 200)
        self.assertEqual(body2["audit"], audit)

    def test_idempotent_replay_returns_original(self):
        payload, _ = build_payload()
        s1, b1 = self.submit("api-idem", payload)
        self.assertEqual(s1, 201)
        s2, b2 = self.submit("api-idem", payload)
        self.assertEqual(s2, 200)
        self.assertFalse(b2["created"])
        self.assertEqual(b2["audit"], b1["audit"])
        self.assertEqual(b2["audit"]["created_at"], b1["audit"]["created_at"])

    def test_conflicting_payload_rejected_and_record_kept(self):
        good, _ = build_payload()
        bad, _ = build_payload(tamper_slot=1)
        s1, b1 = self.submit("api-conflict", good)
        self.assertEqual(s1, 201)
        s2, b2 = self.submit("api-conflict", bad)
        self.assertEqual(s2, 409)
        self.assertEqual(b2["error"], "audit_id_conflict")
        # 既有记录保持原样
        s3, b3 = self.request("GET", "/api/audits/api-conflict")
        self.assertEqual(s3, 200)
        self.assertEqual(b3["audit"], b1["audit"])
        self.assertEqual(b3["audit"]["verdict"], "pass")

    def test_tampered_payload_frozen_as_fail(self):
        payload, _ = build_payload(tamper_slot=3)
        status, body = self.submit("api-tampered", payload)
        self.assertEqual(status, 201)
        audit = body["audit"]
        self.assertEqual(audit["verdict"], "fail")
        self.assertEqual(audit["first_failing_slot"], 3)
        # 失败结论同样被冻结且可重放
        s2, b2 = self.submit("api-tampered", payload)
        self.assertEqual(s2, 200)
        self.assertEqual(b2["audit"], audit)

    def test_structural_failure_never_passes(self):
        status, body = self.submit("api-garbage", b"\x00" * 256)
        self.assertEqual(status, 201)
        self.assertEqual(body["audit"]["verdict"], "fail")
        self.assertIsNotNone(body["audit"]["reason"])
        s2, b2 = self.request("GET", "/api/audits/api-garbage")
        self.assertEqual(b2["audit"]["verdict"], "fail")

    def test_invalid_base64(self):
        status, body = self.request("POST", "/api/audits", {
            "audit_id": "api-bad-b64", "payload_b64": "!!!not-base64!!!"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_base64")

    def test_base64_with_whitespace_accepted(self):
        payload, _ = build_payload()
        b64 = base64.b64encode(payload).decode()
        wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
        status, body = self.request("POST", "/api/audits", {
            "audit_id": "api-wrapped", "payload_b64": wrapped})
        self.assertEqual(status, 201)
        self.assertEqual(body["audit"]["verdict"], "pass")

    def test_oversize_payload_rejected(self):
        raw = os.urandom(2 * 1024 * 1024 + 16)
        status, body = self.submit("api-huge", raw)
        self.assertEqual(status, 413)
        self.assertEqual(body["error"], "payload_too_large")
        # 超限载荷不得留下任何记录
        s2, _ = self.request("GET", "/api/audits/api-huge")
        self.assertEqual(s2, 404)

    def test_invalid_audit_id(self):
        payload, _ = build_payload()
        for bad in ("", "has space", "中文标识", "x" * 129, "-leading"):
            status, body = self.request("POST", "/api/audits", {
                "audit_id": bad,
                "payload_b64": base64.b64encode(payload).decode()})
            self.assertEqual(status, 400, bad)
            self.assertEqual(body["error"], "invalid_audit_id")

    def test_get_missing_audit(self):
        status, body = self.request("GET", "/api/audits/no-such-id")
        self.assertEqual(status, 404)

    def test_list_audits(self):
        payload, _ = build_payload()
        self.submit("api-list-1", payload)
        status, body = self.request("GET", "/api/audits")
        self.assertEqual(status, 200)
        ids = [a["audit_id"] for a in body["audits"]]
        self.assertIn("api-list-1", ids)


if __name__ == "__main__":
    unittest.main()
