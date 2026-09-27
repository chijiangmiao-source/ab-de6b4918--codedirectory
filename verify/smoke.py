"""HTTP 冒烟：健康状态、提交审计、读取冻结结论、分页证据与幂等行为。

通过环境变量 SMOKE_BASE_URL 指向被测服务（默认 http://127.0.0.1:8080）。
全部检查通过时打印 SMOKE OK 并以 0 退出，否则以 1 退出。
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import build_payload  # noqa: E402

BASE = os.environ.get("SMOKE_BASE_URL", "http://127.0.0.1:8080").rstrip("/")

_failures = []


def check(name, cond, detail=""):
    mark = "ok" if cond else "FAIL"
    print("[%s] %s%s" % (mark, name, (" -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        _failures.append(name)


def request(method, path, body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def wait_for_health(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = request("GET", "/health")
            if status == 200 and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def main():
    print("smoke target: %s" % BASE)
    check("health endpoint reachable", wait_for_health())

    # 1. 提交合法载荷 -> 201 + pass + 分页证据
    payload, info = build_payload()
    audit_id = "smoke-" + uuid.uuid4().hex[:12]
    status, body = request("POST", "/api/audits", {
        "audit_id": audit_id,
        "payload_b64": base64.b64encode(payload).decode()})
    check("submit valid payload -> 201", status == 201, status)
    audit = body.get("audit", {})
    check("verdict is pass", audit.get("verdict") == "pass", audit.get("verdict"))
    pages = audit.get("pages", [])
    check("page evidence count matches n_code_slots",
          len(pages) == info["n_code_slots"], len(pages))
    check("page evidence ascending by slot",
          [p.get("slot") for p in pages] == list(range(len(pages))))
    check("all pages match", all(p.get("match") for p in pages))
    cov = audit.get("coverage", {})
    check("coverage end equals codeLimit",
          cov.get("end") == info["code_limit"], cov)
    check("page size reported", cov.get("page_size") == info["page_size"])
    cd = audit.get("code_directory", {})
    check("code directory summary present",
          cd.get("hash_type") == "sha256" and cd.get("page_size") == info["page_size"])

    # 2. 读取冻结审计 -> 与提交响应一致
    status, frozen = request("GET", "/api/audits/" + audit_id)
    check("frozen audit readable", status == 200, status)
    check("frozen audit identical to submit response",
          frozen.get("audit") == audit)

    # 3. 完全相同载荷重传 -> 幂等返回原审计
    status, replay = request("POST", "/api/audits", {
        "audit_id": audit_id,
        "payload_b64": base64.b64encode(payload).decode()})
    check("identical replay -> 200", status == 200, status)
    check("identical replay returns original audit",
          replay.get("audit") == audit and replay.get("created") is False)

    # 4. 复用标识但更换字节 -> 409 且保留既有记录
    tampered, _ = build_payload(tamper_slot=1)
    status, conflict = request("POST", "/api/audits", {
        "audit_id": audit_id,
        "payload_b64": base64.b64encode(tampered).decode()})
    check("conflicting payload -> 409", status == 409, status)
    check("conflict error code", conflict.get("error") == "audit_id_conflict")
    status, after = request("GET", "/api/audits/" + audit_id)
    check("original record kept after conflict",
          status == 200 and after.get("audit", {}).get("verdict") == "pass")

    # 5. 被篡改载荷 -> fail，指出首个失败槽，绝不记为通过
    fail_id = "smoke-" + uuid.uuid4().hex[:12]
    status, body = request("POST", "/api/audits", {
        "audit_id": fail_id,
        "payload_b64": base64.b64encode(tampered).decode()})
    faudit = body.get("audit", {})
    check("tampered payload -> 201 with fail verdict",
          status == 201 and faudit.get("verdict") == "fail",
          (status, faudit.get("verdict")))
    check("first failing slot reported",
          faudit.get("first_failing_slot") == 1, faudit.get("first_failing_slot"))
    fpages = faudit.get("pages", [])
    check("failing page marked mismatch",
          len(fpages) > 1 and fpages[1].get("match") is False)
    status, ffrozen = request("GET", "/api/audits/" + fail_id)
    check("failed audit frozen as fail",
          status == 200 and ffrozen.get("audit", {}).get("verdict") == "fail")

    # 6. 结构损坏载荷 -> fail 且不留成功结论
    garbage_id = "smoke-" + uuid.uuid4().hex[:12]
    status, body = request("POST", "/api/audits", {
        "audit_id": garbage_id,
        "payload_b64": base64.b64encode(b"\x00" * 512).decode()})
    check("structural garbage -> fail verdict",
          status == 201 and body.get("audit", {}).get("verdict") == "fail",
          (status, body.get("audit", {}).get("verdict")))

    if _failures:
        print("SMOKE FAILED: %d check(s): %s" % (len(_failures), ", ".join(_failures)))
        return 1
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
