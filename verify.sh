#!/bin/sh
# verify：构建检查 + 代码测试 + HTTP 冒烟；任一环节失败即以非零退出。
set -eu
cd "$(dirname "$0")"

echo "== [1/3] 构建检查：全部源码语法编译 + 关键模块可导入 =="
python3 - <<'PY'
import pathlib
import sys

ok = True
for path in sorted(pathlib.Path(".").glob("**/*.py")):
    if "__pycache__" in path.parts:
        continue
    try:
        compile(path.read_bytes(), str(path), "exec")
    except SyntaxError as exc:
        ok = False
        print("语法错误: %s" % exc)
if not ok:
    sys.exit(1)
print("语法编译通过")
PY
python3 -c "import app.server, app.codedir, app.store; print('模块导入通过')"

echo "== [2/3] 单元测试 =="
python3 -m unittest discover -s tests -t . -v

echo "== [3/3] HTTP 冒烟（目标：${SMOKE_BASE_URL:-http://127.0.0.1:8080}） =="
python3 verify/smoke.py

echo "VERIFY OK"
