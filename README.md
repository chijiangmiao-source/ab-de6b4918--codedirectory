# 星载载荷固件签封审计（seal-audit）

上线前审查工具：核对供应商固件（Mach-O 切片）内嵌签封目录是否**逐页覆盖**
可执行字节，防止查看器只显示"签名存在"而漏掉被替换的页面。

## 功能

- 页面粘贴不超过 **2 MiB** 的 Base64 Mach-O 切片与稳定审计标识，提交后得到：
  - **冻结结论**（通过 / 未通过 + 失败原因 + 首个失败槽）
  - **代码目录摘要**（ident、版本、散列类型、槽数、hashOffset、codeLimit 等）
  - **页大小与代码覆盖范围**（0 .. codeLimit）
  - **按页升序的摘要比对证据**（每页期望/实算 SHA-256 与结论）
- 只接受**单个大端 SuperBlob**（`0xfade0cc0`）中的 **SHA-256 CodeDirectory**；
  严格校验长度、索引、偏移、哈希槽边界与 `codeLimit`，按声明页长以原始字节
  复算每个代码槽。
- 不支持的散列类型 / 槽数 / 页指数，或任一页不符：指出首个失败槽或失败原因，
  **绝不把部分结果记为通过**；结构解析失败也不会留下成功结论。
- 幂等：相同标识重传**完全相同**的载荷返回原冻结审计；复用标识但更换字节
  返回 `409` 并保留既有记录。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康状态 |
| GET | `/` | 审计页面 |
| POST | `/api/audits` | 提交 `{audit_id, payload_b64}`；`201` 新建、`200` 幂等重放、`409` 标识冲突、`400/413` 请求非法 |
| GET | `/api/audits/{id}` | 读取冻结审计（含逐页证据） |
| GET | `/api/audits` | 审计摘要列表 |

## 运行

```bash
# 宿主机端口可配置（默认 8080）
PORT=9090 docker compose up app

# 本地无 Docker 时
PORT=8080 AUDIT_STORE_DIR=./data python3 -m app.server
```

## 验证（verify）

`verify` 服务依次执行：构建检查（源码语法编译 + 模块导入）→ 单元测试 →
HTTP 冒烟（等待健康状态、提交审计、读取冻结结论、核对分页证据与幂等/冲突
行为），随后退出并以退出码报告结果：

```bash
docker compose up --exit-code-from verify verify   # 退出码即 verify 结果
echo $?
```

本地等价流程（先启动服务于 8080）：

```bash
python3 -m app.server &          # 另起终端或后台
sh verify.sh                     # 构建检查 + 测试 + 冒烟
```

## 布局

```
app/codedir.py   Mach-O / SuperBlob / CodeDirectory 严格解析与逐页复算
app/server.py    HTTP API + 页面（仅标准库）
app/store.py     冻结审计的原子持久化
app/static/      审计页面
tests/           单元测试与合成载荷夹具
verify/smoke.py  HTTP 冒烟脚本
verify.sh        verify 服务入口（构建检查 + 测试 + 冒烟）
compose.yaml     app（健康检查、可配置端口）+ verify（跑完即退出）
```
