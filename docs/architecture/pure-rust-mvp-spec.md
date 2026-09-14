# 纯 Rust FIX CLI MVP 规格

## 约束检查表与结论

| 约束 | 当前结论 |
|---|---|
| C++ / QuickFIX / FFI | 无依赖、无备选路径，Cargo.lock denylist 零命中 |
| native 编译 | 当前解析图无 `cc/cmake/pkg-config/vcpkg`；build.rs 仅 Rust 配置/版本探测 |
| 存储 | `redb`，无 SQLite；写事务使用 `Durability::Immediate` |
| TLS | 不使用 OpenSSL；因合格的生产纯 Rust rustls provider 尚未通过 gate，TLS/live 强制关闭 |
| 字典 | 不加载外部字典；消息按 tag 结构解析（QuickFIX `UseDataDictionary=N` 语义） |
| unsafe | workspace `unsafe_code = "forbid"` |

最终架构是一个单进程、多 profile 可独立部署的 initiator daemon `fixd`，配套 Agent CLI `fixctl`。MVP 可用于本地和 venue certification；不声称可用于 live 交易。

## 模块边界

```text
Agent
  │ JSON v1 / u32-be length frame
  ▼
fixctl ── local named pipe / Unix socket ──► fixd
                                              │
                 ┌────────────────────────────┼─────────────────────────┐
                 ▼                            ▼                         ▼
          fix-control                  fix-session                 fix-store
      schema/policy/idempotency        SessionActor              redb worker
                 │                            │                         │
                 └──────────────► fix-protocol ◄───────────────────────┘
                                  codec/dictionary
                                          │ TCP
                                          ▼
                                    FIX acceptor
```

- `fix-protocol`：byte-preserving TagValue framing 和 codec。
- `fix-store`：同步 redb 被独立 worker thread 封装；Tokio task 不执行阻塞数据库 I/O。
- `fix-session`：单 writer actor，拥有连接、序号、timer、gap buffer 和 replay；含 QuickFIX 风格 CFG 解析。
- `fix-control`：Agent schema、交易策略、确定性 ID、限流、模式 guard；不了解 TCP。
- `fix-ipc`：本地流和 bounded JSON frame；Windows 拒绝 remote pipe client，Unix socket mode 0600。
- `fixd`：QuickFIX CFG 加载、存储、连接重试、会话槽和 IPC 生命周期。
- `fixctl`：stdout 只输出单行 `ControlResponse` JSON；退出码稳定。
- `fix-mock` / `fix-fuzz`：测试 acceptor 和纯 Rust bounded mutator。

## TagValue codec

`FrameDecoder::ingest` 只接受：

1. frame 从 `8=` 开始，第一字段为 BeginString。
2. 第二字段为 ASCII decimal `9=BodyLength<SOH>`。
3. `BodyLength` 从 tag 35 起始 byte 计到 tag 10 前一个 SOH；用 checked arithmetic 计算 checksum 边界。
4. `10=` 必须恰好位于该边界，值为三位十进制；校验值是 tag 8 到 tag 10 之前所有 byte 的 modulo-256 和。
5. frame 和残留 buffer 均有上限，攻击者不能无限喂入未终止 header。

decoder 保留未完整 byte，单次 `ingest` 可返回 0..N 个 frame，因此同时处理半包和粘包。parser 使用 `Vec<Field>`，保持字段顺序与重复 tag。

parser 支持声明式的 Length→DATA tag 对：遇 Length 后按 byte 数读取紧随其后的 DATA 值，因此值内 SOH 不会被误切分；DATA tag 无 Length、顺序错误或长度越界均拒绝。

Repeating Group 由 count tag、delimiter tag 和有序 member tree 表示。运行时按 count 精确读取每个 entry，entry 必须以 delimiter 开始，支持 nested group；不会把重复 tag 折叠成 map。

## SessionActor

状态：

```text
Disconnected → Connecting → LogonSent → Established
                         ↘ Recovering ↗
Established → LogoutSent → Disconnected
任何不可安全恢复错误 → Blocked
```

关键顺序：

- 出站：构造 → redb 原子提交 wire、command、next_out → socket write+flush → 标记 Written。
- 入站：frame/envelope/sequence 验证 → redb 原子提交 wire、event、next_in → 改变 actor 状态或对 Agent 可见。
- 高序号：最多缓存 1,024 条并发送 `ResendRequest(next_in, 0)`。
- `SequenceReset(4)`：只接受 `GapFillFlag=Y` 且 `NewSeqNo > next_in`；普通 reset 被禁。
- 低序号：必须 `PossDupFlag=Y`、单一 OrigSendingTime；从 store 加载原始序号，比较原始 SendingTime 和去除 43/52/122 后的完整 payload。不存在原文或 payload 变化即 Blocked。
- 对端 ResendRequest：application 原序号重发，设置 `43=Y`、新 52、原 52 写入 122；admin/缺失区间合并成 GapFill。每次 replay/GapFill 都先以独立 transmission 原子持久化，socket flush 后再标记 Written，不推进 `next_out`。
- 空闲：无出站一个 HeartBtInt 发 Heartbeat；无入站两个 HeartBtInt 发 TestRequest；到期先发 Logout 再 Blocked。
- 对端 TestRequest：入站 commit 后回相同 112 的 Heartbeat。
- 断线：`fixd` 清空会话槽，按配置指数退避重连；redb 恢复 next_in/next_out。Agent status 仍返回 `disconnected`。

## FIX 版本与消息解析

- 仅支持 FIX 4.4（BeginString `FIX.4.4`），initiator 与 acceptor 均由 QuickFIX 风格 CFG 描述。
- 消息解析按 tag 结构进行（`UseDataDictionary=N` 语义），不加载外部数据字典；字段校验由服务端负责。
- FIXT 1.1 / FIX 5 当前不支持。

## Agent JSON/IPC 协议

请求 envelope：

```json
{
  "version": 1,
  "request_id": "agent-order-1",
  "profile": "CLIENT-SERVER",
  "execution_mode": "certification",
  "command": {
    "type": "new_order_single",
    "symbol": "IBM",
    "side": "buy",
    "quantity": "100",
    "ord_type": "limit",
    "price": "187.25",
    "time_in_force": "day"
  },
  "auth": null
}
```

IPC 是 `u32 big-endian payload_length || UTF-8 JSON`，单 frame 上限 256 KiB。daemon 最多保留 64 个并发 client，每个 frame 的读写期限为 5 秒。ControlRequest 的 JSON Schema 可由 `fixd schema` 随时生成。

命令：`session_status`、`session_logout`、`new_order_single`、`cancel_order`、`replace_order`。价格/数量必须是正十进制字符串；daemon 注入 8/9/10/11/34/35/49/52/56/60 等受管 tag。

同一 profile + `request_id` 生成确定 ClOrdID。store 保存 request fingerprint：

- 同 request_id、同 fingerprint：返回原 command，不再写 socket。
- 同 request_id、不同 fingerprint：`IDEMPOTENCY_CONFLICT`。

响应：

```json
{
  "version": 1,
  "request_id": "agent-order-1",
  "ok": true,
  "result": {
    "phase": "written_to_socket",
    "cl_ord_id": "FC-...",
    "msg_seq_num": 2,
    "venue_status": "pending"
  }
}
```

主要错误/退出码：

| exit | 错误码 |
|---:|---|
| 2 | `INVALID_REQUEST`, `SCHEMA_VERSION_UNSUPPORTED`, `PROFILE_NOT_FOUND` |
| 3 | `POLICY_DENIED`, `LIVE_GUARD_NOT_ARMED` |
| 4 | `SESSION_NOT_ESTABLISHED` |
| 5 | `IDEMPOTENCY_CONFLICT` |
| 6 | `PROTOCOL_ERROR`, `TRANSPORT_ERROR` |
| 7 | `STORE_UNAVAILABLE` |
| 8 | `RATE_LIMITED`, `TIMEOUT` |
| 70 | 未分类内部错误 |

## 存储与交易安全

- redb 表：meta、commands、outbound、transmissions、inbound、events。
- write transaction 使用 `Durability::Immediate`；sequence 和对应 record 同事务更新。
- 所有自定义 Logon 字段与 553/554/925 的 journal 值为 `<redacted>`；入站敏感 tag 在 commit 前拒绝。
- policy：最大 quantity、最大 notional、每秒消息滑动窗口；持久幂等查询、限流和 submit 在控制面 single-flight 区间内执行。市场单在具备受限参考价格前始终拒绝。
- dry-run 完成 schema/策略/字段映射但不访问 socket；certification 才可发；live 在 config 和 request 两层拒绝。
- 本地 IPC 不是 live 身份认证。Windows named pipe 显式拒绝远程 client；Unix socket 拒绝覆盖非 socket 路径并设置 0600。

## Workspace

```text
crates/
  fix-protocol/  fix-store/     fix-session/
  fix-control/   fix-ipc/   fixd/       fixctl/
  fix-mock/      fix-fuzz/
examples/certification/
docs/
```

workspace 使用 Rust 2024、MSRV 1.97、resolver 3 和 committed `Cargo.lock`。

## 范围分级

### MVP 已实现

- FIX 4.4 certification initiator。
- D/F/G 和 ExecutionReport 接收；session admin、序号、回放、重连。
- redb、Agent IPC、策略、限流、mock、属性/变异/故障测试。

### 生产级前必须完成

- 经过安全审计并获批准的纯 Rust rustls CryptoProvider；`rustls/tokio-rustls` mTLS、证书 pin/轮换和 TLS certification。
- live capability proof：短时效、nonce replay cache、operator key rotation、双人/环境审批策略。
- secret zeroization、OS key vault、IPC 明确 ACL/peer identity。
- 真实 venue 长稳 certification、HA/单活 fencing、监控告警、灾备与断电测试。
- FIXT 1.1 支持与同会话多 ApplVerID 字典路由。

### 暂不支持

- acceptor 生产模式、多腿/算法单等未建模业务消息。
- ResetSeqNumFlag 自动重置和 non-gapfill SequenceReset。
- TLS/live、OpenSSL/native crypto fallback。
- QuickFIX/C++ 迁移桥、SQLite、覆盖引导 libFuzzer。

## 已验证与未验证

已在 Windows MSVC / Rust 1.97.1 执行 workspace `fmt`、`check --all-targets`、自动测试、真实 named pipe 和 10,000 例 fuzz；本次开发另人工执行过真实 `fix-mock` + `fixd` + `fixctl` 进程级 smoke。仓库当前没有自动 child-process E2E。

未验证：Linux/macOS、真实 venue、TLS、live、HA、断电和大规模性能。任何这些内容都不得从当前测试结果推断为可用。
