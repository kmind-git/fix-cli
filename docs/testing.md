# 测试与认证计划

## 自动化层级

| 层级 | 当前覆盖 |
|---|---|
| 单元 | BodyLength/CheckSum、DATA、group、Orchestra 编译、策略映射、错误码、redb 事务 |
| 确定性属性 | 2,000 个 codec round-trip + 任意 fragmentation；10,000 个 bounded random input 抗崩溃 |
| 集成 | SessionActor Logon/Logout/heartbeat/TestRequest/resend/gapfill/replay/PossDup；Windows named pipe；TCP reconnect |
| 故障注入 | application/replay journal 失败不得写 socket；传输断开重连并恢复序号；错误审计 key 拒绝恢复 |
| 端到端 | Agent `ControlRequest` → ControlService → SessionActor → mock venue → ExecutionReport |
| 进程级 smoke | 本次开发中人工运行 `fix-mock` + `fixd` + `fixctl`，验证 status 与 certification NewOrderSingle；尚未提交自动 child-process 测试 |
| 纯 Rust fuzz | `fix-fuzz` 固定 seed bounded mutator，不依赖 libFuzzer/C++ |

## 常规命令

```powershell
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo run --locked -p fix-fuzz -- --seed 4354685564936845355 --cases 10000 --max-input-bytes 4096
```

发现 parser panic、错误接受或状态机分歧时，固定 seed 和最小样本必须加入 `tests/`，之后才能修改实现。

## Certification 清单

每个真实对手方单独维护 profile 与测试记录，至少执行：

1. Logon 正常、CompID 错误、HeartBtInt 不一致、重复 Logon。
2. 空闲 Heartbeat、TestRequest/Heartbeat 回应、TestRequest 超时 Logout。
3. inbound/outbound sequence gap、`EndSeqNo=0`、混合 admin/application replay、多个连续 GapFill。
4. PossDup 正常重放、OrigSendingTime 错误、payload 篡改、未知旧序号。
5. D/F/G 字段顺序、价格/数量精度、拒单、部分成交、完全成交、取消、改单。
6. socket 半包、粘包、慢读、突然 EOF、连接拒绝、重连抖动。
7. daemon kill/restart、journaled-but-not-written、redb reopen、错误审计 key。
8. Orchestra 字典哈希不匹配、未知 MsgType、缺少 required tag、错误 repeating group count。
9. 超限数量/名义金额/市场单、symbol allowlist、速率上限、幂等冲突。
10. 对手方正式 certification script 和结果归档。

## 尚未执行

- Linux GNU/musl、macOS 的编译和 Unix socket 权限测试。
- 真正断电/文件系统损坏测试；当前只有重启和逻辑故障注入。
- 真实券商/交易所 FIX certification。
- TLS 互操作、mTLS、证书轮换；TLS/live 当前不可启用。
- 覆盖引导 fuzz；`cargo-fuzz/libfuzzer-sys` 因 C++ 被明确排除。
