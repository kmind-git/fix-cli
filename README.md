# fix-cli

面向 Agent 的纯 Rust FIX initiator：`fixd` 维护 FIX 会话，`fixctl` 通过本地 IPC 提交 JSON 命令，`fix-mock` 提供确定性认证测试对手方。

当前版本是 **FIX 4.4 认证环境 MVP**（QuickFIX 风格 CFG 驱动、按 tag 结构解析）。生产 live 交易和 TLS 当前强制 fail-closed；项目不包含 C++、QuickFIX、OpenSSL、FFI、SQLite 或 `cargo-fuzz/libFuzzer`。

## 已实现

- TagValue frame/codec：SOH、BodyLength、CheckSum、DATA/Length、半包/粘包、重复 tag、严格 Repeating Group。
- SessionActor：Logon、Logout、Heartbeat、TestRequest、ResendRequest、GapFill SequenceReset、Reject 记录、序号持久化、回放、PossDup 原文校验、超时 Logout、指数退避重连。
- redb 原子 journal：序号、出入站原文、resend transmission、命令幂等和事件。
- Agent 控制面：带版本的 JSON Schema、u32 大端长度帧、本机 Windows named pipe / Unix socket、确定性 ClOrdID、策略校验、限流、dry-run / certification / live guard。
- 测试工具：TCP mock acceptor、属性测试、纯 Rust bounded mutational fuzz、存储/断线/回放故障注入、自动 Agent-to-mock 端到端测试；另有人工作过进程级 CLI smoke test。

## 快速开始

要求 Rust 1.97+。以下命令均在仓库根目录执行。

```powershell
cargo build --workspace
```

分别在两个终端启动 mock venue 与 daemon（均由 QuickFIX 风格 CFG 驱动）：

```powershell
cargo run -p fix-mock -- --cfg config/mock/SERVER.CFG
```

```powershell
cargo run -p fixd -- run-real --cfg config/mock/CLIENT.CFG
```

第三个终端调用（profile 名为 `{SenderCompID}-{TargetCompID}`）：

```powershell
cargo run -p fixctl -- --profile CLIENT-SERVER session status

cargo run -p fixctl -- --profile CLIENT-SERVER order new `
  --input examples/orders/new-order.json `
  --mode dry-run `
  --request-id agent-order-1

cargo run -p fixctl -- --profile CLIENT-SERVER order new `
  --input examples/orders/new-order.json `
  --mode certification `
  --request-id agent-order-1
```

取消/改单：

```powershell
cargo run -p fixctl -- --profile CLIENT-SERVER order cancel `
  --input examples/orders/cancel-order.json `
  --mode certification `
  --request-id agent-cancel-1

cargo run -p fixctl -- --profile CLIENT-SERVER order replace `
  --input examples/orders/replace-order.json `
  --mode certification `
  --request-id agent-replace-1
```

Agent 可直接通过 stdin 提交完整协议对象：

```powershell
Get-Content request.json -Raw |
  cargo run -p fixctl -- --profile CLIENT-SERVER invoke --stdin
```

## 凭据与真实柜台

连接真实 FIX 柜台时，用 QuickFIX 风格的 CLIENT.CFG 启动（`config/CLIENT.CFG` 即当前连接恒生认证环境的配置）：

```powershell
cargo run -p fixd -- run-real --cfg config/CLIENT.CFG
cargo run -p fixctl -- --profile CLIENTCOMPIDT_gq-HUNDSUNSTRD session status
```

Logon 自定义字段（如 `LogonField.554=secret` 写入 554 Password）直接配置在 CLIENT.CFG 的会话节；所有自定义 Logon 字段与 Tag 553/554/925 都会在 redb replay journal 中替换为 `<redacted>`，真实值只写向 socket。含敏感 tag 的入站消息会在持久化前 fail-closed。当前 MVP 尚未实现进程内 secret zeroization 或 OS key vault。

## 验证

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p fix-fuzz -- --seed 4354685564936845355 --cases 10000 --max-input-bytes 4096
```

当前完整设计、边界和未支持项见：

- `docs/architecture/pure-rust-mvp-spec.md`
- `docs/testing.md`
- `docs/research/pure-rust-dependency-audit.md`

## 安全边界

- `runtime_mode = "live"` 和所有 `execution_mode = "live"` 请求当前均被拒绝。
- `plaintext_cert` 只允许认证/本地 mock 环境，不是生产传输。
- 市场单当前始终拒绝；在实现受限参考价格/名义金额策略前，`allow_market_orders = true` 会使配置校验失败。
- rustls 的默认 AWS-LC provider和 ring 都会引入 native 源码；实验性的纯 Rust RustCrypto provider尚未达到本项目生产 gate，因此本版本没有悄悄降级到 OpenSSL 或 native TLS。
- 每个 profile 必须使用独立数据库、CompID 和本地 IPC endpoint。
