# fix-cli

面向 Agent 的纯 Rust FIX initiator：`fixd` 维护 FIX 会话，`fixctl` 通过本地 IPC 提交 JSON 命令，`fixdictc` 从外部 FIX Orchestra XML 生成运行时字典，`fix-mock` 提供确定性认证测试对手方。

当前版本是 **FIX 4.4 / 单一默认应用版本 FIXT 1.1 的认证环境 MVP**。生产 live 交易和 TLS 当前强制 fail-closed；项目不包含 C++、QuickFIX、OpenSSL、FFI、SQLite 或 `cargo-fuzz/libFuzzer`。

## 已实现

- TagValue frame/codec：SOH、BodyLength、CheckSum、DATA/Length、半包/粘包、重复 tag、严格 Repeating Group。
- SessionActor：Logon、Logout、Heartbeat、TestRequest、ResendRequest、GapFill SequenceReset、Reject 记录、序号持久化、回放、PossDup 原文校验、超时 Logout、指数退避重连。
- redb 原子 journal：序号、出入站原文、命令幂等、事件和 HMAC-SHA256 审计链；恢复时验证审计链。
- Agent 控制面：带版本的 JSON Schema、u32 大端长度帧、本机 Windows named pipe / Unix socket、确定性 ClOrdID、策略校验、限流、dry-run / certification / live guard。
- 外部字典：纯 Rust Orchestra XML 编译器，解析 DATA `lengthId`、component、group、nested group 和敏感标签。
- 测试工具：TCP mock acceptor、属性测试、纯 Rust bounded mutational fuzz、存储/断线故障注入、进程级 CLI 端到端测试。

## 快速开始

要求 Rust 1.97+。以下命令均在仓库根目录执行。

```powershell
cargo build --workspace

cargo run -p fixdictc -- `
  --input examples/certification/fix44-mock-orchestra.xml `
  --begin-string FIX.4.4 `
  --output examples/certification/dictionary/fix44-mock.json

cargo run -p fixd -- validate --profile examples/certification/fixd.toml
```

分别在两个终端启动 mock venue 与 daemon：

```powershell
cargo run -p fix-mock -- `
  --listen 127.0.0.1:19876 `
  --begin-string FIX.4.4 `
  --sender-comp-id SERVER `
  --target-comp-id CLIENT
```

```powershell
cargo run -p fixd -- run --profile examples/certification/fixd.toml
```

第三个终端调用：

```powershell
cargo run -p fixctl -- --profile broker-a-uat session status

cargo run -p fixctl -- --profile broker-a-uat order new `
  --input examples/certification/orders/new-order.json `
  --mode dry-run `
  --request-id agent-order-1

cargo run -p fixctl -- --profile broker-a-uat order new `
  --input examples/certification/orders/new-order.json `
  --mode certification `
  --request-id agent-order-1
```

取消/改单：

```powershell
cargo run -p fixctl -- --profile broker-a-uat order cancel `
  --input examples/certification/orders/cancel-order.json `
  --mode certification `
  --request-id agent-cancel-1

cargo run -p fixctl -- --profile broker-a-uat order replace `
  --input examples/certification/orders/replace-order.json `
  --mode certification `
  --request-id agent-replace-1
```

Agent 可直接通过 stdin 提交完整协议对象：

```powershell
Get-Content request.json -Raw |
  cargo run -p fixctl -- --profile broker-a-uat invoke --stdin
```

Schema 位于 `schemas/control-request.schema.json`，也可重新生成：

```powershell
cargo run -p fixd -- schema --output schemas/control-request.schema.json
```

## 凭据

认证环境需要 Logon 自定义字段时，复制 `secrets/logon-fields.json.example` 为未跟踪文件，例如 `secrets/logon-fields.json`，然后在 profile 的 `[session]` 中设置：

```toml
logon_fields_file = "../../secrets/logon-fields.json"
```

Tag 553/554/925 以及字典标记的敏感字段会在 redb replay journal 中替换为 `<redacted>`；真实值只写向 socket。示例文件不能用于真实环境。当前 MVP 尚未实现进程内 secret zeroization 或 OS key vault。

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
- rustls 的默认 AWS-LC provider和 ring 都会引入 native 源码；实验性的纯 Rust RustCrypto provider尚未达到本项目生产 gate，因此本版本没有悄悄降级到 OpenSSL 或 native TLS。
- 每个 profile 必须使用独立数据库、字典哈希、审计 key、CompID 和本地 IPC endpoint。
