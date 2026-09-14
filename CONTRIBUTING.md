# Engineering standard

## 不可破坏的边界

- 禁止 C++、QuickFIX、quickfix-rs、FFI、`cxx`、`bindgen`、OpenSSL、AWS-LC、ring、SQLite、`cc`、CMake、pkg-config、vcpkg 和 libFuzzer。
- workspace 自有 crate 必须保留 `#![forbid(unsafe_code)]` 或 workspace `unsafe_code = "forbid"`。
- 所有 FIX 消息必须先通过 `fix-protocol` framing/codec。
- 出站消息必须先持久化，后写 socket；入站消息必须先持久化，后改变业务可见状态。
- live 路径必须 fail-closed。没有经过批准的 TLS provider、capability proof、nonce 防重放和认证测试，不得解除 gate。

## 代码规则

- 公共错误使用稳定错误码；不要把凭据、原始认证字段或支付/联系信息写入错误、日志或 Agent JSON。
- 金额和数量使用十进制字符串与 `rust_decimal`，禁止 `f32/f64`。
- FIX 字段保持原始 byte 值和顺序；重复 tag 不能被 `HashMap` 静默覆盖。
- 时间、随机性和 I/O 需要可替换 seam，测试使用固定 seed / `StaticTimeSource`。
- 新依赖必须说明 feature、纯 Rust 状态、build.rs 和 transitive native 风险。

## 提交前

```text
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
```

协议、session、store 或交易策略变更必须先增加会失败的测试，再实现最小修复。
