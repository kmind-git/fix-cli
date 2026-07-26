# 纯 Rust FIX Engine 依赖边界审计

- 审计日期：2026-07-26
- 范围：当前 workspace 锁定依赖、源码、feature、构建脚本和操作系统接口边界
- 来源规则：只采用 crates.io/docs.rs 上的 crate 官方文档与源码、项目官方 GitHub、Rust/Tokio/rustls/redb 官方文档
- 状态：实现后审计；已执行 `cargo fetch --locked`、离线 `cargo metadata`、`cargo check/test`、build.rs 扫描和 Cargo.lock denylist

## 结论摘要

1. FIX codec、会话状态机、CLI/JSON、外部 XML 字典、IPC、限流和 redb 存储已经以 Rust 实现并通过当前 Windows 构建与测试。
2. **TLS 是生产落地的关键阻塞项。** `rustls 0.23` 与 `tokio-rustls 0.26` 默认启用 `aws-lc-rs`，其 `aws-lc-sys` 通过 FFI 使用 AWS-LC，并要求 C/C++ 工具链。切换到 `ring` 也不满足约束，因为 `ring` 构建 C 与汇编源码。
3. 成熟、通用、生产可推荐且“源码级纯 Rust、无 C/汇编”的 rustls provider 目前没有：
   - `rustls-rustcrypto` 宣称纯 Rust，但版本仍为 `0.0.2-alpha`，官方明确写明不可用于生产。
   - `rustls-graviola` 不需要外部 C 编译器/汇编器，但包含手写汇编，项目也明确提示较新且平台/CPU 有限制，因此不满足源码级纯 Rust约束，也不能作为通用默认方案。
4. `redb` 是纯 Rust、ACID、崩溃安全的嵌入式存储；生产中必须使用默认的 `Durability::Immediate`，并把序号、待回放消息和幂等记录放在同一个写事务里。
5. Tokio 的 Windows named pipe 与 Unix domain socket 都由 Rust API 直接支持，不需要 C++。Unix 侧会通过 Rust 的 FFI/系统调用访问 OS，Windows 侧通过 `windows-sys` 访问 Win32；这不是编译第三方 C/C++。
6. `cargo-fuzz` 默认使用 `libfuzzer-sys`，其构建脚本明确编译 C++17 的 libFuzzer 源码，**必须排除**。严格约束下使用固定 seed 属性循环、固定语料回归测试和自研纯 Rust 变异测试器。

## 当前锁文件实测

- `Cargo.lock` 包条目：87；当前离线 `cargo metadata` 实际解析节点：85。
- denylist 命中：0。
- 不存在 `quickfix`、`cxx`、`bindgen`、OpenSSL、AWS-LC、ring、SQLite、`cc`、CMake、pkg-config、vcpkg 或 libFuzzer。
- 含 build.rs 的解析包：`generic-array`、`libc`、`num-traits`、`proc-macro2`、`quote`、`redb`、`ref-cast`、`rust_decimal`、`rustversion`、`serde`、`serde_core`、`serde_json`、`thiserror`、`wasm-bindgen`、`wasm-bindgen-shared`、`zmij`。
- 对上述 build.rs 扫描 `cc::`、CMake、pkg-config、vcpkg、bindgen、clang/gcc/cl.exe 与外部命令：没有 C/C++ 编译调用。命中的 `Command::new` 是 rustc 版本探测，以及非当前 target 的 FreeBSD/wasm 工具探测。
- `libc` / `windows-sys` 属于 OS ABI 边界，不编译仓库附带的 C/C++ 源码。

当前直接依赖：

| 依赖 | 用途 | 纯 Rust / 边界 |
|---|---|---|
| `bytes` | FIX byte ownership | 纯 Rust |
| `clap` | CLI | 纯 Rust，关闭默认 feature 后显式最小 feature |
| `quick-xml` | Orchestra XML | 纯 Rust，默认 feature 关闭 |
| `redb` | ACID store | 纯 Rust；build.rs 为 Rust 配置 |
| `rust_decimal` | 数量/价格/名义金额 | 纯 Rust |
| `schemars` | JSON Schema | 纯 Rust |
| `serde`, `serde_json`, `toml` | 配置/协议/存储编码 | 纯 Rust与 proc-macro |
| `sha2`, `hmac` | ID、字典 hash、审计链 | 纯 Rust；未启用 asm |
| `thiserror` | 错误类型 | 纯 Rust proc-macro |
| `time` | FIX UTC timestamp | 纯 Rust，读取系统时钟 |
| `tokio` | runtime/TCP/IPC/timer | Rust + OS ABI；未启用 native TLS/io-uring |

## 审计口径

本文把边界分为三类：

- **通过：纯 Rust 构建**：Cargo 构建不调用 C/C++ 编译器、外部汇编器、CMake、pkg-config 或 vcpkg，也不链接项目自带的 native 库。Rust proc-macro 和纯 Rust `build.rs` 不算 native 编译。
- **通过但有 OS ABI**：Rust 代码经 `libc`、`windows-sys` 或直接 syscall 调用操作系统。标准库、网络、文件和随机数都不可避免地依赖 OS ABI；这不需要 C++ 工具链，但不是“完全不调用平台 ABI”。
- **排除**：构建或链接第三方 C/C++/汇编、使用 C/C++ FFI、依赖 OpenSSL/QuickFIX，或引入 `cxx`、`bindgen`。

如果把“纯 Rust”进一步解释为连 Rust 内联汇编或由 `rustc` 组装的汇编也禁止，则还必须禁用 `getrandom` 的非默认 raw/CPU 指令后端，并排除 `graviola`。本方案采用这一更严格解释来选择密码学依赖。

## 1. rustls 0.23 + tokio-rustls

### 默认 feature 会触发 native 编译

| 项目 | 官方证据 | 审计结论 |
|---|---|---|
| `tokio-rustls 0.26` | [feature 列表](https://docs.rs/crate/tokio-rustls/latest/features)显示默认 feature 包含 `aws_lc_rs`；[Cargo.toml](https://docs.rs/crate/tokio-rustls/latest/source/Cargo.toml)显示其 rustls 依赖自身关闭默认 feature，再由 tokio-rustls feature 重新选择 provider | 直接写 `tokio-rustls = "0.26"` 会启用 AWS-LC 路线，不合格 |
| `rustls 0.23` | [rustls feature 列表](https://docs.rs/crate/rustls/0.23.35/features)与[官方 Cargo.toml](https://docs.rs/crate/rustls/0.23.35/source/Cargo.toml.orig)显示默认包含 `aws_lc_rs` | 直接写 `rustls = "0.23"` 不合格 |
| `aws-lc-rs` | [官方仓库](https://github.com/aws/aws-lc-rs)说明它通过 `aws-lc-sys` / `aws-lc-fips-sys` 对 AWS-LC 做 FFI；[官方构建要求](https://aws.github.io/aws-lc-rs/requirements/linux.html)列出 C/C++ 编译器，FIPS 构建还需要 CMake、Go，部分场景使用 bindgen | 编译 native C/C++；绝对排除 |
| `ring` | [官方 crate manifest](https://docs.rs/crate/ring/latest/source/Cargo.toml.orig)包含 `.c`、`.S` 源码及 `cc` 构建依赖；[build.rs](https://docs.rs/crate/ring/latest/source/build.rs)负责构建 C/汇编 | 不是纯 Rust；不能作为替代生产路线 |

rustls 的 [`CryptoProvider`](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html)允许进程早期显式安装 provider，也允许实现自定义 provider。因此可以同时关闭 rustls 与 tokio-rustls 的默认 feature，但关闭默认 feature **只移除了 provider，并没有自动得到可用于生产的纯 Rust provider**。

### 纯 Rust provider 的成熟度

| Provider | 官方状态 | 决策 |
|---|---|---|
| `rustls-rustcrypto` | [官方文档](https://docs.rs/rustls-rustcrypto/latest/rustls_rustcrypto/)和[官方仓库](https://github.com/RustCrypto/rustls-rustcrypto)称其基于 RustCrypto、纯 Rust，但版本为 `0.0.2-alpha`，明确警告“DO NOT USE THIS IN PRODUCTION”，功能仍不完整且性能较低 | 仅可做实验、互操作测试；生产禁用 |
| `rustls-graviola` | [graviola 官方文档](https://docs.rs/graviola/latest/graviola/)称无需 C 编译器或外部汇编器，但也明确说明包含来自 s2n-bignum 的手写汇编、项目很新、仅支持部分架构及 CPU 特性；[rustls provider 文档](https://docs.rs/rustls-graviola/latest/rustls_graviola/) | 不满足“无汇编”的严格定义；不作为通用生产路线 |

实验环境若要验证 provider 注入，可采用下面的 feature 形状；这不是生产批准清单：

```toml
# 仅实验/互操作测试；rustls-rustcrypto 官方明确禁止生产使用
rustls = { version = "0.23", default-features = false, features = ["std", "tls12"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["tls12"] }
rustls-rustcrypto = "0.0.2-alpha"
```

**生产建议：** 在“无 C、无 C++、无汇编、无 native crypto”的硬约束不变时，FIX live/TLS 功能应保持 fail-closed，不发布生产版本。不能为了上线偷偷恢复 AWS-LC、ring 或 OpenSSL。未来只有在候选纯 Rust provider 达到稳定版、完成安全审计、算法覆盖与性能/互操作验证后，才解除该 gate。

Cargo feature 是全局加和的；任何传递依赖都可能重新启用 provider。每次锁文件变化都必须检查：

```text
cargo tree -e features
cargo tree -i aws-lc-sys
cargo tree -i aws-lc-rs
cargo tree -i ring
cargo tree -i openssl-sys
```

## 2. redb

[`redb` 官方文档](https://docs.rs/redb/latest/redb/)将其定义为纯 Rust、ACID、copy-on-write B-tree 数据库，支持 MVCC、崩溃安全和 savepoint；[官方仓库](https://github.com/cberner/redb)说明其文件格式稳定。其[官方 Cargo.toml](https://github.com/cberner/redb/blob/master/Cargo.toml)没有 C/C++ 构建依赖；仓库虽有 [`build.rs`](https://github.com/cberner/redb/blob/master/build.rs)，但该脚本是纯 Rust 配置脚本，并不调用 native 编译器。

事务边界：

- [`Database::begin_read` / `begin_write`](https://docs.rs/redb/latest/redb/struct.Database.html)提供并发读事务，但同一时刻只有一个写事务。
- [`WriteTransaction`](https://docs.rs/redb/latest/redb/struct.WriteTransaction.html)默认使用 `Durability::Immediate`；`commit()` 返回前执行持久化。官方也提供可选 two-phase commit 与 quick-repair，二者是恢复速度/写放大的显式取舍。
- [`Durability::Immediate`](https://docs.rs/redb/latest/redb/enum.Durability.html)保证 commit 返回后数据已持久化；`Durability::None` 不提供该保证，不得用于 FIX 序号、回放日志或幂等记录。

落地规则：

1. 每个 SessionActor 串行提交写请求，接受 redb 单 writer 约束。
2. `next_sender_seq_num`、`next_target_seq_num`、出站原始 FIX bytes、发送状态、幂等键和审计元数据必须在同一个 redb 写事务提交。
3. 外部文本审计文件不能与 redb 原子提交；可信恢复依据应是 redb 内的 append-only 逻辑记录，文件仅作派生导出。
4. 是否开启 two-phase commit/quick-repair 必须通过断电恢复和写放大基准后决定，不能仅凭 API 存在就启用。

## 3. 其余候选依赖

“通过”表示在表中所述 feature 下没有发现第三方 C/C++ 编译；最终仍以锁定后的完整依赖图为准。

| Crate | 边界与建议 | 官方证据 |
|---|---|---|
| `tokio` | 通过但有 OS ABI。默认无 feature；显式启用 `rt-multi-thread,macros,net,io-util,sync,time`，按需加 `signal`，不要使用 `full` 或可选 `io-uring`。`net` 在 Unix 通过 `libc`/`mio`，Windows 通过 `windows-sys`，不编译 C++ | [features](https://docs.rs/crate/tokio/latest/features)、[crate docs](https://docs.rs/tokio/latest/tokio/) |
| `bytes` | 通过。Rust 容器与引用计数实现；默认仅 `std`，可选 serde/portable-atomic | [Cargo.toml](https://docs.rs/crate/bytes/latest/source/Cargo.toml.orig) |
| `clap` | 通过。Rust 代码与 proc-macro；可关闭默认 feature 后只启用需要的 `derive,std,help,usage,error-context` | [Cargo.toml](https://docs.rs/crate/clap/latest/source/Cargo.toml.orig) |
| `serde` / `serde_derive` | 通过。derive 使用 `proc-macro2`、`quote`、`syn`，均为 Rust 编译期代码 | [serde Cargo.toml](https://docs.rs/crate/serde/latest/source/Cargo.toml)、[serde_derive Cargo.toml](https://docs.rs/crate/serde_derive/latest/source/Cargo.toml.orig) |
| `serde_json` | 通过。运行时依赖为 Rust crates；不需要 native toolchain | [Cargo.toml](https://docs.rs/crate/serde_json/latest/source/Cargo.toml) |
| `toml` | 通过。官方描述为 native Rust encoder/decoder，这里的 native 指 Rust 原生实现，不是 native library | [Cargo.toml](https://docs.rs/crate/toml/latest/source/Cargo.toml.orig)、[docs](https://docs.rs/toml/latest/toml/) |
| `thiserror` | 通过。derive proc-macro 由 `syn/quote/proc-macro2` 实现 | [docs](https://docs.rs/thiserror/latest/thiserror/)、[thiserror-impl Cargo.toml](https://docs.rs/crate/thiserror-impl/latest/source/Cargo.toml.orig) |
| `tracing` | 通过。核心与宏均为 Rust；具体输出 sink 需单独审计，避免后来接入 native exporter | [tracing source](https://docs.rs/crate/tracing/latest/source/)、[tracing-core Cargo.toml](https://docs.rs/crate/tracing-core/latest/source/Cargo.toml.orig) |
| `quick-xml` | 通过，推荐作为 FIX XML/Orchestra 流式解析器。默认 feature 为空；只按需启用 `serialize`，不需要异步 XML 时不要启用 `async-tokio` | [docs](https://docs.rs/quick-xml/latest/quick_xml/)、[Cargo.toml](https://docs.rs/crate/quick-xml/latest/source/Cargo.toml) |
| `roxmltree` | 通过。只读 DOM，依赖极少；官方说明大约需要 XML 文件大小 6–8 倍内存，适合较小字典，不作为大型 Orchestra 文件默认选择 | [docs/crate page](https://docs.rs/crate/roxmltree/latest)、[Cargo.toml](https://docs.rs/crate/roxmltree/latest/source/Cargo.toml.orig) |
| `sha2` | 通过，但必须禁用旧版可选 `asm` feature。当前 manifest 标注纯 Rust；若停留在 0.10 系列，不得开启会拉入 `sha2-asm`/`cc` 的 `asm` | [当前 Cargo.toml](https://docs.rs/crate/sha2/latest/source/Cargo.toml.orig)、[0.10 features](https://docs.rs/crate/sha2/0.10.6/features)、[sha2-asm](https://docs.rs/crate/sha2-asm/latest) |
| `hmac` | 通过。泛型纯 Rust HMAC 实现，native 风险来自所选 digest 的 feature；与禁用 asm 的 `sha2` 配合 | [source](https://docs.rs/crate/hmac/latest/source/)、[docs](https://docs.rs/hmac/latest/hmac/) |
| `zeroize` | 通过。官方明确为 portable pure Rust、无 FFI/assembly；用 volatile write 与内存栅栏降低被优化掉的风险 | [docs](https://docs.rs/zeroize/latest/zeroize/)、[Cargo.toml](https://docs.rs/crate/zeroize/latest/source/Cargo.toml.orig) |
| `secrecy` | 通过。基于 `zeroize`，限制 Debug/Display/Serialize 暴露；不提供 `mlock`/`mprotect`，因此不能声称密钥不会进入 pagefile/core dump | [docs](https://docs.rs/secrecy/latest/secrecy/) |
| `governor` | 通过但有 OS/时钟边界。默认启用 `dashmap,jitter,quanta` 等 Rust crates；若只做每 session 限流，优先 `default-features = false, features = ["std"]` 并在实装时验证 API，或直接用 Tokio time 实现 actor 内 token bucket | [features](https://docs.rs/crate/governor/latest/features)、[Cargo.toml](https://docs.rs/crate/governor/latest/source/Cargo.toml.orig) |
| `uuid` | 通过。`v4`/`v7` 会启用 `getrandom`，仍不编译 C/C++；只启用 `std,serde` 和实际使用的版本 feature，避免 wasm `js` feature | [features](https://docs.rs/crate/uuid/latest/features)、[Cargo.toml](https://docs.rs/crate/uuid/latest/source/Cargo.toml.orig) |
| `rand` | 通过但有 OS 熵源。crate 与算法实现为 Rust，系统随机数路径委托 `getrandom` | [docs](https://docs.rs/rand/latest/rand/)、[Cargo.toml](https://docs.rs/crate/rand/latest/source/Cargo.toml) |
| `getrandom` | 通过但有 OS ABI。默认在 Windows/Unix 调用系统熵源，不编译 C/C++；不要选择 `linux_raw`、`rdrand`、`rndr` 等显式 raw/CPU 后端，以免引入更严格口径下的汇编/CPU 指令边界 | [官方平台/后端文档](https://docs.rs/getrandom/latest/getrandom/) |
| `proptest` | 通过。Rust property testing；默认 `fork/timeout` 会加入进程与临时文件依赖但不编译 C++。Windows/最小依赖建议先用 `default-features = false, features = ["std"]`，再按测试需求加 feature | [features](https://docs.rs/crate/proptest/latest/features)、[docs](https://docs.rs/proptest/latest/proptest/) |
| `cargo-fuzz` / `libfuzzer-sys` | **排除。** Rust fuzz 工具外层最终使用 LLVM libFuzzer；`libfuzzer-sys/build.rs` 明确以 `cpp(true)`、C++17 编译 `.cpp` | [rust-fuzz/libfuzzer 官方仓库](https://github.com/rust-fuzz/libfuzzer)、[libfuzzer-sys build.rs](https://docs.rs/crate/libfuzzer-sys/latest/source/build.rs) |

严格约束下，fuzz 替代方案为：`proptest` 随机/缩减测试、固定 seed、已发现样本永久加入 corpus 回归、针对 TagValue frame/length/checksum/group 的纯 Rust bounded mutator。覆盖引导 fuzz 暂列“不支持”，直到找到并审计通过不含 C/C++ 的 runner。

## 4. Windows named pipe / Unix socket

Tokio 的 [`tokio::net`](https://docs.rs/tokio/latest/tokio/net/)官方模块直接列出 Windows named pipes 和 Unix domain sockets：

- Windows：[`tokio::net::windows::named_pipe`](https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/)提供 client/server；启用 Tokio `net` feature 即可。底层使用 `windows-sys` 声明 Win32 API，不需要 C++。
- Unix：[`tokio::net::UnixStream`](https://docs.rs/tokio/latest/tokio/net/struct.UnixStream.html) / `UnixListener`，也可用标准库 [`std::os::unix::net`](https://doc.rust-lang.org/std/os/unix/net/)。底层是 Unix socket syscall/libc ABI，不编译 C++。

建议以 `cfg(windows)` 和 `cfg(unix)` 隔离 transport，实现共同的 length-prefixed JSON frame。协议层必须限制 frame 大小、设置读写超时；Windows 配置 pipe ACL，Unix 配置 socket 目录权限、owner/group 和文件 mode。不能把 IPC 本地可达误当成已认证。

## 5. 绝对排除项

| 排除项 | 原因与官方证据 |
|---|---|
| QuickFIX | [官方仓库](https://github.com/quickfix/quickfix)明确是 C++ FIX engine，并要求 C++17；不得作为实现、备选或参考 runtime |
| `quickfix-rs` / crates.io `quickfix` / `quickfix-ffi` | [官方 crate 文档](https://docs.rs/quickfix/latest/quickfix/)明确是 QuickFIX 的非官方 Rust binding，构建要求 CMake 与 C++17，并持有 foreign C++ object |
| `cxx` / `cxx-build` | [cxx 官方文档](https://cxx.rs/)定义其用途为 Rust/C++ 安全桥接；与边界直接冲突 |
| `bindgen` | [rust-bindgen 官方文档](https://rust-lang.github.io/rust-bindgen/)用于生成 C/C++ FFI binding；[构建要求](https://rust-lang.github.io/rust-bindgen/requirements.html)包含 libclang |
| `openssl` / `openssl-sys` / `native-tls` | [`openssl-sys`](https://docs.rs/crate/openssl-sys/latest)明确是 OpenSSL FFI，manifest 含 `cc/pkg-config/vcpkg` 与可选 bindgen；[`openssl` 构建文档](https://docs.rs/openssl/latest/openssl/#building)说明 vendored 模式需要 C 编译器；[`native-tls`](https://docs.rs/native-tls/latest/native_tls/#how-is-this-implemented)在非 Windows/macOS 平台使用 OpenSSL |
| `aws-lc-rs` / `aws-lc-sys` / `ring` | 都会跨入 C/汇编/native crypto；只作为本审计解释 rustls 默认行为的被拒项，不是可选路线 |
| `cargo-fuzz` / `libfuzzer-sys` | 构建 C++ libFuzzer；与无 C++ 约束直接冲突 |

建议在 CI 对解析后的依赖图设置拒绝清单：

```text
quickfix quickfix-ffi cxx cxx-build bindgen
openssl openssl-sys native-tls
aws-lc-rs aws-lc-sys aws-lc-fips-sys ring
libfuzzer-sys
```

同时审查 `cc`、`cmake`、`pkg-config`、`vcpkg` 是否出现在 build-dependencies。它们出现不等于一定在当前 target 执行，但在本项目的严格策略下必须人工解释并默认拒绝。`libc` 与 `windows-sys` 是 OS ABI 声明 crate，不应被误报成 C/C++ 源码编译。

## 6. 可接受清单与上线 gate

当前实际使用的核心依赖：

- runtime/bytes：`tokio`、`bytes`
- CLI/config/JSON：`clap`、`serde`、`serde_json`、`toml`、`thiserror`
- XML：`quick-xml`
- storage：`redb`
- application crypto：禁用 asm 的 `sha2` + `hmac`
- IDs：`sha2` 的确定性 domain-separated hash；不依赖随机 ID
- rate limit：项目内 1 秒滑动窗口
- testing：项目内固定 seed 属性循环和 `fix-fuzz` bounded mutator
- IPC：Tokio named pipe / Unix domain socket

必须保持关闭：

- 生产 TLS/live 交易：在没有成熟且审计通过的纯 Rust provider 前 fail-closed
- coverage-guided `cargo-fuzz`：因 C++ libFuzzer 被禁
- 所有 QuickFIX、OpenSSL、C++ FFI 路线

## 7. 已验证与后续复核

当前已固定 `rust-toolchain.toml` 与 `Cargo.lock`，并在 Windows MSVC 上执行 workspace all-target check/test、clippy（最终提交前执行）、本地 named pipe、TCP 重连和 redb reopen；进程级 `fix-mock` + `fixd` + `fixctl` 仅作为本次开发的人工 smoke 执行，尚未提交自动 child-process 测试。锁文件 denylist 与 build.rs 扫描结果见上文。

仍需：

1. 在 Linux GNU、Linux musl（若支持）和 macOS 分别验证构建、Unix socket mode/ownership 与完整依赖图。
2. 每次锁文件变化重新执行 metadata、feature、denylist 和 build.rs 审计。
3. 任何 TLS provider 变更都必须单独审计，不能依赖“rustls”名称推断纯 Rust。
4. 对 redb 执行真正断电/文件损坏测试，并完成备份恢复演练。
5. 对真实 venue 执行 certification；当前 mock 结果不代表真实对手方兼容。
