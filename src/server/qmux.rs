//! QMux v1 —— **协议本体已实现**（`draft-ietf-quic-qmux-02`），外加一份真在生效的流预算。
//!
//! # 实现范围（对着草案逐条）
//!
//! | 草案条款 | 实现位置 |
//! |---|---|
//! | §3.2 记录（`Size(i) + Frames`，自定界、帧不跨记录、末尾对不齐即错） | [`proto::RecordReader`] / [`proto::encode_record`] |
//! | §4 允许/禁止的帧集合（沿用 QUIC v1 帧格式） | [`proto::FrameKind::from_type`] / [`proto::parse_frames`] |
//! | §4.1 STREAM 必须按序（同流 offset 连续） | [`conn`] 的 `handle_frame` |
//! | §4.2 首个帧必须是 `QX_TRANSPORT_PARAMETERS`（wire 上是 `\xffQMX\r\n\r\n`） | [`conn::serve`] / [`proto::QX_TP_TYPE`] |
//! | §4.3 `QX_PING` 请求/响应与序号单调性 | [`conn`] 的 `handle_frame` |
//! | §5 传输参数（允许 7 个 QUIC 参数 + `max_record_size`；被禁的报错、未知的忽略） | [`proto::TransportParams::decode`] |
//! | §5.2 `max_record_size`（默认 16382，不得小于默认；记录不得超限） | [`proto::DEFAULT_MAX_RECORD_SIZE`] / [`conn::Conn::push_frames`] |
//! | §6 读侧永不因应用不读而阻塞（缓冲上限 = 声明的流控额度，消费即回补） | [`conn::QmuxStream`] |
//! | §7.1 空闲超时（收满/发完一条记录都重置） | [`conn::serve`] |
//! | §7.2/§7.3 CONNECTION_CLOSE 的收发与优雅关闭 | [`conn::serve`] |
//! | §9.1 DATAGRAM 扩展（按 §6 允许丢弃） | [`conn`] 的 `handle_frame` |
//! | §9.2 RESET_STREAM_AT 扩展（按 RESET_STREAM 语义） | [`conn`] 的 `handle_frame` |
//!
//! 单测见 [`proto::tests`]（编解码与边界）与 [`conn::tests`]（用内存 duplex 跑的
//! 一致性用例：握手、回显、首个帧校验、禁止帧、偏移连续性、PING 语义、被禁参数）。
//!
//! # 怎么用
//!
//! QMux 自己**没有 ALPN**（§8.1），由上层协议指定。本实现服务 **HTTP/1.1 over QMux**，
//! ALPN 标识 [`conn::QMUX_ALPN`] = `h1-02qx`（`02` = 草案版本）。启用方式：监听器加
//! `qmux = true`，且 `http_versions` 里含 `h1`（HTTP/1.1 跑在 QMux 流上）。
//! 客户端在 ALPN 里只提供 `h1-02qx` 即可走 QMux；同时提供 `h2`/`http/1.1` 的老客户端
//! 行为不变（服务端偏好 h2 > h1 > qmux，见 `tls::boring_path::apply_alpn`）。
//!
//! # 与「流预算」的关系
//!
//! [`QmuxBudget`] 是另一件事：h3（QUIC）**每连接每请求**的并发流闸门（闸门上限刻意与
//! quinn 默认对齐，真正拦的是「漏释放导致的计数泄漏」）。它与本文件的协议实现相互独立：
//! 协议实现有自己的流状态机与流控（[`conn`]），预算只管并发计数。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub mod conn;
pub mod proto;

/// 用 **HTTP/1.1** 服务一条 QMux 连接：每条 QMux 逻辑流跑一个独立的 h1 会话。
///
/// 这样 QMux 复用的就是现成的 HTTP/1.1 实现（报文解析、路由、应用引擎、上传……），
/// 与 h1/h2/h3 共享同一套分发与安全闸门 —— 不会出现「新协议上少一道检查」的漂移。
pub async fn serve_h1<IO>(
    io: IO,
    live: Arc<crate::server::live_config::LiveConfig>,
    lc: crate::config::ListenerConfig,
    peer: std::net::SocketAddr,
) -> anyhow::Result<()>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    conn::serve(io, move |stream| {
        let live = Arc::clone(&live);
        let lc = lc.clone();
        async move {
            // **必须用 half_close 版本**：QMux 客户端会把 FIN 与请求数据放在同一条记录里，
            // hyper 默认（allow_half_close=false）会把「响应派发前的 EOF」判成
            // `IncompleteMessage`，现象是「连上了但什么都不发生」。详见 h1::serve_tls_half_close。
            if let Err(e) = crate::server::h1::serve_tls_half_close(stream, live, lc, peer).await {
                // warn 而不是 debug：QMux 流上的 h1 会话失败是「协议面不可用」级别的
                // 事件，静默掉就等于什么都看不到，无从排障。
                log::warn!("qmux: h1 会话结束 peer={peer}: {e:#}");
            }
        }
    })
    .await
}

#[cfg(test)]
mod compose_tests {
    use super::*;
    use crate::server::qmux::proto::{self, put_varint, Frame, RecordReader};

    /// 端到端：QMux 上跑一个**真实 HTTP/1.1 请求**，必须拿到 HTTP 响应。
    ///
    /// 这条测试专门覆盖「QMux 流 ↔ hyper」的接缝（协议层已有 19 条测试、ALPN 与
    /// 明文魔数也实测过，问题只可能出在这一段）。
    #[tokio::test]
    async fn h1_over_qmux_end_to_end() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut lc = crate::config::ListenerConfig::default();
        lc.root = std::env::temp_dir();
        lc.http_versions = vec!["h1".to_string()];
        lc.qmux = true;
        // 注意：**不设 lc.ssl** —— 这里只要 HTTP/1.1 能正常处理，避免 301 跳转干扰
        let live = std::sync::Arc::new(crate::server::live_config::LiveConfig::new(
            crate::config::Config::default(),
            std::path::PathBuf::from("/tmp/qmux-test.toml"),
        ));
        let srv = tokio::spawn(serve_h1(b, live, lc, "127.0.0.1:1".parse().unwrap()));

        let mut io = a;
        let mut rd = RecordReader::new();
        // 1) 读服务端传输参数（§4.2：它不等我们）
        let mut buf = [0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await.unwrap();
        eprintln!("[test] 读到服务端首记录 {n} 字节");
        rd.push(&buf[..n]);
        let body = rd.next_record().unwrap().expect("服务端参数记录");
        let frames = proto::parse_frames(&body).unwrap();
        eprintln!("[test] 服务端首记录帧: {frames:?}");
        assert!(matches!(
            frames.first(),
            Some(Frame::QxTransportParameters(_))
        ));

        // 2) 发我方传输参数 + 一个带 FIN 的 STREAM（HTTP/1.1 GET）
        //
        // 注意编码：传输参数的值是「变长整数，前面再带自己的长度」。最初这里把长度硬写成 1
        // 而值实际占 4 字节 —— 服务端解析立刻失步并回 `varint: 截断`（error_code=7），
        // 现象与「QMux 用不了」一模一样。长度必须**算出来**。
        fn tp_item(id: u64, val: u64) -> Vec<u8> {
            let mut out = Vec::new();
            put_varint(&mut out, id);
            let mut tmp = Vec::new();
            put_varint(&mut tmp, val);
            put_varint(&mut out, tmp.len() as u64);
            out.extend_from_slice(&tmp);
            out
        }
        let mut tp = tp_item(0x05, 1 << 20); // initial_max_stream_data_bidi_local
        tp.extend(tp_item(0x04, 1 << 20)); // initial_max_data
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec();
        let mut out = Vec::new();
        proto::encode_record(
            &[
                Frame::QxTransportParameters(tp),
                Frame::Stream {
                    stream_id: 0,
                    offset: 0,
                    fin: true,
                    data: req,
                },
            ],
            &mut out,
        );
        tokio::io::AsyncWriteExt::write_all(&mut io, &out).await.unwrap();
        eprintln!("[test] 已发请求（{} 字节记录）", out.len());

        // 3) 读响应：拼 STREAM 载荷直到 FIN
        let mut got = Vec::new();
        let deadline = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                loop {
                    if let Some(body) = rd.next_record().unwrap() {
                        for f in proto::parse_frames(&body).unwrap() {
                            match f {
                                Frame::Stream { offset, data, fin, .. } => {
                                    assert_eq!(offset, got.len() as u64, "偏移必须连续");
                                    got.extend_from_slice(&data);
                                    if fin {
                                        return;
                                    }
                                }
                                other => eprintln!("[test] 其他帧: {other:?}"),
                            }
                        }
                    } else {
                        break;
                    }
                }
                let n = tokio::io::AsyncReadExt::read(&mut io, &mut buf)
                    .await
                    .unwrap();
                if n == 0 {
                    eprintln!("[test] 对端关闭（EOF）");
                    return;
                }
                rd.push(&buf[..n]);
            }
        })
        .await;
        eprintln!(
            "[test] 结果 deadline={:?} 收到 {} 字节: {}",
            deadline.is_err(),
            got.len(),
            String::from_utf8_lossy(&got[..got.len().min(200)])
        );
        assert!(
            got.starts_with(b"HTTP/1.1 "),
            "期望 HTTP 响应，实际 {:?}",
            String::from_utf8_lossy(&got[..got.len().min(200)])
        );
        srv.abort();
    }
}

/// 单连接默认并发请求流上限。
///
/// 与 quinn 默认 `max_concurrent_bidi_streams`（100，见
/// `quinn-proto-0.11.17/src/config/transport.rs`）对齐：闸门不比传输层更严，
/// 正常流量不会因为它被拒。
pub const DEFAULT_MAX_ACTIVE: u64 = 100;

/// 每连接一份的并发流预算。
///
/// 只有 [`QMUX_BUDGET`] 这一个实例没有 parent；其余（`per_connection` 出来的）
/// 都挂到它下面做汇总。
pub struct QmuxBudget {
    active: AtomicU64,
    total_opened: AtomicU64,
    total_closed: AtomicU64,
    rejected: AtomicU64,
    max_active: AtomicU64,
    /// 汇总目标（进程级）。子预算的增减同时计入它。
    parent: Option<&'static QmuxBudget>,
}

impl Default for QmuxBudget {
    fn default() -> Self {
        Self {
            active: AtomicU64::new(0),
            total_opened: AtomicU64::new(0),
            total_closed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            max_active: AtomicU64::new(DEFAULT_MAX_ACTIVE),
            parent: None,
        }
    }
}

impl QmuxBudget {
    /// 新建一条连接自己的预算。
    ///
    /// `h3.rs::handle_incoming` 在每条 QUIC 连接上调用一次，并把结果传给
    /// 该连接的所有请求任务。上限继承 [`QMUX_BUDGET`]，便于只在一个地方调。
    pub fn per_connection() -> Arc<Self> {
        let max = QMUX_BUDGET.max_active.load(Ordering::Acquire);
        Arc::new(Self {
            max_active: AtomicU64::new(max),
            parent: Some(&QMUX_BUDGET),
            ..Self::default()
        })
    }

    /// 占用一个并发名额；成功返回 RAII 守卫（Drop 自动释放）。
    ///
    /// 超限时返回 [`QmuxReject`]，调用方应回 503 —— 而不是把这次请求算成
    /// 「已服务」。旧桩代码的问题正是：计数器存在，但没有任何人读它。
    pub fn acquire(self: &Arc<Self>) -> Result<QmuxGuard, QmuxReject> {
        let cur = self.active.fetch_add(1, Ordering::AcqRel);
        let max = self.max_active.load(Ordering::Acquire);
        if cur + 1 > max {
            // 自己加的那一份要退回去，否则拒绝一次就永久少一个名额。
            self.active.fetch_sub(1, Ordering::AcqRel);
            self.rejected.fetch_add(1, Ordering::AcqRel);
            return Err(QmuxReject {
                active: cur,
                max,
            });
        }
        self.total_opened.fetch_add(1, Ordering::AcqRel);
        if let Some(p) = self.parent {
            p.active.fetch_add(1, Ordering::AcqRel);
            p.total_opened.fetch_add(1, Ordering::AcqRel);
        }
        Ok(QmuxGuard {
            budget: Arc::clone(self),
            released: false,
        })
    }

    /// 释放一个名额（由守卫保证只调用一次）。
    fn release(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.total_closed.fetch_add(1, Ordering::AcqRel);
        if let Some(p) = self.parent {
            p.active.fetch_sub(1, Ordering::AcqRel);
            p.total_closed.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// 一行汇总，给日志用（字段少，不单独做 Display）。
    pub fn stats_line(&self) -> String {
        format!(
            "active={} opened={} closed={} rejected={} max={}",
            self.active.load(Ordering::Acquire),
            self.total_opened.load(Ordering::Acquire),
            self.total_closed.load(Ordering::Acquire),
            self.rejected.load(Ordering::Acquire),
            self.max_active.load(Ordering::Acquire),
        )
    }
}

/// 名额守卫：Drop 时释放。
///
/// 这一层是刻意的——`h3.rs` 里从取名额到请求结束之间有很多 `return Ok(())`
/// 的早退分支（客户端复位、超时、cancel 都是常态），靠手写配对释放必然漏账。
pub struct QmuxGuard {
    budget: Arc<QmuxBudget>,
    released: bool,
}

impl QmuxGuard {
    /// 释放名额。幂等：之后再被 Drop 也不会重复扣减。
    fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.released {
            self.released = true;
            self.budget.release();
        }
    }
}

impl Drop for QmuxGuard {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// 被预算拒绝。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QmuxReject {
    /// 拒绝时的在途并发数。
    pub active: u64,
    /// 当前上限。
    pub max: u64,
}

impl std::fmt::Display for QmuxReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qmux over budget: active={} max={}", self.active, self.max)
    }
}

impl std::error::Error for QmuxReject {}

/// 进程级汇总预算：**不做闸门**，只做跨连接的计数汇总，并为新连接提供默认上限。
///
/// 为什么不在这里设全局闸门：全局上限会在高并发下误伤正常流量
/// （quinn 每连接默认就允许 100 条并发双向流，两条连接的正常业务加起来就能到 200），
/// 而这道闸门本来要防的是「计数漏释放」，那是每连接的问题。
pub static QMUX_BUDGET: once_cell::sync::Lazy<QmuxBudget> =
    once_cell::sync::Lazy::new(QmuxBudget::default);

/// 开流登记：检查该连接的并发上限并占用一个名额。
///
/// 与 `h3.rs` 原来的调用形状一致（处理请求前开、处理后关），
/// 但返回的是 RAII 守卫，早退 / panic 都会释放。
pub fn stream_opened(budget: &Arc<QmuxBudget>) -> Result<QmuxGuard, QmuxReject> {
    budget.acquire()
}

/// 关流登记：显式释放名额。
///
/// 守卫的 `Drop` 也会释放，两者幂等，所以「显式关」和「早退漏关」都不会算错。
pub fn stream_closed(guard: QmuxGuard) {
    guard.release();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_rejects_and_releases() {
        let b = Arc::new(QmuxBudget::default());
        assert_eq!(b.max_active.load(Ordering::Acquire), DEFAULT_MAX_ACTIVE);
        let g1 = b.acquire().expect("first");
        // 拿到守卫就占了一个名额。
        assert!(b.stats_line().contains("active=1"));
        drop(g1);
        assert!(b.stats_line().contains("active=0"));
        assert!(b.stats_line().contains("closed=1"));
    }

    #[test]
    fn budget_does_not_overcount_on_reject() {
        let b = Arc::new(QmuxBudget {
            max_active: AtomicU64::new(1),
            ..QmuxBudget::default()
        });
        let g = b.acquire().expect("first fits");
        assert!(b.acquire().is_err(), "second must be rejected");
        assert!(b.stats_line().contains("active=1"));
        assert!(b.stats_line().contains("rejected=1"));
        // 被拒之后名额没有被吃掉：释放后还能再拿一个。
        drop(g);
        assert!(b.acquire().is_ok());
    }

    #[test]
    fn explicit_close_is_idempotent() {
        let b = Arc::new(QmuxBudget::default());
        let g = b.acquire().expect("first");
        stream_closed(g);
        assert!(b.stats_line().contains("active=0"));
        assert!(b.stats_line().contains("closed=1"));
    }
}
