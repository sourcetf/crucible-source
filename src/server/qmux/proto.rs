//! QMux v1 的**线格式编解码**（draft-ietf-quic-qmux-02，即本仓库一直缺的那份协议的正文实现）。
//!
//! 本模块是纯函数式的：字节进、字节出，不碰 IO、不碰异步，便于单测穷举边界。
//! 连接状态机在 [`super::conn`]。
//!
//! # 与草案的对应关系（逐条，便于复核）
//!
//! * §3.2 记录：`QMux Record { Size(i), Frames(..) }` —— `Size` 是变长整数，
//!   只覆盖 `Frames` 的长度；帧**不得跨记录**；记录末尾对不齐帧边界 → `FRAME_ENCODING_ERROR`。
//! * §4 帧：沿用 QUIC v1 的帧格式与语义，只允许 PADDING / RESET_STREAM / STOP_SENDING /
//!   STREAM / MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS / DATA_BLOCKED / STREAM_DATA_BLOCKED /
//!   STREAMS_BLOCKED / CONNECTION_CLOSE；其余（PING/ACK/CRYPTO/NEW_TOKEN/…/HANDSHAKE_DONE）
//!   收到即 `FRAME_ENCODING_ERROR`。
//! * §4.1 STREAM 帧必须**按序**：同一 Stream ID 的 payload 必须紧跟上一帧（Offset 连续），
//!   否则 `PROTOCOL_VIOLATION`（这条让实现不必重组，直接把 payload 交给应用）。
//! * §4.2 `QX_TRANSPORT_PARAMETERS`（type `0x3f5153300d0a0d0a`，即 wire 上的 `\xffQMX\r\n\r\n`）
//!   必须是**第一个**帧，否则 `PROTOCOL_VIOLATION`。
//! * §4.3 `QX_PING`（`0x348c67529ef8c7bd` 请求 / `0x348c67529ef8c7be` 响应）：
//!   请求的序号必须严格递增，响应原样回显。
//! * §5 传输参数：允许 QUIC 的 7 个（idle/流控/流数上限）+ 本协议定义的
//!   `max_record_size`(`0x0571c59429cd0845`)；收到 QUIC 里**被禁**的那批 → `TRANSPORT_PARAMETER_ERROR`；
//!   未知参数按 §5.1 忽略。
//! * §9.1 DATAGRAM（RFC 9221）与 §9.2 RESET_STREAM_AT（draft-ietf-quic-reliable-stream-reset）
//!   作为扩展：编码与语义不变，靠传输参数协商。

use std::collections::BTreeMap;

/// QMux（= QUIC v1）的传输错误码，取值与 QUIC v1 一致（RFC 9000 §20.1）。
pub mod err {
    pub const NO_ERROR: u64 = 0x00;
    pub const INTERNAL_ERROR: u64 = 0x01;
    pub const FLOW_CONTROL_ERROR: u64 = 0x03;
    pub const STREAM_LIMIT_ERROR: u64 = 0x04;
    pub const STREAM_STATE_ERROR: u64 = 0x05;
    pub const FINAL_SIZE_ERROR: u64 = 0x06;
    pub const FRAME_ENCODING_ERROR: u64 = 0x07;
    pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
    pub const PROTOCOL_VIOLATION: u64 = 0x0a;
}

/// 协议级错误：一律带上「关闭时要发的错误码」，调用方直接拿去发 CONNECTION_CLOSE。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError {
    pub code: u64,
    pub reason: String,
}

impl ProtoError {
    pub fn new(code: u64, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
    pub fn frame(reason: impl Into<String>) -> Self {
        Self::new(err::FRAME_ENCODING_ERROR, reason)
    }
    pub fn protocol(reason: impl Into<String>) -> Self {
        Self::new(err::PROTOCOL_VIOLATION, reason)
    }
    pub fn params(reason: impl Into<String>) -> Self {
        Self::new(err::TRANSPORT_PARAMETER_ERROR, reason)
    }
    pub fn flow(reason: impl Into<String>) -> Self {
        Self::new(err::FLOW_CONTROL_ERROR, reason)
    }
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qmux error 0x{:x}: {}", self.code, self.reason)
    }
}

impl std::error::Error for ProtoError {}

/// 变长整数（RFC 9000 §16）：1/2/4/8 字节，前两位表示长度。
pub fn varint_len(v: u64) -> usize {
    if v < 64 {
        1
    } else if v < 16_384 {
        2
    } else if v < 1_073_741_824 {
        4
    } else {
        8
    }
}

pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    // RFC 9000 §16：8 字节形态的高两位固定为 `11`，只剩 62 位有效载荷 —— 即最大
    // 可编码值是 2^62-1。传进来 ≥ 2^62 的值时 `v | 0xc000_...` 会与这两个前缀位冲突，
    // **静默**编出一个错的值（如 2^62 编成 0），对端解析出来就是另一个数。
    // 当前所有调用点的值都有界（内部流控窗口/发送偏移/记录长/流 id），无外部可驱动
    // 路径（见 reports/h2h3c-wave4.md F3）；这里加 debug 断言，让将来误用**当场暴露**。
    debug_assert!(
        v < (1u64 << 62),
        "put_varint: {v} 超出变长整数 62 位上限（RFC 9000 §16）"
    );
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// 读一个变长整数；越界/非法编码 → `FRAME_ENCODING_ERROR`。
pub fn get_varint(buf: &[u8], pos: &mut usize) -> Result<u64, ProtoError> {
    let first = *buf
        .get(*pos)
        .ok_or_else(|| ProtoError::frame("varint: 缓冲区结束"))?;
    let len = 1usize << (first >> 6);
    let end = pos
        .checked_add(len)
        .filter(|e| *e <= buf.len())
        .ok_or_else(|| ProtoError::frame("varint: 截断"))?;
    let mut v = (first & 0x3f) as u64;
    for b in &buf[*pos + 1..end] {
        v = (v << 8) | *b as u64;
    }
    *pos = end;
    Ok(v)
}

/// 帧类型。注意：这里的**取值**就是 QUIC v1 的取值（草案 §4 要求格式一致），
/// 另外加上 QMux 自己的两个、以及两个扩展帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Padding,
    ResetStream,
    StopSending,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreamsBidi,
    MaxStreamsUni,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlockedBidi,
    StreamsBlockedUni,
    ConnectionCloseTransport,
    ConnectionCloseApp,
    QxTransportParameters,
    QxPingRequest,
    QxPingResponse,
    Datagram,     // RFC 9221（0x30 带长度 / 0x31 不带）
    ResetStreamAt, // draft-ietf-quic-reliable-stream-reset
}

/// `QX_TRANSPORT_PARAMETERS` 的帧类型（**逻辑值**）。varint 编码后的 wire 形式是
/// `\xffQMX\r\n\r\n` —— 草案 §4.2 特意选它当协议魔数（用来区分 QMux / HTTP/1.1 / HTTP/2），
/// §10.1 又允许非 TLS 场景直接用它识别 QMux。
///
/// ⚠️ 与草案正文的一处**不一致**（-01 与 -02 都有，已核对两版）：正文把类型写成
/// `0x3f5153300d0a0d0a`，而同一句又说 wire 是 `"\xffQMX\r\n\r\n"`。二者不可能同时成立：
/// `0x3f515330…` 的 varint 编码是 `\xffQS0\r\n\r\n`（"QS0" ≠ "QMX"）。
/// 本实现**以 ASCII 形式为准**（发送 `\xffQMX…`，即逻辑值 `0x3f514d58…`），理由：
/// 1) 它是正文明确标注的「on wire」形式，也是 §10.1 用来**识别协议**的那八个字节；
/// 2) 该魔数的全部意义就在于能一眼认出 QMux（`QMX`），"QS0" 讲不通；
/// 3) 十六进制那串更像是把 `0x3f514d58…` 手抄成了 `0x3f515330…`（"4d58"→"5330"）。
///
/// 互操作上的保险：**接收时两种都认**（见 [`QX_TP_TYPE_DOC_HEX`]），所以即便对端按正文的
/// 十六进制实现，也能正常对接。
pub const QX_TP_TYPE: u64 = 0x3f51_4d58_0d0a_0d0a;
/// 草案正文十六进制写法对应的逻辑值（wire 是 `\xffQS0\r\n\r\n`）。
/// 只在**接收**时兼容它，发送一律用 [`QX_TP_TYPE`]。
pub const QX_TP_TYPE_DOC_HEX: u64 = 0x3f51_5330_0d0a_0d0a;
/// `QX_TRANSPORT_PARAMETERS` 在 wire 上的 8 个字节（§4.2 的魔数，§10.1 的协议识别字节）。
pub const QX_TP_TYPE_WIRE: &[u8] = b"\xffQMX\r\n\r\n";

/// 明文传输上「这一串字节是不是 QMux」的判定（草案 §10.1）。
///
/// §10.1 说用「first 8 bytes exchanged on the transport (i.e., the type field of the
/// QX_TRANSPORT_PARAMETERS frame in its encoded form)」识别 —— 但 §3.2 规定字节流上
/// **每条记录都以 Size 变长整数开头**，所以真实首字节是 Size，魔数在其后。
/// 因此这里两种都认：魔数在偏移 0（对端若按 §10.1 的字面意思直接发帧类型），
/// 以及魔数紧跟在**记录 Size** 之后（按 §3.2 的规范编码，也就是本实现的发送方式）。
pub fn plaintext_is_qmux(buf: &[u8]) -> bool {
    if buf.len() >= 8 && &buf[..8] == QX_TP_TYPE_WIRE {
        return true;
    }
    let mut pos = 0usize;
    if get_varint(buf, &mut pos).is_ok() && buf.len() >= pos + 8 {
        return &buf[pos..pos + 8] == QX_TP_TYPE_WIRE;
    }
    false
}
pub const QX_PING_REQ: u64 = 0x348c_6752_9ef8_c7bd;
pub const QX_PING_RESP: u64 = 0x348c_6752_9ef8_c7be;
pub const FRAME_PADDING: u64 = 0x00;
pub const FRAME_RESET_STREAM: u64 = 0x04;
pub const FRAME_STOP_SENDING: u64 = 0x05;
pub const FRAME_RESET_STREAM_AT: u64 = 0x24;
pub const FRAME_STREAM_BASE: u64 = 0x08;
pub const FRAME_MAX_DATA: u64 = 0x10;
pub const FRAME_MAX_STREAM_DATA: u64 = 0x11;
pub const FRAME_MAX_STREAMS_BIDI: u64 = 0x12;
pub const FRAME_MAX_STREAMS_UNI: u64 = 0x13;
pub const FRAME_DATA_BLOCKED: u64 = 0x14;
pub const FRAME_STREAM_DATA_BLOCKED: u64 = 0x15;
pub const FRAME_STREAMS_BLOCKED_BIDI: u64 = 0x16;
pub const FRAME_STREAMS_BLOCKED_UNI: u64 = 0x17;
pub const FRAME_DATAGRAM_LEN: u64 = 0x31;
pub const FRAME_DATAGRAM: u64 = 0x30;
pub const FRAME_CONNECTION_CLOSE_TRANSPORT: u64 = 0x1c;
pub const FRAME_CONNECTION_CLOSE_APP: u64 = 0x1d;

impl FrameKind {
    pub fn from_type(t: u64) -> Option<(FrameKind, u8)> {
        match t {
            FRAME_PADDING => Some((FrameKind::Padding, 0)),
            FRAME_RESET_STREAM => Some((FrameKind::ResetStream, 0)),
            FRAME_STOP_SENDING => Some((FrameKind::StopSending, 0)),
            FRAME_RESET_STREAM_AT => Some((FrameKind::ResetStreamAt, 0)),
            FRAME_MAX_DATA => Some((FrameKind::MaxData, 0)),
            FRAME_MAX_STREAM_DATA => Some((FrameKind::MaxStreamData, 0)),
            FRAME_MAX_STREAMS_BIDI => Some((FrameKind::MaxStreamsBidi, 0)),
            FRAME_MAX_STREAMS_UNI => Some((FrameKind::MaxStreamsUni, 0)),
            FRAME_DATA_BLOCKED => Some((FrameKind::DataBlocked, 0)),
            FRAME_STREAM_DATA_BLOCKED => Some((FrameKind::StreamDataBlocked, 0)),
            FRAME_STREAMS_BLOCKED_BIDI => Some((FrameKind::StreamsBlockedBidi, 0)),
            FRAME_STREAMS_BLOCKED_UNI => Some((FrameKind::StreamsBlockedUni, 0)),
            FRAME_DATAGRAM_LEN => Some((FrameKind::Datagram, 1)),
            FRAME_DATAGRAM => Some((FrameKind::Datagram, 0)),
            FRAME_CONNECTION_CLOSE_TRANSPORT => Some((FrameKind::ConnectionCloseTransport, 0)),
            FRAME_CONNECTION_CLOSE_APP => Some((FrameKind::ConnectionCloseApp, 0)),
            QX_TP_TYPE => Some((FrameKind::QxTransportParameters, 0)),
            // 兼容草案十六进制写法（见 QX_TP_TYPE 的说明）：接收端两种都认
            QX_TP_TYPE_DOC_HEX => Some((FrameKind::QxTransportParameters, 0)),
            QX_PING_REQ => Some((FrameKind::QxPingRequest, 0)),
            QX_PING_RESP => Some((FrameKind::QxPingResponse, 0)),
            t if (FRAME_STREAM_BASE..FRAME_STREAM_BASE + 8).contains(&t) => {
                Some((FrameKind::Stream, (t & 0x07) as u8))
            }
            // §4：QUIC v1 里其它帧一律禁止 —— 收到就是帧编码错误。
            _ => None,
        }
    }
}

/// 解析出来的帧。字段按 QUIC v1 定义，未用到的字段留默认值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    ResetStreamAt {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
        reliable_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    Stream {
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    },
    MaxData(u64),
    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },
    MaxStreams {
        bidi: bool,
        maximum: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },
    StreamsBlocked {
        bidi: bool,
        limit: u64,
    },
    Datagram(Vec<u8>),
    ConnectionClose {
        app: bool,
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    QxTransportParameters(Vec<u8>),
    QxPing(u64),
    QxPingAck(u64),
}

impl Frame {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Padding(n) => out.extend(std::iter::repeat(0u8).take(*n)),
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                put_varint(out, FRAME_RESET_STREAM);
                put_varint(out, *stream_id);
                put_varint(out, *error_code);
                put_varint(out, *final_size);
            }
            Frame::ResetStreamAt {
                stream_id,
                error_code,
                final_size,
                reliable_size,
            } => {
                put_varint(out, FRAME_RESET_STREAM_AT);
                put_varint(out, *stream_id);
                put_varint(out, *error_code);
                put_varint(out, *final_size);
                put_varint(out, *reliable_size);
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                put_varint(out, FRAME_STOP_SENDING);
                put_varint(out, *stream_id);
                put_varint(out, *error_code);
            }
            Frame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                // type = 0x08 | FIN(0x01) | LEN(0x02) | OFF(0x04)；本实现始终带 LEN 与 OFF：
                // 带 OFF 是为了与草案「保留冗余字段以便复用 QUIC 栈」的取向一致，
                // 带 LEN 让接收侧不必依赖记录边界解析（§3.2 允许用记录边界，但显式更稳）。
                let t = FRAME_STREAM_BASE | if *fin { 0x01 } else { 0 } | 0x02 | 0x04;
                put_varint(out, t);
                put_varint(out, *stream_id);
                put_varint(out, *offset);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::MaxData(v) => {
                put_varint(out, FRAME_MAX_DATA);
                put_varint(out, *v);
            }
            Frame::MaxStreamData { stream_id, maximum } => {
                put_varint(out, FRAME_MAX_STREAM_DATA);
                put_varint(out, *stream_id);
                put_varint(out, *maximum);
            }
            Frame::MaxStreams { bidi, maximum } => {
                put_varint(
                    out,
                    if *bidi {
                        FRAME_MAX_STREAMS_BIDI
                    } else {
                        FRAME_MAX_STREAMS_UNI
                    },
                );
                put_varint(out, *maximum);
            }
            Frame::DataBlocked(v) => {
                put_varint(out, FRAME_DATA_BLOCKED);
                put_varint(out, *v);
            }
            Frame::StreamDataBlocked { stream_id, limit } => {
                put_varint(out, FRAME_STREAM_DATA_BLOCKED);
                put_varint(out, *stream_id);
                put_varint(out, *limit);
            }
            Frame::StreamsBlocked { bidi, limit } => {
                put_varint(
                    out,
                    if *bidi {
                        FRAME_STREAMS_BLOCKED_BIDI
                    } else {
                        FRAME_STREAMS_BLOCKED_UNI
                    },
                );
                put_varint(out, *limit);
            }
            Frame::Datagram(d) => {
                put_varint(out, FRAME_DATAGRAM_LEN);
                put_varint(out, d.len() as u64);
                out.extend_from_slice(d);
            }
            Frame::ConnectionClose {
                app,
                error_code,
                frame_type,
                reason,
            } => {
                put_varint(
                    out,
                    if *app {
                        FRAME_CONNECTION_CLOSE_APP
                    } else {
                        FRAME_CONNECTION_CLOSE_TRANSPORT
                    },
                );
                put_varint(out, *error_code);
                if !*app {
                    put_varint(out, *frame_type);
                }
                put_varint(out, reason.len() as u64);
                out.extend_from_slice(reason);
            }
            Frame::QxTransportParameters(tp) => {
                put_varint(out, QX_TP_TYPE);
                put_varint(out, tp.len() as u64);
                out.extend_from_slice(tp);
            }
            Frame::QxPing(seq) => {
                put_varint(out, QX_PING_REQ);
                put_varint(out, *seq);
            }
            Frame::QxPingAck(seq) => {
                put_varint(out, QX_PING_RESP);
                put_varint(out, *seq);
            }
        }
    }
}

/// 解析**一个记录**（Frames 字段）里的帧序列。
///
/// 记录边界即负载边界：末尾若不是帧边界 → `FRAME_ENCODING_ERROR`（§3.2）。
pub fn parse_frames(buf: &[u8]) -> Result<Vec<Frame>, ProtoError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let t = get_varint(buf, &mut pos)?;
        let (kind, bits) = FrameKind::from_type(t).ok_or_else(|| {
            ProtoError::frame(format!("禁止/未知的帧类型 0x{t:x}（§4 只允许 QUIC v1 的子集）"))
        })?;
        let f = match kind {
            FrameKind::Padding => {
                // PADDING 是 0x00 单字节；连续多个合并成一个事件即可。
                let mut n = 1;
                while pos < buf.len() && buf[pos] == 0 {
                    n += 1;
                    pos += 1;
                }
                Frame::Padding(n)
            }
            FrameKind::ResetStream => Frame::ResetStream {
                stream_id: get_varint(buf, &mut pos)?,
                error_code: get_varint(buf, &mut pos)?,
                final_size: get_varint(buf, &mut pos)?,
            },
            FrameKind::ResetStreamAt => Frame::ResetStreamAt {
                stream_id: get_varint(buf, &mut pos)?,
                error_code: get_varint(buf, &mut pos)?,
                final_size: get_varint(buf, &mut pos)?,
                reliable_size: get_varint(buf, &mut pos)?,
            },
            FrameKind::StopSending => Frame::StopSending {
                stream_id: get_varint(buf, &mut pos)?,
                error_code: get_varint(buf, &mut pos)?,
            },
            FrameKind::Stream => {
                let stream_id = get_varint(buf, &mut pos)?;
                let offset = if bits & 0x04 != 0 {
                    get_varint(buf, &mut pos)?
                } else {
                    0
                };
                let len = if bits & 0x02 != 0 {
                    get_varint(buf, &mut pos)? as usize
                } else {
                    // 无 LEN：一直延伸到记录末尾（§3.2 允许用记录边界当负载边界）
                    buf.len() - pos
                };
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(|| ProtoError::frame("STREAM 帧声明长度超出记录"))?;
                let data = buf[pos..end].to_vec();
                pos = end;
                Frame::Stream {
                    stream_id,
                    offset,
                    fin: bits & 0x01 != 0,
                    data,
                }
            }
            FrameKind::MaxData => Frame::MaxData(get_varint(buf, &mut pos)?),
            FrameKind::MaxStreamData => Frame::MaxStreamData {
                stream_id: get_varint(buf, &mut pos)?,
                maximum: get_varint(buf, &mut pos)?,
            },
            FrameKind::MaxStreamsBidi => Frame::MaxStreams {
                bidi: true,
                maximum: get_varint(buf, &mut pos)?,
            },
            FrameKind::MaxStreamsUni => Frame::MaxStreams {
                bidi: false,
                maximum: get_varint(buf, &mut pos)?,
            },
            FrameKind::DataBlocked => Frame::DataBlocked(get_varint(buf, &mut pos)?),
            FrameKind::StreamDataBlocked => Frame::StreamDataBlocked {
                stream_id: get_varint(buf, &mut pos)?,
                limit: get_varint(buf, &mut pos)?,
            },
            FrameKind::StreamsBlockedBidi => Frame::StreamsBlocked {
                bidi: true,
                limit: get_varint(buf, &mut pos)?,
            },
            FrameKind::StreamsBlockedUni => Frame::StreamsBlocked {
                bidi: false,
                limit: get_varint(buf, &mut pos)?,
            },
            FrameKind::Datagram => {
                let len = if bits == 1 {
                    get_varint(buf, &mut pos)? as usize
                } else {
                    buf.len() - pos
                };
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(|| ProtoError::frame("DATAGRAM 帧声明长度超出记录"))?;
                let d = buf[pos..end].to_vec();
                pos = end;
                Frame::Datagram(d)
            }
            FrameKind::ConnectionCloseTransport | FrameKind::ConnectionCloseApp => {
                let app = kind == FrameKind::ConnectionCloseApp;
                let error_code = get_varint(buf, &mut pos)?;
                // 传输错误才带 Frame Type 字段（RFC 9000 §19.19）
                let frame_type = if app { 0 } else { get_varint(buf, &mut pos)? };
                let rlen = get_varint(buf, &mut pos)? as usize;
                let end = pos
                    .checked_add(rlen)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(|| ProtoError::frame("CONNECTION_CLOSE 理由长度超出记录"))?;
                let reason = buf[pos..end].to_vec();
                pos = end;
                Frame::ConnectionClose {
                    app,
                    error_code,
                    frame_type,
                    reason,
                }
            }
            FrameKind::QxTransportParameters => {
                let len = get_varint(buf, &mut pos)? as usize;
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= buf.len())
                    .ok_or_else(|| ProtoError::frame("QX_TRANSPORT_PARAMETERS 长度超出记录"))?;
                let tp = buf[pos..end].to_vec();
                pos = end;
                Frame::QxTransportParameters(tp)
            }
            FrameKind::QxPingRequest => Frame::QxPing(get_varint(buf, &mut pos)?),
            FrameKind::QxPingResponse => Frame::QxPingAck(get_varint(buf, &mut pos)?),
        };
        // PADDING 合并计数：不把每个 0x00 都塞进事件列表
        if let Frame::Padding(_) = f {
            continue;
        }
        out.push(f);
    }
    Ok(out)
}

/// 传输参数 id（RFC 9000 §18.2 + 草案 §5.2）。
pub mod tpid {
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
    pub const MAX_RECORD_SIZE: u64 = 0x0571_c594_29cd_0845;
    /// 草案 §9.2：Stream Resets with Partial Delivery 协商用的传输参数。
    pub const RESET_STREAM_AT: u64 = 0x2a76_d166_2b8d_bbcd;
}

/// QUIC §18.2 里**被草案 §5.1 禁止**的那批（收到即 `TRANSPORT_PARAMETER_ERROR`）。
const FORBIDDEN_TP: &[u64] = &[
    0x00, // original_destination_connection_id
    0x02, // stateless_reset_token
    0x0a, // ack_delay_exponent
    0x0b, // max_ack_delay
    0x0c, // disable_active_migration
    0x0d, // preferred_address
    0x0e, // active_connection_id_limit
    0x0f, // initial_source_connection_id
    0x10, // retry_source_connection_id
];

/// `max_record_size` 的默认值（§5.2）。
pub const DEFAULT_MAX_RECORD_SIZE: u64 = 16382;

/// 我方声明的传输参数（对端视角的「我的能力/限额」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportParams {
    pub max_idle_timeout: u64, // ms；0 = 不设
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_record_size: u64,
    /// Some(n) 表示支持 DATAGRAM 扩展且最大帧长 n（§9.1）
    pub max_datagram_frame_size: Option<u64>,
    /// 是否支持 RESET_STREAM_AT（§9.2）
    pub reset_stream_at: bool,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            max_idle_timeout: 30_000,
            initial_max_data: 1024 * 1024,
            initial_max_stream_data_bidi_local: 256 * 1024,
            initial_max_stream_data_bidi_remote: 256 * 1024,
            initial_max_stream_data_uni: 256 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            max_record_size: DEFAULT_MAX_RECORD_SIZE,
            max_datagram_frame_size: Some(DEFAULT_MAX_RECORD_SIZE),
            reset_stream_at: true,
        }
    }
}

impl TransportParams {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut put = |id: u64, v: u64| {
            put_varint(&mut out, id);
            put_varint(&mut out, varint_len(v) as u64);
            put_varint(&mut out, v);
        };
        if self.max_idle_timeout > 0 {
            put(tpid::MAX_IDLE_TIMEOUT, self.max_idle_timeout);
        }
        put(tpid::INITIAL_MAX_DATA, self.initial_max_data);
        put(
            tpid::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        put(
            tpid::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        );
        put(tpid::INITIAL_MAX_STREAM_DATA_UNI, self.initial_max_stream_data_uni);
        put(tpid::INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi);
        put(tpid::INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni);
        put(tpid::MAX_RECORD_SIZE, self.max_record_size);
        if let Some(n) = self.max_datagram_frame_size {
            put(tpid::MAX_DATAGRAM_FRAME_SIZE, n);
        }
        if self.reset_stream_at {
            put(tpid::RESET_STREAM_AT, 1);
        }
        out
    }

    /// 解析对端参数并按草案 §5.1 校验。
    ///
    /// 规则：允许 id 逐个读；**被禁**的 id → `TRANSPORT_PARAMETER_ERROR`；
    /// 其余未知 id 按 §5.1 忽略（保留在 `unknown` 里便于观测）。
    pub fn decode(buf: &[u8]) -> Result<(TransportParams, Vec<u64>), ProtoError> {
        let mut tp = TransportParams::default();
        let mut unknown = Vec::new();
        let mut seen: BTreeMap<u64, ()> = BTreeMap::new();
        let mut pos = 0usize;
        while pos < buf.len() {
            let id = get_varint(buf, &mut pos)?;
            let len = get_varint(buf, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|e| *e <= buf.len())
                .ok_or_else(|| ProtoError::params("传输参数长度超出帧"))?;
            let val = &buf[pos..end];
            pos = end;
            if seen.insert(id, ()).is_some() {
                return Err(ProtoError::params(format!("传输参数 0x{id:x} 重复")));
            }
            if FORBIDDEN_TP.contains(&id) {
                return Err(ProtoError::params(format!(
                    "传输参数 0x{id:x} 在 QMux 中被禁止（草案 §5.1）"
                )));
            }
            // 取值：按 QUIC §18 的编码，一律是变长整数（保留 0 长度写法）
            let mut vpos = 0usize;
            let num = if val.is_empty() {
                0
            } else {
                let v = get_varint(val, &mut vpos)?;
                if vpos != val.len() {
                    return Err(ProtoError::params(format!(
                        "传输参数 0x{id:x} 的值不是单个变长整数"
                    )));
                }
                v
            };
            match id {
                tpid::MAX_IDLE_TIMEOUT => tp.max_idle_timeout = num,
                tpid::INITIAL_MAX_DATA => tp.initial_max_data = num,
                tpid::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    tp.initial_max_stream_data_bidi_local = num
                }
                tpid::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    tp.initial_max_stream_data_bidi_remote = num
                }
                tpid::INITIAL_MAX_STREAM_DATA_UNI => tp.initial_max_stream_data_uni = num,
                tpid::INITIAL_MAX_STREAMS_BIDI => tp.initial_max_streams_bidi = num,
                tpid::INITIAL_MAX_STREAMS_UNI => tp.initial_max_streams_uni = num,
                tpid::MAX_RECORD_SIZE => {
                    if num < DEFAULT_MAX_RECORD_SIZE {
                        return Err(ProtoError::params(format!(
                            "max_record_size={num} 小于默认值 {DEFAULT_MAX_RECORD_SIZE}（草案 §5.2）"
                        )));
                    }
                    tp.max_record_size = num;
                }
                tpid::MAX_DATAGRAM_FRAME_SIZE => tp.max_datagram_frame_size = Some(num),
                tpid::RESET_STREAM_AT => tp.reset_stream_at = num != 0,
                other => unknown.push(other),
            }
        }
        Ok((tp, unknown))
    }
}

/// 把若干帧封进一条记录（超出 `max_record_size` 由调用方负责切分）。
pub fn encode_record(frames: &[Frame], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    for f in frames {
        f.encode(&mut body);
    }
    put_varint(out, body.len() as u64);
    out.extend_from_slice(&body);
}

/// 记录解析器：从字节流里增量取记录（§3.2 的自定界）。
///
/// 用法：`push(&bytes)` 累积，然后反复 `next_record()`；返回 `Ok(None)` 表示还需要更多字节。
pub struct RecordReader {
    buf: Vec<u8>,
    /// 已读到的大小（None = 还没读完 Size 字段）
    need: Option<usize>,
    /// 允许的单条记录上限。默认 [`DEFAULT_MAX_RECORD_SIZE`]，协商 `max_record_size`
    /// 传输参数后由 [`RecordReader::set_max_record_size`] **提高**（草案 §5.2 只允许调大）。
    max_record_size: u64,
}

impl Default for RecordReader {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            need: None,
            max_record_size: DEFAULT_MAX_RECORD_SIZE,
        }
    }
}

impl RecordReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// 协商后的单条记录上限（取「默认值」与「对端声明值」的较大者，对齐 §5.2 的语义）。
    pub fn set_max_record_size(&mut self, v: u64) {
        self.max_record_size = v.max(DEFAULT_MAX_RECORD_SIZE);
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// 缓冲里还有多少没被消费的字节（用于流控/DoS 观测）。
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// 取下一条完整记录（Frames 字段）。`Ok(None)` = 数据还不够。
    pub fn next_record(&mut self) -> Result<Option<Vec<u8>>, ProtoError> {
        if self.need.is_none() {
            // 先看能不能读出 Size（变长整数，可能不完整）
            let mut pos = 0usize;
            match get_varint(&self.buf, &mut pos) {
                Ok(size) => {
                    // **先查上限再缓冲**。旧实现把 Size 原样当作「还要再收多少字节」，
                    // 于是任何能连上 QMux 的客户端发 8 字节 `FF..FF`（≈2^62）就能让我们
                    // 按声明值无界涨内存 —— 未认证的 OOM。上限来自协商值
                    //（`set_max_record_size`），默认 16382（§5.2）。
                    if size > self.max_record_size {
                        return Err(ProtoError::frame(format!(
                            "记录声明长度 {size} 超过上限 {}（max_record_size）",
                            self.max_record_size
                        )));
                    }
                    self.need = Some(size as usize);
                    self.buf.drain(..pos);
                }
                Err(_) => return Ok(None), // 不完整 → 等更多字节
            }
        }
        let need = self.need.unwrap_or(0);
        if self.buf.len() < need {
            return Ok(None);
        }
        let body: Vec<u8> = self.buf.drain(..need).collect();
        self.need = None;
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 声明长度必须**先**与上限比较：超限立刻报错，绝不按声明值缓冲。
    ///
    /// 这是「一条未认证连接吃光内存」那个问题的回归测试：旧实现的 `next_record`
    /// 把 Size 直接当成待收字节数，客户端发 `C0 FF FF FF FF FF FF FF FF` 即可无界占用。
    #[test]
    fn declared_record_size_is_capped_before_buffering() {
        let mut r = RecordReader::new();
        // 8 字节 varint = 2^62-1：远超上限
        r.push(&[0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let e = r.next_record().expect_err("超限声明必须报错，而不是等待缓冲");
        assert!(format!("{e}").contains("上限"), "{e}");
        // 缓冲里最多只有我们推给它的那几个字节（**没有**按声明长度涨起来）
        assert!(
            r.buffered() <= 9,
            "不得按声明长度缓冲：buffered={}",
            r.buffered()
        );

        // 恰好等于默认上限：合法，只是还需要更多字节
        let mut r2 = RecordReader::new();
        let mut h = Vec::new();
        put_varint(&mut h, DEFAULT_MAX_RECORD_SIZE);
        r2.push(&h);
        assert!(matches!(r2.next_record(), Ok(None)), "等于上限的长度的记录应当继续等待字节");

        // 协商把上限调高后，比默认值大的记录合法
        let mut r3 = RecordReader::new();
        r3.set_max_record_size(DEFAULT_MAX_RECORD_SIZE + 1);
        let mut h3 = Vec::new();
        put_varint(&mut h3, DEFAULT_MAX_RECORD_SIZE + 1);
        r3.push(&h3);
        assert!(matches!(r3.next_record(), Ok(None)), "协商调高后的记录应当合法");

        // 但协商值**不能低于默认**（§5.2：只允许调大）
        let mut r4 = RecordReader::new();
        r4.set_max_record_size(16);
        let mut h4 = Vec::new();
        put_varint(&mut h4, DEFAULT_MAX_RECORD_SIZE);
        r4.push(&h4);
        assert!(matches!(r4.next_record(), Ok(None)), "set 传入过小值时不得低于默认上限");
    }

    #[test]
    fn varint_roundtrip_boundaries() {
        for v in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            (1u64 << 62) - 1,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out.len(), varint_len(v), "长度不匹配 v={v}");
            let mut pos = 0;
            assert_eq!(get_varint(&out, &mut pos).unwrap(), v);
            assert_eq!(pos, out.len());
        }
        // 截断要报错而不是 panic
        let mut pos = 0;
        assert!(get_varint(&[0x40], &mut pos).is_err()); // 声明 2 字节但只有 1 字节
    }

    #[test]
    fn frame_roundtrip_allowed_types() {
        let frames = vec![
            Frame::ResetStream {
                stream_id: 4,
                error_code: 1,
                final_size: 9,
            },
            Frame::ResetStreamAt {
                stream_id: 4,
                error_code: 1,
                final_size: 9,
                reliable_size: 5,
            },
            Frame::StopSending {
                stream_id: 4,
                error_code: 2,
            },
            Frame::Stream {
                stream_id: 0,
                offset: 1234,
                fin: true,
                data: b"hello".to_vec(),
            },
            Frame::MaxData(1 << 20),
            Frame::MaxStreamData {
                stream_id: 0,
                maximum: 1 << 16,
            },
            Frame::MaxStreams {
                bidi: true,
                maximum: 7,
            },
            Frame::MaxStreams {
                bidi: false,
                maximum: 8,
            },
            Frame::DataBlocked(1),
            Frame::StreamDataBlocked {
                stream_id: 0,
                limit: 2,
            },
            Frame::StreamsBlocked {
                bidi: true,
                limit: 3,
            },
            Frame::StreamsBlocked {
                bidi: false,
                limit: 4,
            },
            Frame::Datagram(b"dgram".to_vec()),
            Frame::ConnectionClose {
                app: false,
                error_code: err::PROTOCOL_VIOLATION,
                frame_type: FRAME_STREAM_BASE,
                reason: b"bad".to_vec(),
            },
            Frame::QxTransportParameters(vec![1, 2, 3]),
            Frame::QxPing(42),
            Frame::QxPingAck(42),
        ];
        let mut buf = Vec::new();
        for f in &frames {
            f.encode(&mut buf);
        }
        let back = parse_frames(&buf).unwrap();
        assert_eq!(back, frames);
    }

    /// §4：QUIC v1 里被禁的帧（PING/ACK/CRYPTO/...）必须被拒。
    #[test]
    fn prohibited_frames_rejected() {
        for t in [0x01u64, 0x02, 0x03, 0x06, 0x07, 0x18, 0x19, 0x1a, 0x1b, 0x1e] {
            let mut buf = Vec::new();
            put_varint(&mut buf, t);
            let e = parse_frames(&buf).unwrap_err();
            assert_eq!(e.code, err::FRAME_ENCODING_ERROR, "type=0x{t:x}");
        }
    }

    #[test]
    fn record_reader_incremental() {
        let mut out = Vec::new();
        encode_record(&[Frame::MaxData(10)], &mut out);
        let mut rd = RecordReader::new();
        // 逐字节喂，最终必须取出完整记录
        let mut got = None;
        for b in &out {
            rd.push(&[*b]);
            if let Some(body) = rd.next_record().unwrap() {
                got = Some(body);
            }
        }
        let body = got.expect("record body");
        assert_eq!(parse_frames(&body).unwrap(), vec![Frame::MaxData(10)]);
        assert_eq!(rd.buffered(), 0);
    }

    /// §3.2：记录末尾对不齐帧边界 → FRAME_ENCODING_ERROR。
    #[test]
    fn truncated_final_frame_is_encoding_error() {
        // STREAM 帧声明 5 字节 payload，但记录里只有 2 字节
        let mut body = Vec::new();
        put_varint(&mut body, FRAME_STREAM_BASE | 0x02 | 0x04);
        put_varint(&mut body, 0);
        put_varint(&mut body, 0);
        put_varint(&mut body, 5);
        body.extend_from_slice(b"ab");
        let e = parse_frames(&body).unwrap_err();
        assert_eq!(e.code, err::FRAME_ENCODING_ERROR);
    }

    /// §5.1：被禁的传输参数 → TRANSPORT_PARAMETER_ERROR；未知参数忽略。
    #[test]
    fn transport_params_validation() {
        let mine = TransportParams::default();
        let enc = mine.encode();
        let (back, unknown) = TransportParams::decode(&enc).unwrap();
        assert_eq!(back, mine);
        assert!(unknown.is_empty());

        // 被禁参数（max_ack_delay = 0x0b）→ 必须报错
        let mut bad = Vec::new();
        put_varint(&mut bad, 0x0b);
        put_varint(&mut bad, 1);
        put_varint(&mut bad, 25);
        let e = TransportParams::decode(&bad).unwrap_err();
        assert_eq!(e.code, err::TRANSPORT_PARAMETER_ERROR);

        // 未知参数 → 忽略（草案 §5.1 明文要求）
        let mut unk = Vec::new();
        put_varint(&mut unk, 0x1234_5678);
        put_varint(&mut unk, 1);
        put_varint(&mut unk, 7);
        let (_, unknown) = TransportParams::decode(&unk).unwrap();
        assert_eq!(unknown, vec![0x1234_5678]);

        // max_record_size 小于默认值 → 报错（§5.2）
        let mut small = Vec::new();
        put_varint(&mut small, tpid::MAX_RECORD_SIZE);
        put_varint(&mut small, 2);
        put_varint(&mut small, 100);
        let e = TransportParams::decode(&small).unwrap_err();
        assert_eq!(e.code, err::TRANSPORT_PARAMETER_ERROR);
    }

    /// §4.2：magic（wire 上是 `\xffQMX\r\n\r\n`）必须能被识别；两种写法都接受。
    #[test]
    fn qx_tp_frame_type_is_the_magic() {
        let mut buf = Vec::new();
        Frame::QxTransportParameters(vec![]).encode(&mut buf);
        assert_eq!(&buf[..8], b"\xffQMX\r\n\r\n");
        assert_eq!(QX_TP_TYPE, 0x3f514d580d0a0d0a);
        assert_eq!(QX_TP_TYPE_WIRE, b"\xffQMX\r\n\r\n");
        // 草案十六进制写法（wire `\xffQS0…`）也要认
        assert_eq!(QX_TP_TYPE_DOC_HEX, 0x3f5153300d0a0d0a);
        assert!(FrameKind::from_type(QX_TP_TYPE_DOC_HEX).is_some());
    }
}
