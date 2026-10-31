#![no_main]

//! QMux 帧编解码的属性 fuzz：
//!
//! 1. 任意字节 → `parse_frames` 不 panic（越界/截断只能是 `ProtoError`）；
//! 2. 解析成功 → `encode` 再解析必须是**不动点**（语义相等）；
//! 3. 合法编码的**任意前缀**（模拟截断）→ 不 panic，且成功时同样是不动点；
//! 4. `RecordReader` 分块投喂的结果必须与一次性投喂一致（自定界不依赖读边界）；
//! 5. 声明长度超过上限 → 立刻报错且**不按声明值缓冲**（OOM 回归）；
//! 6. `TransportParams` 编解码是规范形（`encode(decode(encode(x))) == encode(x)`）。

use crucible_fuzz::qmux_proto::*;
use libfuzzer_sys::fuzz_target;

fn take_varint_like(data: &[u8], pos: &mut usize) -> u64 {
    // 用输入字节构造任意 62 位以内的值（覆盖 1/2/4/8 字节编码形态）。
    let mut v = 0u64;
    for _ in 0..8 {
        if *pos >= data.len() {
            break;
        }
        v = (v << 8) | data[*pos] as u64;
        *pos += 1;
    }
    v & ((1u64 << 62) - 1)
}

fn assert_idempotent(frames: &[Frame]) {
    let mut body = Vec::new();
    for f in frames {
        f.encode(&mut body);
    }
    let again = parse_frames(&body).expect("encode→parse 必须成功");
    // PADDING 在 parse_frames 里按设计合并/丢弃，两端都不会出现在 frames 里。
    assert_eq!(frames, again.as_slice(), "帧语义 round-trip 不一致");
}

fn frames_from_input(data: &[u8]) -> Vec<Frame> {
    let mut pos = 0usize;
    let a = take_varint_like(data, &mut pos);
    let b = take_varint_like(data, &mut pos);
    let c = take_varint_like(data, &mut pos);
    let payload = if pos < data.len() {
        data[pos..].to_vec()
    } else {
        Vec::new()
    };
    let mut frames = vec![
        Frame::ResetStream {
            stream_id: a,
            error_code: b,
            final_size: c,
        },
        Frame::ResetStreamAt {
            stream_id: a,
            error_code: b,
            final_size: c,
            reliable_size: b ^ c,
        },
        Frame::StopSending {
            stream_id: a,
            error_code: c,
        },
        Frame::Stream {
            stream_id: a,
            offset: b,
            fin: a & 1 == 1,
            data: payload.clone(),
        },
        Frame::MaxData(c),
        Frame::MaxStreamData {
            stream_id: b,
            maximum: a,
        },
        Frame::MaxStreams {
            bidi: c & 1 == 0,
            maximum: a,
        },
        Frame::DataBlocked(b),
        Frame::StreamDataBlocked {
            stream_id: a,
            limit: c,
        },
        Frame::StreamsBlocked {
            bidi: b & 1 == 1,
            limit: c,
        },
        Frame::Datagram(payload.clone()),
        Frame::ConnectionClose {
            app: false,
            error_code: a,
            frame_type: b,
            reason: payload.clone(),
        },
        Frame::ConnectionClose {
            app: true,
            error_code: b,
            frame_type: 0,
            reason: payload,
        },
        Frame::QxPing(a),
        Frame::QxPingAck(b),
        Frame::QxTransportParameters(vec![1, 2, 3]),
    ];
    // 可选 PADDING：只影响编码长度，不参与语义比较（parse 会丢弃）。
    if c & 1 == 1 {
        frames.push(Frame::Padding(1 + (a % 7) as usize));
    }
    frames
}

fuzz_target!(|data: &[u8]| {
    // (1) 任意字节直接解析：不 panic。
    let arbitrary = parse_frames(data);
    if let Ok(ref frames) = arbitrary {
        // (2) 成功解析 → 重新编码 → 再解析必须一致。
        assert_idempotent(frames);
    }

    // (3)(4)(5) 由输入构造的合法帧序列。
    let frames = frames_from_input(data);
    let mut body = Vec::new();
    for f in &frames {
        f.encode(&mut body);
    }
    let parsed = parse_frames(&body).expect("合法编码必须可解析");
    let semantic: Vec<Frame> = frames
        .iter()
        .filter(|f| !matches!(f, Frame::Padding(_)))
        .cloned()
        .collect();
    assert_eq!(parsed, semantic, "构造帧 round-trip 不一致");

    // 任意截断：不 panic；成功时（截断恰好落在帧边界）必须是不动点。
    // 长输入按步长抽样，保证单次执行是 O(n) 而不是 O(n²)。
    let step = (body.len() / 64).max(1);
    let mut seen = 0usize;
    loop {
        if let Ok(fs) = parse_frames(&body[..seen]) {
            assert_idempotent(&fs);
        }
        if seen >= body.len() {
            break;
        }
        seen = (seen + step).min(body.len());
    }

    // RecordReader：一次性 vs 分块投喂，结果序列必须一致。
    //
    // 注意：`encode_record` **不**切分（文档：「超出 max_record_size 由调用方负责切分」）。
    // 构造帧里带 PAYLOAD 的三份拷贝，body 很容易超过 DEFAULT_MAX_RECORD_SIZE；此时
    // RecordReader 按 §5.2 必须拒绝这条超限记录，而不是接受它。
    let mut rec = Vec::new();
    encode_record(&frames, &mut rec);
    let mut rr = RecordReader::new();
    rr.push(&rec);
    if body.len() as u64 <= DEFAULT_MAX_RECORD_SIZE {
        let whole = rr.next_record().expect("未超上限的记录必须可解析");
        assert_eq!(whole.as_deref(), Some(body.as_slice()));
        assert_eq!(rr.next_record().unwrap(), None);
    } else {
        assert!(
            rr.next_record().is_err(),
            "单条记录 {} 字节超过 max_record_size={} 却未被拒绝",
            body.len(),
            DEFAULT_MAX_RECORD_SIZE
        );
    }

    if body.len() as u64 <= DEFAULT_MAX_RECORD_SIZE && rec.len() > 1 {
        let mut rr2 = RecordReader::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        let chunk = 1 + (data.first().copied().unwrap_or(0) as usize % 7);
        for chunk_bytes in rec.chunks(chunk) {
            rr2.push(chunk_bytes);
            while let Some(r) = rr2.next_record().unwrap() {
                got.push(r);
            }
        }
        assert_eq!(got, vec![body.clone()], "分块投喂的结果与一次性不同");
    }

    // 声明长度超上限：立刻 Err，且 buffered() 不得按声明值增长。
    let mut rr3 = RecordReader::new();
    let mut huge = Vec::new();
    put_varint(&mut huge, DEFAULT_MAX_RECORD_SIZE + 1);
    huge.extend_from_slice(&[0xAA; 16]);
    rr3.push(&huge);
    let before = rr3.buffered();
    assert!(rr3.next_record().is_err(), "超上限的记录必须立刻拒绝");
    assert_eq!(rr3.buffered(), before, "拒绝时不得消费/扩增缓冲");

    // TransportParams 规范形。
    let mut tp = TransportParams::default();
    let mut p0 = 0usize;
    let mut p1 = 1usize;
    let mut p2 = 2usize;
    let mut p3 = 3usize;
    let mut p4 = 4usize;
    let mut p5 = 5usize;
    let mut p6 = 6usize;
    let mut p7 = 7usize;
    let mut p8 = 8usize;
    tp.max_idle_timeout = take_varint_like(data, &mut p0);
    tp.initial_max_data = take_varint_like(data, &mut p1);
    tp.initial_max_stream_data_bidi_local = take_varint_like(data, &mut p2);
    tp.initial_max_stream_data_bidi_remote = take_varint_like(data, &mut p3);
    tp.initial_max_stream_data_uni = take_varint_like(data, &mut p4);
    tp.initial_max_streams_bidi = take_varint_like(data, &mut p5);
    tp.initial_max_streams_uni = take_varint_like(data, &mut p6);
    // put_varint 的合法域是 62 位；max_record_size 还必须 ≥ 默认值。
    tp.max_record_size = DEFAULT_MAX_RECORD_SIZE
        + (take_varint_like(data, &mut p7) % ((1u64 << 62) - DEFAULT_MAX_RECORD_SIZE));
    tp.max_datagram_frame_size = if data.len() % 2 == 0 {
        Some(take_varint_like(data, &mut p8))
    } else {
        None
    };
    tp.reset_stream_at = data.len() % 3 != 0;
    let enc1 = tp.encode();
    let (dec, unknown) = TransportParams::decode(&enc1).expect("自编码参数必须可解码");
    assert!(unknown.is_empty());
    // encode 是**规范形**：`max_idle_timeout == 0`（不设）与 `reset_stream_at == false`
    // 都不落盘；decode 对缺失项取 Default（30000 / true）。因此由任意输入构造的 enc1
    // 可能不是 encode→decode→encode 的不动点；从 dec 起的规范形必须稳定。
    let enc2 = dec.encode();
    let (dec2, _) = TransportParams::decode(&enc2).unwrap();
    assert_eq!(dec, dec2, "TransportParams 解码不是幂等");
    let enc3 = dec2.encode();
    assert_eq!(enc2, enc3, "TransportParams 不是编码不动点");
});
