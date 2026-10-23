#!/usr/bin/env python3
"""TLS 版本探针（验收脚本用）。

用法: python3 scripts/tls_probe.py <port> [TLSv1|TLSv1_1|TLSv1_2|TLSv1_3|sslv3|v2compat] [host]

为什么需要它：验收脚本此前调用 `/tmp/_tlsprobe.py`，而那个文件**在仓库与历史里都不存在**
——硬门（post-sslv2 必须仍能 TLS1.3）因此**必然失败**，其余 TLS 冒烟又都带 `|| true`，
等于既跑不通、又什么都没测。这里给出一个真实可用的实现：

* 用 python3 自带的 `ssl`（底层是平台 TLS 栈）而不是 openssl CLI（用户要求项目不依赖 openssl）；
* `minimum_version == maximum_version` 把协商钉死在目标版本上，成功即证明该版本可用；
* 退出码 0/1 明确表达结果，调用方**不要**再用 `|| true` 吞掉。

另外提供两个**纯标准库**的 SSL 3.0 客户端模式（本机 OpenSSL 3.x 已删除 SSLv3，`ssl`
模块无法用来验证 NSS 遗留栈）：

* `sslv3`    —— 标准 SSLv3 ClientHello（record version 0x0300）
* `v2compat` —— IE6 风格 `SSL_ENABLE_V2_COMPATIBLE_HELLO`：SSLv2 记录封装的
  ClientHello，version 字段 0x0300，cipher spec 用 `00 || suite` 三字节编码。

两者都走完整的 RSA 密钥交换 + RC4_128_MD5（0x0004）记录层，最后发一个 HTTP 请求并
校验响应，用来证明「握手真的完成、应用数据真的能收发」，而不只是 ServerHello。
只依赖 hashlib/socket/struct —— RSA 加密用 DER 解析证书后做 `pow()`，RC4 是内联实现。
"""
import hashlib
import os
import socket
import ssl
import struct
import sys

_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1_0": ssl.TLSVersion.TLSv1,
    "TLSv1_1": ssl.TLSVersion.TLSv1_1,
    "TLSv1_2": ssl.TLSVersion.TLSv1_2,
    "TLSv1_3": ssl.TLSVersion.TLSv1_3,
}
LEGACY_MODES = ("sslv3", "v2compat")

# ---------------------------------------------------------------------------
# 纯标准库工具：DER / RSA / RC4 / SSLv3 PRF
# ---------------------------------------------------------------------------

CIPHER_RC4_128_MD5 = 0x0004
PAD48 = b"\x36" * 48
PAD48_OUT = b"\x5c" * 48
PAD40 = b"\x36" * 40
PAD40_OUT = b"\x5c" * 40


def _der_tlv(buf, off):
    """Return (tag, value_bytes, next_offset) for one DER TLV."""
    if off + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or off + n > len(buf):
            raise ValueError("bad DER length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + ln > len(buf):
        raise ValueError("DER length overflow")
    return tag, buf[off:off + ln], off + ln


def cert_rsa_pubkey(der):
    """Extract (n, e) from an X.509 certificate's subjectPublicKeyInfo."""
    _, cert, _ = _der_tlv(der, 0)          # Certificate SEQUENCE
    _, tbs, _ = _der_tlv(cert, 0)          # tbsCertificate SEQUENCE
    off = 0
    if tbs[0] == 0xA0:                     # optional [0] EXPLICIT version
        _, _, off = _der_tlv(tbs, 0)
    for _ in range(5):                     # serial, sigalg, issuer, validity, subject
        _, _, off = _der_tlv(tbs, off)
    _, spki, _ = _der_tlv(tbs, off)        # subjectPublicKeyInfo
    _, _, o2 = _der_tlv(spki, 0)           # AlgorithmIdentifier
    _, bits, _ = _der_tlv(spki, o2)        # BIT STRING
    if not bits or bits[0] != 0:
        raise ValueError("SPKI is not a byte-aligned key")
    _, rsapub, _ = _der_tlv(bits, 1)       # RSAPublicKey SEQUENCE
    _, n_bytes, o3 = _der_tlv(rsapub, 0)
    _, e_bytes, _ = _der_tlv(rsapub, o3)
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def rsa_encrypt_pkcs1v15(n, e, message):
    """RSAES-PKCS1-v1_5 encryption with a random non-zero padding string."""
    k = (n.bit_length() + 7) // 8
    ps_len = k - 3 - len(message)
    if ps_len < 8:
        raise ValueError("RSA modulus too small")
    ps = bytes((b if b else 1) for b in os.urandom(ps_len))
    em = b"\x00\x02" + ps + b"\x00" + message
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")


class RC4:
    """SSL 3.0 RC4_128: one continuous keystream per direction."""

    def __init__(self, key):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self.S, self.i, self.j = S, 0, 0

    def crypt(self, data):
        out = bytearray(len(data))
        S, i, j = self.S, self.i, self.j
        for k, b in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[k] = b ^ S[(S[i] + S[j]) & 0xFF]
        self.i, self.j = i, j
        return bytes(out)


def ssl3_prf(secret, seed, need):
    """SSL 3.0 PRF: MD5(secret + SHA1(label + secret + seed)), labels A, BB, CCC…"""
    out = b""
    i = 1
    while len(out) < need:
        label = bytes([ord("A") + i - 1]) * i
        out += hashlib.md5(secret + hashlib.sha1(label + secret + seed).digest()).digest()
        i += 1
    return out[:need]


def ssl3_mac_md5(secret, seq, rtype, frag):
    """SSL 3.0 record MAC (MD5): MD5(K + pad2 + MD5(K + pad1 + seq+type+len+frag))."""
    inner = hashlib.md5(secret + PAD48 + struct.pack("!Q", seq) + bytes([rtype])
                        + struct.pack("!H", len(frag)) + frag).digest()
    return hashlib.md5(secret + PAD48_OUT + inner).digest()


def ssl3_finished(master, transcript, sender):
    md5 = hashlib.md5(master + PAD48_OUT
                      + hashlib.md5(transcript + sender + master + PAD48).digest()).digest()
    sha = hashlib.sha1(master + PAD40_OUT
                       + hashlib.sha1(transcript + sender + master + PAD40).digest()).digest()
    return md5 + sha


def _hs_msg(msg_type, body):
    return bytes([msg_type]) + struct.pack("!I", len(body))[1:] + body


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"EOF after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


class _RecordReader:
    def __init__(self, sock):
        self.sock = sock
        self.pending = b""
        self.rc4 = None
        self.mac_key = None
        self.seq = 0

    def _record(self):
        hdr = _recv_exact(self.sock, 5)
        rtype, ver, ln = hdr[0], struct.unpack("!H", hdr[1:3])[0], struct.unpack("!H", hdr[3:5])[0]
        payload = _recv_exact(self.sock, ln)
        if self.rc4 is not None and rtype in (0x15, 0x16, 0x17):
            payload = self.rc4.crypt(payload)
            mac, frag = payload[-16:], payload[:-16]
            if ssl3_mac_md5(self.mac_key, self.seq, rtype, frag) != mac:
                raise ValueError("bad record MAC from server")
            self.seq += 1
            payload = frag
        return rtype, ver, payload

    def handshake(self, expect=None):
        while len(self.pending) < 4:
            rtype, _ver, payload = self._record()
            if rtype != 0x16:
                raise ValueError(f"expected handshake record, got type {rtype}")
            self.pending += payload
        mtype = self.pending[0]
        mlen = int.from_bytes(self.pending[1:4], "big")
        while len(self.pending) < 4 + mlen:
            rtype, _ver, payload = self._record()
            if rtype != 0x16:
                raise ValueError(f"expected handshake record, got type {rtype}")
            self.pending += payload
        body = self.pending[4:4 + mlen]
        self.pending = self.pending[4 + mlen:]
        if expect is not None and mtype != expect:
            raise ValueError(f"expected handshake type {expect}, got {mtype}")
        return mtype, body


def legacy_handshake(port, host, mode, timeout=8.0):
    """Complete an SSLv3 handshake (RSA + RC4_128_MD5) and exchange one request."""
    client_random = os.urandom(32)
    challenge = client_random[-16:]
    if mode == "v2compat":
        # NSS maps the v2 challenge into the low bytes of the 32-byte client_random.
        client_random = b"\x00" * 16 + challenge
        suites = b"\x00" + struct.pack("!H", CIPHER_RC4_128_MD5)
        body = (b"\x01" + struct.pack("!H", 0x0300) + struct.pack("!H", len(suites))
                + struct.pack("!H", 0) + struct.pack("!H", len(challenge)) + suites + challenge)
        hello = bytes([0x80 | ((len(body) >> 8) & 0x7F), len(body) & 0xFF]) + body
        transcript = hello[2:]  # v2-framed hellos are hashed without the 2-byte header
    else:
        hs_body = (struct.pack("!H", 0x0300) + client_random + b"\x00"
                   + struct.pack("!H", 2) + struct.pack("!H", CIPHER_RC4_128_MD5) + b"\x01\x00")
        hs = _hs_msg(1, hs_body)
        hello = b"\x16\x03\x00" + struct.pack("!H", len(hs)) + hs
        transcript = hs  # handshake messages only (no record header)

    sock = socket.create_connection((host, port), timeout=timeout)
    sock.sendall(hello)
    rr = _RecordReader(sock)

    _mtype, sbody = rr.handshake(2)
    transcript += _hs_msg(2, sbody)
    server_version = struct.unpack("!H", sbody[0:2])[0]
    server_random = sbody[2:34]
    sid_len = sbody[34]
    off = 35 + sid_len
    suite = struct.unpack("!H", sbody[off:off + 2])[0]
    if suite != CIPHER_RC4_128_MD5:
        raise ValueError(f"server negotiated unexpected cipher 0x{suite:04x}")

    cert_der = None
    while True:
        mtype, body = rr.handshake()
        transcript += _hs_msg(mtype, body)
        if mtype == 11:
            total = int.from_bytes(body[0:3], "big")
            clen = int.from_bytes(body[3:6], "big")
            cert_der = body[6:6 + clen]
            if 3 + total > len(body):
                raise ValueError("truncated Certificate")
        elif mtype == 14:
            break
        elif mtype in (12, 13):
            raise ValueError(f"unexpected server message type {mtype} (RSA key exchange)")
    if cert_der is None:
        raise ValueError("server sent no certificate")

    n, e = cert_rsa_pubkey(cert_der)
    premaster = struct.pack("!H", 0x0300) + os.urandom(46)
    encrypted = rsa_encrypt_pkcs1v15(n, e, premaster)
    # SSL 3.0 omits the 2-byte length prefix for EncryptedPreMasterSecret.
    cke = _hs_msg(16, encrypted)
    transcript += cke
    sock.sendall(b"\x16\x03\x00" + struct.pack("!H", len(cke)) + cke)

    master = ssl3_prf(premaster, client_random + server_random, 48)
    kb = ssl3_prf(master, server_random + client_random, 64)
    client_mac, server_mac = kb[0:16], kb[16:32]
    client_key, server_key = kb[32:48], kb[48:64]

    sock.sendall(b"\x14\x03\x00\x00\x01\x01")
    client_rc4 = RC4(client_key)
    client_fin = ssl3_finished(master, transcript, b"CLNT")
    fin_msg = _hs_msg(20, client_fin)
    fin_rec = fin_msg + ssl3_mac_md5(client_mac, 0, 0x16, fin_msg)
    sock.sendall(b"\x16\x03\x00" + struct.pack("!H", len(fin_rec)) + client_rc4.crypt(fin_rec))

    rr.rc4 = RC4(server_key)
    rr.mac_key = server_mac
    rr.seq = 0
    rtype, _ver, payload = rr._record()
    if rtype != 0x14 or payload != b"\x01":
        raise ValueError(f"expected server CCS, got type={rtype} payload={payload.hex()}")
    rtype, _ver, server_fin = rr._record()
    expect = _hs_msg(20, ssl3_finished(master, transcript + fin_msg, b"SRVR"))
    if rtype != 0x16 or server_fin != expect:
        raise ValueError("server Finished did not verify")

    req = b"GET / HTTP/1.1\r\nHost: crucible.local\r\nConnection: close\r\n\r\n"
    app = req + ssl3_mac_md5(client_mac, 1, 0x17, req)
    sock.sendall(b"\x17\x03\x00" + struct.pack("!H", len(app)) + client_rc4.crypt(app))

    resp = b""
    try:
        while True:
            rtype, _ver, payload = rr._record()
            if rtype == 0x17:
                resp += payload
            elif rtype == 0x15:
                break
    except (EOFError, ConnectionResetError, socket.timeout, ValueError, OSError):
        pass
    sock.close()
    text = resp.decode("latin-1", "replace")
    first = text.split("\r\n")[0] if text else "<empty>"
    print(f"OK {mode} negotiated=SSL 3.0 (0x{server_version:04x}) cipher=RC4_128_MD5 "
          f"finished=verified http={first!r}")
    return 0 if text.startswith("HTTP/1.1 200") else 1


def main(argv):
    if len(argv) < 2:
        print("usage: tls_probe.py <port> [version] [host]", file=sys.stderr)
        return 2
    port = int(argv[1])
    want = argv[2] if len(argv) > 2 else "TLSv1_3"
    host = argv[3] if len(argv) > 3 else "127.0.0.1"
    if want in LEGACY_MODES:
        try:
            return legacy_handshake(port, host, want)
        except Exception as e:  # noqa: BLE001 - 探针要如实报告任何失败
            print(f"FAIL {want}: {type(e).__name__}: {e}")
            return 1
    ver = _VERSIONS.get(want)
    if ver is None:
        print(f"FAIL unknown version {want!r} (want one of {sorted(_VERSIONS)} or {list(LEGACY_MODES)})")
        return 2

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except (ValueError, OSError) as e:
        # 平台 TLS 栈拒绝钉该版本（LibreSSL/OpenSSL 的安全级别策略）——如实报告。
        print(f"FAIL {want}: platform refuses to pin version: {e}")
        return 1
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                got = tls.version()
                print(f"OK {want} negotiated={got} cipher={tls.cipher()[0]}")
                return 0
    except Exception as e:  # noqa: BLE001 - 探针要如实报告任何失败
        print(f"FAIL {want}: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
