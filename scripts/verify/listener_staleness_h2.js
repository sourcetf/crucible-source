#!/usr/bin/env node
// J 项修复的 h2 判据：listener 配置变化后，**已建立**的 h2 会话必须收尾（GOAWAY 或关闭），
// 而在**没改配置**时不得收尾（否则每次保存配置都会把在线连接全部打断）。
// node 自带 http2 模块，能直接观察 'goaway' 事件 —— curl 看不到帧。
const http2 = require('http2');
const fs = require('fs');

const port = parseInt(process.argv[2], 10);
const mode = process.argv[3]; // baseline | listener
const cfg = process.argv[4];
const dirB = process.argv[5];

function writeCfg() {
  fs.writeFileSync(
    cfg,
    '[[listeners]]\n' +
      'address = "127.0.0.1"\n' +
      `port = ${port}\n` +
      `root = "${dirB}"\n` +
      'http_versions = ["h1", "h2"]\n\n'
  );
}

function get(session, tag) {
  return new Promise((resolve) => {
    let req;
    try {
      req = session.request({ ':path': '/index.html' });
    } catch (e) {
      return resolve({ body: '<session closed>', err: String(e) });
    }
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => resolve({ body }));
    req.on('error', (e) => resolve({ body: '<error>', err: String(e) }));
    req.end();
  });
}

(async () => {
  const client = http2.connect(`http://127.0.0.1:${port}`);
  let goaway = null;
  let closed = false;
  client.on('goaway', (code, lastStreamID) => {
    goaway = { code, lastStreamID };
  });
  client.on('close', () => (closed = true));
  client.on('error', () => {}); // 收尾时的正常噪声

  const r1 = await get(client, '1');
  console.log(`  第 1 次（改前）body=${JSON.stringify(r1.body.slice(0, 6))}`);

  if (mode === 'baseline') {
    const r2 = await get(client, '2');
    console.log(
      `  第 2 次（未改配置）body=${JSON.stringify(r2.body.slice(0, 6))} goaway=${goaway} closed=${closed}`
    );
    const ok = goaway === null && acked(r2);
    console.log('  判定：', ok ? 'PASS 未发 GOAWAY' : 'FAIL 无谓发 GOAWAY/连接被打断');
    client.close();
    process.exit(ok ? 0 : 1);
  }

  writeCfg();
  await new Promise((r) => setTimeout(r, 4500));
  const r2 = await get(client, '2');
  console.log(`  第 2 次（root 已改）body=${JSON.stringify(r2.body.slice(0, 6))}`);
  await new Promise((r) => setTimeout(r, 1000));
  console.log(`  goaway=${JSON.stringify(goaway)} closed=${closed}`);
  const ok1 = goaway !== null || closed;
  console.log('  判定：', ok1 ? 'PASS 已收尾（GOAWAY / 连接关闭）' : 'FAIL 会话照旧复用');

  // 新会话必须拿到新 root
  const c2 = http2.connect(`http://127.0.0.1:${port}`);
  c2.on('error', () => {});
  const out = await get(c2, 'new');
  console.log(`  新会话 body=${JSON.stringify(out.body.slice(0, 6))}（期望 BBB）`);
  const ok2 = out.body.startsWith('BBB');
  console.log('  判定：', ok2 ? 'PASS 新配置已生效' : 'FAIL 新会话仍是旧配置');
  c2.close();
  client.close();
  process.exit(ok1 && ok2 ? 0 : 1);
})();

function acked(r) {
  return typeof r.body === 'string' && r.body.length > 0 && !r.body.startsWith('<');
}