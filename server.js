const express = require('express');
const cors = require('cors');
const Pusher = require('pusher');
const path = require('path');

const app = express();

// ============ 安全加固（零额外依赖，纯代码） ============

// 让 req.ip 正确取到真实客户端 IP（Railway/反向代理场景必须）
app.set('trust proxy', true);

// 简单内存限流器：按 IP 滑动窗口限流，防刷接口 / 应用层 DDoS
const rateStore = new Map(); // ip -> { hits: [timestamps] }
function rateLimit({ windowMs = 60000, max = 60 } = {}) {
  return (req, res, next) => {
    const xff = req.headers['x-forwarded-for'];
    const ip = xff ? String(xff).split(',')[0].trim() : (req.ip || 'unknown');
    const now = Date.now();
    let rec = rateStore.get(ip);
    if (!rec) { rec = { hits: [] }; rateStore.set(ip, rec); }
    rec.hits = rec.hits.filter(t => now - t < windowMs);
    if (rec.hits.length >= max) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      return res.status(429).json({ error: '请求过于频繁，请稍后再试' });
    }
    rec.hits.push(now);
    // 定期清理陈旧记录，防止内存无限增长
    if (rateStore.size > 10000) {
      for (const [k, v] of rateStore) {
        v.hits = v.hits.filter(t => now - t < windowMs);
        if (v.hits.length === 0) rateStore.delete(k);
      }
    }
    next();
  };
}

// 安全响应头
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(cors());
// 限制请求体大小：放行正常同步（含完整状态快照），阻断超大垃圾包
app.use(express.json({ limit: '512kb' }));

// 托管前端静态文件（index.html 放同一目录）
app.use(express.static(path.join(__dirname, '.')));

const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID,
  key: process.env.PUSHER_KEY,
  secret: process.env.PUSHER_SECRET,
  cluster: process.env.PUSHER_CLUSTER || 'ap3',
  useTLS: true
});

// 名字消毒（服务端）：去除 HTML/脚本注入字符，限制长度
function sanitizeName(str, maxLen = 12) {
  if (str == null) return '';
  str = String(str).trim();
  if (str.length > maxLen) str = str.slice(0, maxLen);
  return str.replace(/[<>"'`]/g, '');
}

const EXPECTED_CHANNEL = 'presence-daming-fengyun';

// Pusher Presence 鉴权（必须，跨设备联机的关键）
app.post('/pusher/auth', rateLimit({ windowMs: 60000, max: 120 }), (req, res) => {
  const { socket_id, channel_name, user_info } = req.body || {};
  if (!socket_id || !channel_name) return res.status(400).json({ error: 'Missing params' });
  // socket_id 格式校验（Pusher 标准：数字.数字）
  if (!/^\d{1,20}\.\d{1,30}$/.test(String(socket_id))) {
    return res.status(400).json({ error: 'Invalid socket_id' });
  }
  // 频道名白名单，防止拿本服务去刷任意 Pusher 频道
  if (channel_name !== EXPECTED_CHANNEL) {
    return res.status(400).json({ error: 'Invalid channel' });
  }

  // 清洗 user_info（防止恶意 name 注入 Presence 成员信息，导致前端 XSS）
  let safeUser = { user_id: 'anon', user_info: { name: '未命名玩家', country: '', role: '', countryId: '' } };
  try {
    const raw = user_info || {};
    const inner = raw.user_info || raw; // 兼容前端嵌套结构
    safeUser.user_id = String(raw.user_id || inner.user_id || 'anon').slice(0, 40);
    safeUser.user_info.name = sanitizeName(inner.name) || '未命名玩家';
    safeUser.user_info.country = sanitizeName(inner.country);
    safeUser.user_info.role = sanitizeName(inner.role, 20);
    safeUser.user_info.countryId = sanitizeName(inner.countryId, 40);
  } catch (e) {}

  try {
    res.json(pusher.authenticate(socket_id, channel_name, safeUser));
  } catch (e) {
    res.status(400).json({ error: 'Auth failed' });
  }
});

// 状态广播接口（前端会调这个）
app.post('/api/action', rateLimit({ windowMs: 60000, max: 300 }), (req, res) => {
  const body = req.body || {};
  const action = typeof body.action === 'string' ? body.action.slice(0, 40) : 'unknown';
  const payload = body.payload;
  // 只放行对象型 payload，拒绝数组/原始值垃圾包
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return res.status(400).json({ error: 'Invalid payload' });
  }
  const _msgId = typeof body._msgId === 'string' ? body._msgId.slice(0, 64) : '';

  pusher.trigger(EXPECTED_CHANNEL, 'server-state-update', {
    action,
    payload,
    _msgId,
    timestamp: Date.now()
  }).catch(() => {});

  res.json({ success: true });
});

// 健康检查
app.get('/api/state', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 大明风云: http://localhost:${PORT}`));
