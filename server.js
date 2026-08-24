const express = require('express');
const cors = require('cors');
const Pusher = require('pusher');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// 托管前端静态文件（index.html 放同一目录）
app.use(express.static(path.join(__dirname, '.')));

const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID,
  key: process.env.PUSHER_KEY,
  secret: process.env.PUSHER_SECRET,
  cluster: process.env.PUSHER_CLUSTER || 'ap3',
  useTLS: true
});

// Pusher Presence 鉴权（必须，跨设备联机的关键）
app.post('/pusher/auth', (req, res) => {
  const { socket_id, channel_name, user_info } = req.body;
  if (!socket_id || !channel_name) return res.status(400).json({ error: 'Missing params' });
  res.json(pusher.authenticate(socket_id, channel_name, user_info || {}));
});

// 状态广播接口（前端会调这个）
app.post('/api/action', (req, res) => {
  const { action, payload, _msgId } = req.body;
  pusher.trigger('presence-daming-fengyun', 'server-state-update', {
    action, payload, _msgId, timestamp: Date.now()
  }).catch(() => {});
  res.json({ success: true });
});

// 健康检查
app.get('/api/state', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 大明风云: http://localhost:${PORT}`));
