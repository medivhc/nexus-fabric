'use strict';

/* Nexus Web Gateway browser client (MVP).
 *
 * - Generates an in-memory temporary identity (random 32-byte peer id).
 * - Joins the first-touch node via WSS signaling + RTCPeerConnection.
 * - Receives the mesh node list over the control DataChannel.
 * - Connects to every other node by relaying SDP offers through the
 *   established mesh (no external signaling service).
 * - Opens an SSH terminal: DataChannel -> target node -> real SSH client ->
 *   local sshd. Terminal bytes travel over the DataChannel/mesh (pty layer);
 *   the SSH protocol only happens node <-> sshd.
 */

const $ = (id) => document.getElementById(id);

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function b64encode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const peerId = randomHex(32);
let sessionId = randomHex(16);
let config = null;
let ws = null;
let firstPc = null;
let controlChannel = null; // DataChannel to the first-touch node
const nodeChannels = {};   // peer_id -> RTCDataChannel
const nodeState = {};      // peer_id -> { connected, connecting, pc }
const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];

let termNode = null;
let term = null;
let termFit = null;
let currentSshSession = null;
let currentSshChannel = null;   // channel the open SSH session is bound to
let firstIceTimeout = null;    // first-touch ICE connection timeout handle
let offerReadTimeout = null;   // waiting for answer read timeout handle
let wsHeartbeatTimer = null;   // periodic WS ping interval handle
let lastWsPongTime = 0;        // timestamp of last received WS pong
let isHeartbeatTimeout = false;// whether current disconnect was caused by heartbeat timeout
let answerReceived = false;    // whether SDP answer has been received

const WS_HEARTBEAT_INTERVAL_MS = 3000;
const WS_HEARTBEAT_TIMEOUT_MS = 5000;
const OFFER_READ_TIMEOUT_MS = 10000;
const ICE_CONNECT_TIMEOUT_MS = 15000;
// Binds an SSH session to the DataChannel route it was opened on, so terminal
// bytes never switch channels mid-session (which caused silent freezing when a
// direct channel to the target node late-connects).
const sshRoutes = {}; // session_id -> { channel, node }

// True once the first-touch node's hello_ack arrives. After that the mesh runs
// over WebRTC DataChannels, so a closed signaling WebSocket is no longer an
// error (the old unconditional "Signaling closed" banner was a false alarm that
// also covered the first-node ICE guidance).
let joined = false;

$('peer-id').textContent = `peer: ${peerId}`;

function setStatus(text, cls) {
  const el = $('status');
  el.textContent = text;
  el.className = `status ${cls || ''}`;
}

function setTerminalError(text) {
  const el = $('terminal-error');
  if (el) el.textContent = text;
}

function clearTerminalError() {
  setTerminalError('');
}

function showErrorBanner(text, kind) {
  const el = $('first-node-error');
  const msgEl = $('error-message');
  const badgeEl = $('error-badge');
  if (msgEl) {
    msgEl.textContent = text;
  } else if (el) {
    el.textContent = text;
  }
  if (badgeEl) {
    if (kind === 'heartbeat_timeout') {
      badgeEl.textContent = '心跳超时';
      badgeEl.className = 'error-banner-badge badge-heartbeat';
    } else if (kind === 'read_timeout') {
      badgeEl.textContent = '读超时';
      badgeEl.className = 'error-banner-badge badge-read';
    } else if (kind === 'ice_timeout' || kind === 'ice_failed') {
      badgeEl.textContent = 'P2P 握手';
      badgeEl.className = 'error-banner-badge badge-ice';
    } else {
      badgeEl.textContent = '网络提示';
      badgeEl.className = 'error-banner-badge';
    }
  }
  if (el) el.hidden = false;
  showRetry();
}

function hideErrorBanner() {
  const el = $('first-node-error');
  if (el) el.hidden = true;
}

function showFirstNodeError(text, kind) {
  showErrorBanner(text, kind);
}

function hideFirstNodeError() {
  hideErrorBanner();
}

function showRetry() {
  const el = $('retry-btn');
  if (el) el.hidden = false;
}

function hideRetry() {
  const el = $('retry-btn');
  if (el) el.hidden = true;
}

function startWsHeartbeat() {
  stopWsHeartbeat();
  lastWsPongTime = Date.now();
  wsHeartbeatTimer = setInterval(() => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const now = Date.now();
    if (lastWsPongTime > 0 && (now - lastWsPongTime) > WS_HEARTBEAT_TIMEOUT_MS) {
      isHeartbeatTimeout = true;
      showErrorBanner(
        '心跳超时：未能收到网关的心跳响应（网络可能已断开或丢包严重）。建议检查本地网络、Wi-Fi 或移动数据连接。',
        'heartbeat_timeout'
      );
      setStatus('信令心跳超时 (网络断开)', 'error');
      try { ws.close(); } catch (e) {}
      stopWsHeartbeat();
      return;
    }
    try {
      ws.send(JSON.stringify({ type: 'ping' }));
    } catch (e) {
      console.warn('ws ping failed', e);
    }
  }, WS_HEARTBEAT_INTERVAL_MS);
}

function stopWsHeartbeat() {
  if (wsHeartbeatTimer) {
    clearInterval(wsHeartbeatTimer);
    wsHeartbeatTimer = null;
  }
}

function handleWsPong() {
  lastWsPongTime = Date.now();
}

function createPc() {
  const pc = new RTCPeerConnection({ iceServers });
  pc.oniceconnectionstatechange = () => {
    console.log('ice state', pc.iceConnectionState);
    // First-touch node: if ICE ultimately fails, surface an actionable error
    // in its own banner (never overwritten by later status changes) instead of
    // leaving the page stuck on "WebRTC established".
    if (pc === firstPc &&
        (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected')) {
      showErrorBanner(
        'WebRTC ICE 握手失败。可能处于严格对称 NAT 环境，建议检查 TURN 服务器配置或尝试其他节点。',
        'ice_failed'
      );
      setStatus('P2P ICE 失败', 'error');
    }
  };
  return pc;
}

function openChannel(pc, label, onOpen, onMessage) {
  const ch = pc.createDataChannel(label);
  ch.onopen = onOpen;
  ch.onmessage = onMessage;
  return ch;
}

function sendJson(ch, obj) {
  if (ch && ch.readyState === 'open') ch.send(JSON.stringify(obj));
}

async function init() {
  try {
    const r = await fetch('/api/config');
    config = await r.json();
    if (config.ice_servers && config.ice_servers.length) {
      iceServers.length = 0;
      for (const s of config.ice_servers) iceServers.push(s);
    }
  } catch (e) {
    console.warn('failed to fetch /api/config', e);
  }
  await joinMesh();
}

function joinMesh() {
  isHeartbeatTimeout = false;
  answerReceived = false;
  ws = new WebSocket(`wss://${location.host}/ws`);

  ws.onmessage = async (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (e) {
      return;
    }
    if (msg.type === 'pong') {
      handleWsPong();
      return;
    }
    if (msg.type === 'answer' && firstPc) {
      answerReceived = true;
      clearTimeout(offerReadTimeout);
      await firstPc.setRemoteDescription({ type: 'answer', sdp: msg.sdp.sdp });
      // ICE may still be connecting; do NOT claim "WebRTC established" here.
      // The control channel opening is the real signal.
      setStatus('Signaling connected, establishing ICE…', 'connecting');
    } else if (msg.type === 'error') {
      clearTimeout(offerReadTimeout);
      showErrorBanner(`信令错误: ${msg.error}`, 'error');
      setStatus(`Signaling error: ${msg.error}`, 'error');
    }
  };

  // Wait for the WebSocket to be OPEN before sending the offer. Sending while
  // CONNECTING throws InvalidStateError in the browser and silently kills the
  // join (no offer -> no answer -> the node list never appears).
  const wsOpened = new Promise((resolve, reject) => {
    ws.onopen = () => {
      setStatus('Signaling connected, negotiating WebRTC…', 'connecting');
      ws.onclose = handleWsClose;
      ws.onerror = handleWsError;
      startWsHeartbeat();
      resolve();
    };
    ws.onerror = () => reject(new Error('WebSocket error'));
    ws.onclose = () => reject(new Error('WebSocket closed before connecting'));
  });

  return (async () => {
    try {
      await wsOpened;
      firstPc = createPc();
      controlChannel = openChannel(firstPc, 'control', onControlOpen, onControlMessage);
      const offer = await firstPc.createOffer();
      await firstPc.setLocalDescription(offer);
      ws.send(JSON.stringify({
        type: 'offer',
        session_id: sessionId,
        peer_id: peerId,
        name: 'browser',
        sdp: { type: 'offer', sdp: firstPc.localDescription.sdp },
      }));

      // Start read timeout: waiting for the gateway to respond with SDP answer
      clearTimeout(offerReadTimeout);
      offerReadTimeout = setTimeout(() => {
        if (!answerReceived && !joined) {
          showErrorBanner(
            '读超时：等待网关响应 answer 超时（服务端响应过慢或处理中）。网络已连通，但网关未及时返回信令应答，请稍后重试。',
            'read_timeout'
          );
          setStatus('网关读超时 (Server 响应慢)', 'error');
        }
      }, OFFER_READ_TIMEOUT_MS);

      // First-touch node ICE timeout: if the control DataChannel never opens,
      // tell the user what to do instead of hanging forever. Shown in the
      // dedicated banner so later status changes cannot cover it.
      clearTimeout(firstIceTimeout);
      firstIceTimeout = setTimeout(() => {
        if (!controlChannel || controlChannel.readyState !== 'open') {
          showErrorBanner(
            'WebRTC P2P 建连耗时过长（弱网高延迟或丢包）。若网络波动已恢复请点击“重试连接”，如处于对称 NAT 环境可配置 TURN 中继。',
            'ice_timeout'
          );
          setStatus('P2P 握手超时', 'error');
        }
      }, ICE_CONNECT_TIMEOUT_MS);
    } catch (e) {
      showErrorBanner(`连接网关失败: ${e.message}`, 'error');
      setStatus(`Failed to join the mesh: ${e.message}`, 'error');
    }
  })();
}

function handleWsClose() {
  stopWsHeartbeat();
  if (isHeartbeatTimeout) {
    // Already reported with heartbeat timeout guidance
    return;
  }
  if (joined) {
    // The signaling WebSocket only establishes the first-touch WebRTC session;
    // after hello_ack the mesh runs over DataChannels. A closed signaling
    // socket is not an error once we have joined.
    setStatus('Signaling closed — mesh active over WebRTC', 'connecting');
  } else {
    showErrorBanner(
      '信令连接已断开，请检查网络或点击“重试连接”。',
      'ws_close'
    );
    setStatus('信令已断开', 'error');
  }
}

function handleWsError() {
  stopWsHeartbeat();
  if (isHeartbeatTimeout) return;
  if (!joined) {
    showErrorBanner(
      '信令连接发生错误。网络可能中断或不可达。',
      'ws_error'
    );
    setStatus('信令错误', 'error');
  }
}

async function reconnect() {
  hideRetry();
  hideErrorBanner();
  clearTimeout(firstIceTimeout);
  clearTimeout(offerReadTimeout);
  stopWsHeartbeat();
  isHeartbeatTimeout = false;
  answerReceived = false;

  // Tear down the old signaling/session objects so joinMesh starts clean.
  if (ws) {
    ws.onclose = null;
    ws.onerror = null;
    try { ws.close(); } catch (e) { /* already closed */ }
  }
  if (firstPc) {
    try { firstPc.close(); } catch (e) { /* already closed */ }
  }
  firstPc = null;
  controlChannel = null;
  joined = false;
  sessionId = randomHex(16);

  for (const k of Object.keys(nodeChannels)) delete nodeChannels[k];
  for (const k of Object.keys(nodeState)) delete nodeState[k];
  for (const k of Object.keys(sshRoutes)) delete sshRoutes[k];
  currentSshSession = null;
  currentSshChannel = null;

  const nodesCard = $('nodes-card');
  if (nodesCard) nodesCard.hidden = true;
  const list = $('node-list');
  if (list) list.textContent = '';

  setStatus('Reconnecting…', 'connecting');
  await joinMesh();
}

function onControlOpen() {
  setStatus('WebRTC established', 'online');
  // ICE jitter recovered: the first-touch DataChannel is open, so any earlier
  // first-node ICE banner is stale and must disappear automatically.
  hideErrorBanner();
  sendJson(controlChannel, { type: 'hello', peer_id: peerId, name: 'browser' });
}

function onControlMessage(ev) {
  let msg;
  try {
    msg = JSON.parse(ev.data);
  } catch (e) {
    return;
  }
  switch (msg.type) {
    case 'hello_ack':
      // Only the first-touch node's hello_ack should render the node list and
      // trigger connections. Every other node also sends hello_ack; rendering
      // those caused the reconnect storm.
      if (msg.node_id === config.node_id) {
        joined = true;
        hideFirstNodeError();
        hideRetry();
        renderNodes(msg.node_list);
        setStatus(`Joined ${msg.node_name} (${msg.node_list.length} nodes)`, 'online');
      }
      break;
    case 'relay_answer':
      finishRelay(msg.target, msg.session_id, msg.sdp);
      break;
    case 'relay_error':
      setNodeConn(msg.target, `relay error: ${msg.error}`, false);
      if (nodeState[msg.target]) nodeState[msg.target].connecting = false;
      break;
    case 'ssh_open_ack':
      handleSshOpenAck(msg);
      break;
    case 'ssh_data':
      handleSshData(msg);
      break;
    case 'ssh_close':
      handleSshClose(msg);
      break;
  }
}

function renderNodes(nodeList) {
  const ul = $('node-list');
  ul.textContent = '';
  $('nodes-card').hidden = false;
  for (const node of nodeList) {
    const li = document.createElement('li');

    const info = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'node-name';
    name.textContent = node.name || node.peer_id;
    const meta = document.createElement('div');
    meta.className = 'node-meta';
    meta.textContent = `${node.peer_id.slice(0, 16)}…  ${(node.addrs || []).join(', ')}  services: ${(node.services || []).join(',')}`;
    info.append(name, meta);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '8px';
    actions.style.alignItems = 'center';

    const conn = document.createElement('span');
    conn.className = 'conn';
    conn.id = `conn-${node.peer_id}`;
    if (node.peer_id === config.node_id) {
      conn.textContent = 'connected (first node)';
      conn.classList.add('up');
      nodeState[node.peer_id] = { connected: true, connecting: false };
    } else {
      const st = nodeState[node.peer_id];
      if (st && st.connected) {
        conn.textContent = 'connected';
        conn.classList.add('up');
      } else if (st && st.connecting) {
        conn.textContent = 'connecting…';
      } else {
        conn.textContent = 'connecting…';
        nodeState[node.peer_id] = { connected: false, connecting: false };
        connectToNode(node);
      }
    }

    const btn = document.createElement('button');
    btn.textContent = 'Terminal';
    btn.onclick = () => showTerminal(node);
    actions.append(conn, btn);
    li.append(info, actions);
    ul.appendChild(li);
  }
}

function setNodeConn(peerId, text, up) {
  const el = $(`conn-${peerId}`);
  if (el) {
    el.textContent = text;
    el.classList.toggle('up', !!up);
  }
}

async function connectToNode(node) {
  const st = nodeState[node.peer_id];
  // Deduplicate: never start a second connection while one is in flight, and
  // never reconnect an already-connected node (reconnect storm fix).
  if (!st || st.connected || st.connecting) return;
  st.connecting = true;

  const pc = createPc();
  st.pc = pc;
  const ch = openChannel(pc, 'control', () => {
    st.connected = true;
    st.connecting = false;
    setNodeConn(node.peer_id, 'connected', true);
  }, (ev) => onControlMessage(ev));
  nodeChannels[node.peer_id] = ch;

  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendJson(controlChannel, {
      type: 'relay_offer',
      target: node.peer_id,
      session_id: sessionId,
      sdp: { type: 'offer', sdp: pc.localDescription.sdp },
    });
  } catch (e) {
    st.connecting = false;
    setNodeConn(node.peer_id, `offer failed: ${e.message}`);
  }

  // Direct connection timeout: if the DataChannel to this node does not open,
  // mark it as relay-only (terminals still work through the first node).
  setTimeout(() => {
    if (st.connecting && !st.connected) {
      st.connecting = false;
      setNodeConn(node.peer_id, 'direct failed — terminal uses relay', false);
    }
  }, 15000);
}

async function finishRelay(target, sid, sdp) {
  const state = nodeState[target];
  if (!state || !state.pc) return;
  try {
    await state.pc.setRemoteDescription({ type: 'answer', sdp: sdp.sdp });
  } catch (e) {
    state.connecting = false;
    setNodeConn(target, `answer failed: ${e.message}`);
  }
}

/* ---------------- SSH terminal ---------------- */

function showTerminal(node) {
  termNode = node;
  clearTerminalError();
  $('terminal-card').hidden = false;
  $('terminal-node').textContent = `${node.name || node.peer_id}`;
  $('auth-form').hidden = false;
  $('terminal-container').hidden = true;
}

function channelFor(node) {
  if (node.peer_id === config.node_id) return controlChannel;
  const direct = nodeChannels[node.peer_id];
  if (direct && direct.readyState === 'open') return direct;
  // No direct DataChannel to this node (hole punching failed): relay the
  // terminal through the first-touch node's control channel over the mesh.
  return controlChannel;
}

function handleSshOpenAck(msg) {
  const route = sshRoutes[msg.session_id];
  if (msg.status !== 'ok') {
    setTerminalError(`SSH open failed: ${msg.error || 'unknown error'}`);
    delete sshRoutes[msg.session_id];
    return;
  }
  currentSshSession = msg.session_id;
  $('auth-form').hidden = true;
  $('terminal-container').hidden = false;
  clearTerminalError();
  if (!term) {
    term = new Terminal({ cursorBlink: true, fontSize: 13 });
    termFit = new FitAddon.FitAddon();
    term.loadAddon(termFit);
    term.open($('terminal-container'));
    termFit.fit();
    term.onData((data) => {
      // Terminal bytes always go over the route the session was opened on.
      const ch = currentSshChannel || channelFor(termNode);
      if (!ch || ch.readyState !== 'open') {
        term.write('\r\n\x1b[31m[connection lost: DataChannel to the node is not open]\x1b[0m\r\n');
        return;
      }
      sendJson(ch, {
        type: 'ssh_data',
        session_id: currentSshSession,
        data: b64encode(new TextEncoder().encode(data)),
      });
    });
  } else {
    term.reset();
  }
}

function handleSshData(msg) {
  if (term) {
    term.write(new TextDecoder().decode(b64decode(msg.data)));
  }
}

function handleSshClose(msg) {
  if (term) {
    term.write(`\r\n\x1b[31m[connection closed: ${msg.reason}]\x1b[0m\r\n`);
  }
  delete sshRoutes[msg.session_id];
  if (msg.session_id === currentSshSession) {
    currentSshSession = null;
    currentSshChannel = null;
  }
}

$('ssh-connect').onclick = () => {
  const node = termNode;
  if (!node) return;
  clearTerminalError();
  const ch = channelFor(node);
  if (!ch || ch.readyState !== 'open') {
    setTerminalError('DataChannel to this node is not open yet');
    return;
  }
  const user = $('ssh-user').value.trim();
  const authRaw = $('ssh-auth').value;
  let auth;
  if (authRaw.includes('PRIVATE KEY')) {
    auth = { type: 'key', username: user, private_key: authRaw };
  } else {
    auth = { type: 'password', username: user, password: authRaw };
  }
  const sid = randomHex(16);
  // Bind the session to this channel: all subsequent terminal bytes for this
  // session go through the same route (direct or relay), never switching.
  sshRoutes[sid] = { channel: ch, node };
  currentSshChannel = ch;
  sendJson(ch, {
    type: 'ssh_open',
    session_id: sid,
    target: node.peer_id,
    auth,
  });
};

if ($('retry-btn')) $('retry-btn').onclick = () => reconnect();
if ($('banner-retry-btn')) $('banner-retry-btn').onclick = () => reconnect();
if ($('error-close-btn')) $('error-close-btn').onclick = () => hideErrorBanner();
if ($('banner-back-btn')) $('banner-back-btn').onclick = () => {
  hideErrorBanner();
  const termCard = $('terminal-card');
  if (termCard) termCard.hidden = true;
  const nodesCard = $('nodes-card');
  if (nodesCard) nodesCard.hidden = false;
};

init();
