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

/* REQ-002: Identity preference persistence (localStorage).
 * Only UI preferences are persisted (theme, SSH username).
 * Connection state (peerId, sessionId, WebRTC/SSH sessions) is intentionally
 * NOT persisted: after a page refresh the user must re-establish connections.
 */
const PREFS_KEY = 'nexus-web-gateway-prefs';
const DEFAULT_PREFS = { theme: 'dark', sshUser: 'root' };

function loadPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return { ...DEFAULT_PREFS };
    const parsed = JSON.parse(raw);
    return {
      theme: parsed.theme === 'light' ? 'light' : 'dark',
      sshUser: typeof parsed.sshUser === 'string' && parsed.sshUser ? parsed.sshUser : DEFAULT_PREFS.sshUser,
    };
  } catch (e) {
    return { ...DEFAULT_PREFS };
  }
}

function savePrefs(prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch (e) {
    /* storage unavailable: preferences just will not persist */
  }
}

const prefs = loadPrefs();

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('theme-toggle-btn');
  if (btn) btn.textContent = theme === 'dark' ? '\u2600' : '\u263E';
  if (btn) btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}

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
let isHeartbeatTimeout = false;// whether we are currently in a heartbeat-timeout state
let answerReceived = false;    // whether SDP answer has been received
let currentErrorKind = null;   // kind of the banner currently shown (if any)
let joinedName = null;         // node_name from hello_ack, used to restore status
let joinedCount = 0;           // node_list length from hello_ack, used to restore status

const WS_HEARTBEAT_INTERVAL_MS = 3000;
const WS_HEARTBEAT_TIMEOUT_MS = 5000;
const OFFER_READ_TIMEOUT_MS = 10000;
const ICE_CONNECT_TIMEOUT_MS = 15000;
// Binds an SSH session to the DataChannel route it was opened on, so terminal
// bytes never switch channels mid-session (which caused silent freezing when a
// direct channel to the target node late-connects).
const sshRoutes = {}; // session_id -> { channel, node }

/* ---------------- Files (REQ-005..REQ-008) ----------------
 * Frame layout on the binary channel: kind(1) | stream_id(4) | offset(8) |
 * flags(1) | payload. Reads are pull-based (the page asks for each offset), so
 * the gateway never blocks the event loop waiting for the browser to drain.
 */
const FILE_CHANNEL_LABEL = 'nexus.file';
const FRAME_READ_CHUNK = 0x01;
const FRAME_WRITE_CHUNK = 0x81;
const FRAME_HEADER_LEN = 14;
const FRAME_FLAG_FINAL = 0x01;
const FILE_WRITE_WINDOW = 2; // chunks in flight before waiting for an ack

let fileChannel = null;   // binary DataChannel to the first-touch node
let fileSession = null;   // { id, kind, root, chunkBytes, readOnly }
let fileNode = null;      // node the file panel is currently bound to
let fileStreamSeq = 1;
let fileBusy = false;     // one metadata/transfer operation at a time
const fileReads = new Map();  // stream_id -> { resolve, reject, timer }
const fileWaiters = [];       // { match, resolve, reject, timer }

// True once the first-touch node's hello_ack arrives. After that the mesh runs
// over WebRTC DataChannels, so a closed signaling WebSocket is no longer an
// error (the old unconditional "Signaling closed" banner was a false alarm that
// also covered the first-node ICE guidance).
let joined = false;

$('peer-id').textContent = `peer: ${peerId}`;

// REQ-002: restore persisted preferences (theme + SSH username)
applyTheme(prefs.theme);
(function restoreSshUser() {
  const el = $('ssh-user');
  if (el && prefs.sshUser) el.value = prefs.sshUser;
})();

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
      badgeEl.textContent = '网络波动';
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
  currentErrorKind = kind || 'error';
  showRetry();
}

function hideErrorBanner() {
  const el = $('first-node-error');
  if (el) el.hidden = true;
  currentErrorKind = null;
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
      if (!isHeartbeatTimeout) {
        isHeartbeatTimeout = true;
        showErrorBanner(
          '信令心跳暂时未收到响应（可能网络波动）。若数据通道仍正常，网络恢复后本提示会自动消失。',
          'heartbeat_timeout'
        );
        setStatus('信令心跳超时 (网络波动)', 'error');
      }
      // Do NOT close the WebSocket here: a brief stall (Wi-Fi roam, VPN
      // jitter, suspend/resume) can exceed the timeout while the underlying
      // connection is still alive. Closing the socket would make the error
      // permanent; keeping it open lets the next pong clear the banner.
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
  if (isHeartbeatTimeout) {
    // The gateway answered again: the stall is over, clear the stale banner
    // and restore whatever the real connection state is.
    isHeartbeatTimeout = false;
    restoreHealthyStatus();
  }
}

// Single source of truth for status/banner after a recovery event (pong
// resumed, ICE reconnected, control channel opened, hello_ack arrived, or the
// user dismissed the banner). Reflects the real current connection state and
// clears stale errors instead of leaving a permanent "error" on the page.
function restoreHealthyStatus() {
  if (firstPc && (firstPc.iceConnectionState === 'failed' || firstPc.iceConnectionState === 'disconnected')) {
    setStatus('P2P ICE 失败', 'error');
    return;
  }
  if (isHeartbeatTimeout) {
    setStatus('信令心跳超时 (网络波动)', 'error');
    return;
  }
  hideErrorBanner();
  hideRetry();
  if (joined) {
    setStatus(`Joined ${joinedName} (${joinedCount} nodes)`, 'online');
  } else if (controlChannel && controlChannel.readyState === 'open') {
    setStatus('WebRTC established', 'online');
  } else if (answerReceived) {
    setStatus('Signaling connected, establishing ICE…', 'connecting');
  } else {
    setStatus('Signaling connected, negotiating WebRTC…', 'connecting');
  }
}

function createPc() {
  const pc = new RTCPeerConnection({ iceServers });
  pc.oniceconnectionstatechange = () => {
    console.log('ice state', pc.iceConnectionState);
    if (pc !== firstPc) return;
    if (pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') {
      // First-touch node: if ICE ultimately fails, surface an actionable error
      // in its own banner (never overwritten by later status changes) instead
      // of leaving the page stuck on "WebRTC established".
      showErrorBanner(
        'WebRTC ICE 握手失败。可能处于严格对称 NAT 环境，建议检查 TURN 服务器配置或尝试其他节点。',
        'ice_failed'
      );
      setStatus('P2P ICE 失败', 'error');
    } else if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
      // The data plane is back: any heartbeat/ICE error banner is stale and
      // must disappear automatically.
      isHeartbeatTimeout = false;
      restoreHealthyStatus();
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
  // The file panel only offers targets this node actually exposes.
  renderFileTargets();
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
      restoreHealthyStatus();
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
      // The binary file channel must be offered in the *same* SDP as the
      // control channel: the gateway rejects re-offers (no renegotiation).
      fileChannel = openFileChannel(firstPc);
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
  joinedName = null;
  joinedCount = 0;
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
  // The first-touch DataChannel is open: any earlier first-node ICE banner is
  // stale and must disappear automatically.
  restoreHealthyStatus();
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
        joinedName = msg.node_name;
        joinedCount = msg.node_list.length;
        renderNodes(msg.node_list);
        restoreHealthyStatus();
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
    case 'file_open_ack':
      handleFileOpenAck(msg);
      break;
    case 'file_closed':
      pumpFileWaiters(msg);
      handleFileClosed(msg);
      break;
    case 'file_list_ack':
    case 'file_stat_ack':
    case 'file_write_ack':
    case 'file_op_ack':
      pumpFileWaiters(msg);
      if (msg.type === 'file_op_ack' && msg.op === 'read' && !msg.ok) {
        rejectAllFileReads(msg.error || 'read failed');
      }
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
    const filesBtn = document.createElement('button');
    filesBtn.textContent = 'Files';
    filesBtn.onclick = () => showFiles(node);
    actions.append(conn, btn, filesBtn);
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
  const auth = sshAuthFromForm();
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
if ($('error-close-btn')) $('error-close-btn').onclick = () => {
  hideErrorBanner();
  // Closing the banner must also fix the header status: if the underlying
  // problem is still real (ICE failed / heartbeat missing) the status stays
  // red, otherwise it returns to the honest healthy state.
  restoreHealthyStatus();
};
if ($('banner-back-btn')) $('banner-back-btn').onclick = () => {
  hideErrorBanner();
  restoreHealthyStatus();
  const termCard = $('terminal-card');
  if (termCard) termCard.hidden = true;
  const nodesCard = $('nodes-card');
  if (nodesCard) nodesCard.hidden = false;
};

// REQ-002: theme toggle + persist SSH username on change
if ($('theme-toggle-btn')) $('theme-toggle-btn').onclick = () => {
  prefs.theme = prefs.theme === 'dark' ? 'light' : 'dark';
  savePrefs(prefs);
  applyTheme(prefs.theme);
};
if ($('ssh-user')) $('ssh-user').addEventListener('change', () => {
  const v = $('ssh-user').value.trim();
  if (v) {
    prefs.sshUser = v;
    savePrefs(prefs);
  }
});

init();
/* ---------------- Files (REQ-005..REQ-008) ---------------- */

/** Build the SSH credential payload from the terminal form (shared with SFTP).
 *  Credentials stay in memory only: they travel over the encrypted control
 *  channel and are never written to localStorage (G4). */
function sshAuthFromForm() {
  const username = $('ssh-user').value.trim();
  const raw = $('ssh-auth').value;
  if (raw.includes('PRIVATE KEY')) {
    return { type: 'key', username, private_key: raw };
  }
  return { type: 'password', username, password: raw };
}

function openFileChannel(pc) {
  const ch = pc.createDataChannel(FILE_CHANNEL_LABEL);
  ch.binaryType = 'arraybuffer';
  ch.onmessage = (ev) => onFileFrame(ev.data);
  ch.onclose = () => {
    if (fileSession) setFilesError('文件通道已关闭');
    resetFileSession();
  };
  return ch;
}

function encodeFileFrame(kind, streamId, offset, finalBlock, bytes) {
  const out = new Uint8Array(FRAME_HEADER_LEN + bytes.length);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, kind);
  dv.setUint32(1, streamId);
  // 64-bit big-endian offset, split by hand: `setUint64` is not part of the
  // language (no browser ships it), and offsets are exact below 2^53 anyway.
  dv.setUint32(5, Math.floor(offset / 0x100000000));
  dv.setUint32(9, offset % 0x100000000);
  dv.setUint8(13, finalBlock ? FRAME_FLAG_FINAL : 0);
  out.set(bytes, FRAME_HEADER_LEN);
  return out;
}

function decodeFileFrame(buffer) {
  if (!buffer || buffer.byteLength < FRAME_HEADER_LEN) return null;
  const dv = new DataView(buffer);
  return {
    kind: dv.getUint8(0),
    streamId: dv.getUint32(1),
    offset: dv.getUint32(5) * 0x100000000 + dv.getUint32(9),
    finalBlock: (dv.getUint8(13) & FRAME_FLAG_FINAL) !== 0,
    data: new Uint8Array(buffer, FRAME_HEADER_LEN),
  };
}

function onFileFrame(raw) {
  const frame = decodeFileFrame(raw);
  if (!frame || frame.kind !== FRAME_READ_CHUNK) return;
  const pending = fileReads.get(frame.streamId);
  if (!pending) return;
  fileReads.delete(frame.streamId);
  clearTimeout(pending.timer);
  pending.resolve(frame);
}

function rejectAllFileReads(message) {
  for (const entry of [...fileReads.entries()]) {
    const [id, pending] = entry;
    fileReads.delete(id);
    clearTimeout(pending.timer);
    pending.reject(new Error(message));
  }
}

/** Await the next control message satisfying `match`. Requests must register
 *  the waiter *before* sending, or a fast node can answer into the void. */
function waitForFile(match, ms, label) {
  let waiter = null;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const idx = fileWaiters.indexOf(waiter);
      if (idx >= 0) fileWaiters.splice(idx, 1);
      reject(new Error(`等待${label}超时（${ms}ms）`));
    }, ms);
    waiter = {
      match,
      resolve: (msg) => resolve(msg),
      reject,
      timer,
    };
    fileWaiters.push(waiter);
  });
}

function pumpFileWaiters(msg) {
  for (let i = fileWaiters.length - 1; i >= 0; i -= 1) {
    const w = fileWaiters[i];
    let hit = false;
    try {
      hit = !!w.match(msg);
    } catch (e) {
      hit = false;
    }
    if (!hit) continue;
    clearTimeout(w.timer);
    fileWaiters.splice(i, 1);
    w.resolve(msg);
  }
}

function fileCapability() {
  return (config && config.files) || { enabled: false, roots: [], chunk_bytes: 65536 };
}

function renderFileTargets() {
  const sel = $('files-target');
  if (!sel) return;
  const cap = fileCapability();
  sel.textContent = '';
  if (!cap.enabled) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '文件模块未启用（files.enabled）';
    sel.append(opt);
    sel.disabled = true;
    $('files-open').disabled = true;
    return;
  }
  sel.disabled = false;
  $('files-open').disabled = false;
  const sftp = document.createElement('option');
  sftp.value = 'sftp';
  sftp.textContent = '目标主机 SFTP（复用上方 SSH 凭据）';
  sel.append(sftp);
  for (const root of cap.roots || []) {
    const opt = document.createElement('option');
    opt.value = `local:${root.name}`;
    opt.textContent = `节点本地目录 ${root.name}${root.read_only ? '（只读）' : ''}`;
    sel.append(opt);
  }
}

function currentTargetSpec() {
  const value = $('files-target').value;
  if (value.startsWith('local:')) {
    return { kind: 'local', root: value.slice('local:'.length) };
  }
  return { kind: 'sftp', auth: sshAuthFromForm() };
}

function currentTargetReadOnly() {
  const value = $('files-target').value;
  if (!value.startsWith('local:')) return false;
  const name = value.slice('local:'.length);
  const root = (fileCapability().roots || []).find((r) => r.name === name);
  return !!(root && root.read_only);
}

function setFilesError(text) {
  const el = $('files-error');
  if (!el) return;
  el.textContent = text || '';
  el.hidden = !text;
}

function showFiles(node) {
  fileNode = node;
  $('files-card').hidden = false;
  $('files-node').textContent = `· ${node.name || node.peer_id.slice(0, 16)}…`;
  setFilesError('');
  // A file session is bound to the node that hosts it; switching nodes means
  // opening a new session.
  if (fileSession && node && fileSession.nodeId !== node.peer_id) resetFileSession();
  renderFileTargets();
  $('files-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function resetFileSession() {
  fileSession = null;
  for (const w of fileWaiters.splice(0)) clearTimeout(w.timer);
  rejectAllFileReads('文件会话已关闭');
  const label = $('files-session');
  if (label) label.textContent = '未连接';
  for (const id of ['files-refresh', 'files-mkdir', 'files-upload']) {
    if ($(id)) $(id).disabled = true;
  }
  hideProgress();
}

function handleFileOpenAck(msg) {
  pumpFileWaiters(msg);
  if (msg.status !== 'ok') return;
  fileSession = {
    id: msg.session_id,
    nodeId: fileNode ? fileNode.peer_id : (config ? config.node_id : ''),
    kind: msg.kind,
    chunkBytes: msg.chunk_bytes || 65536,
    readOnly: currentTargetReadOnly(),
  };
  $('files-session').textContent =
    `已连接 ${msg.kind} · 分块 ${msg.chunk_bytes} B${fileSession.readOnly ? ' · 只读' : ''}`;
  $('files-refresh').disabled = false;
  $('files-mkdir').disabled = fileSession.readOnly;
  $('files-upload').disabled = fileSession.readOnly;
  fileLs($('files-path').value || '/').catch((e) => setFilesError(e.message));
}

function handleFileClosed(msg) {
  if (fileSession && msg.session_id === fileSession.id) {
    setFilesError(`文件会话已关闭：${msg.reason}`);
    resetFileSession();
  }
}

async function fileOpen() {
  setFilesError('');
  if (!controlChannel || controlChannel.readyState !== 'open') {
    setFilesError('控制通道未打开，无法建立文件会话');
    return;
  }
  if (!fileChannel || fileChannel.readyState !== 'open') {
    setFilesError('文件二进制通道尚未打开（等待 ICE 连通）');
    return;
  }
  if (fileSession) {
    await fileCloseSession().catch(() => {});
  }
  const id = randomHex(8);
  const wait = waitForFile(
    (m) => m.type === 'file_open_ack' && m.session_id === id,
    25000,
    '文件会话应答'
  );
  sendJson(controlChannel, {
    type: 'file_open',
    session_id: id,
    token: $('files-token').value,
    target: currentTargetSpec(),
  });
  const ack = await wait;
  if (ack.status !== 'ok') throw new Error(ack.error || '文件会话建立失败');
  // handleFileOpenAck already applied the ack; make the path absolute again.
  $('files-path').value = '/';
}

async function fileCloseSession() {
  if (!fileSession) return;
  const id = fileSession.id;
  const wait = waitForFile(
    (m) => m.type === 'file_closed' && m.session_id === id,
    10000,
    '文件会话关闭'
  ).catch(() => null);
  sendJson(controlChannel, { type: 'file_close', session_id: id });
  await wait;
  resetFileSession();
}

async function fileLs(path) {
  if (!fileSession) throw new Error('未连接文件会话');
  const wait = waitForFile(
    (m) =>
      m.type === 'file_list_ack' && m.session_id === fileSession.id && m.path === path,
    20000,
    '目录列表'
  );
  sendJson(controlChannel, { type: 'file_list', session_id: fileSession.id, path });
  const ack = await wait;
  if (ack.error) throw new Error(ack.error);
  $('files-path').value = ack.path;
  renderFileRows(ack.entries || []);
}

function fmtSize(bytes) {
  if (!bytes && bytes !== 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1048576).toFixed(1)} MiB`;
  return `${(bytes / 1073741824).toFixed(2)} GiB`;
}

function fmtTime(secs) {
  if (!secs) return '-';
  const d = new Date(secs * 1000);
  return d.toLocaleString();
}

function fmtMode(entry) {
  if (!entry.mode && entry.mode !== 0) return '-';
  const bits = (entry.mode & 0o777).toString(8).padStart(3, '0');
  return `${entry.kind === 'dir' ? 'd' : entry.kind === 'symlink' ? 'l' : '-'}${bits}`;
}

function joinPath(dir, name) {
  const base = !dir || dir === '/' ? '' : dir.replace(/\/+$/, '');
  return `${base}/${name}`;
}

function parentPath(path) {
  const parts = (path || '/').split('/').filter((p) => p && p !== '.');
  parts.pop();
  return parts.length ? `/${parts.join('/')}` : '/';
}

function renderFileRows(entries) {
  const body = $('files-body');
  body.textContent = '';
  const path = $('files-path').value || '/';
  if (path !== '/') {
    const up = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    const link = document.createElement('a');
    link.href = '#';
    link.textContent = '../ （返回上级）';
    link.onclick = (ev) => {
      ev.preventDefault();
      fileLs(parentPath(path)).catch((e) => setFilesError(e.message));
    };
    td.append(link);
    up.append(td);
    body.append(up);
  }
  if (!entries.length) {
    const tr = document.createElement('tr');
    tr.className = 'files-empty';
    const td = document.createElement('td');
    td.colSpan = 5;
    td.textContent = '空目录';
    tr.append(td);
    body.append(tr);
    return;
  }
  for (const entry of entries) body.append(fileRow(entry));
}

function fileRow(entry) {
  const tr = document.createElement('tr');

  const nameCell = document.createElement('td');
  if (entry.kind === 'dir') {
    const link = document.createElement('a');
    link.href = '#';
    link.textContent = entry.name;
    link.onclick = (ev) => {
      ev.preventDefault();
      fileLs(entry.path).catch((e) => setFilesError(e.message));
    };
    nameCell.append(link);
  } else {
    nameCell.textContent = entry.name;
    nameCell.title = entry.path;
  }

  const sizeCell = document.createElement('td');
  sizeCell.className = 'mono';
  sizeCell.textContent = entry.kind === 'dir' ? '-' : fmtSize(entry.size);

  const timeCell = document.createElement('td');
  timeCell.className = 'mono';
  timeCell.textContent = fmtTime(entry.mtime);

  const modeCell = document.createElement('td');
  modeCell.className = 'mono';
  modeCell.textContent = fmtMode(entry);

  const actions = document.createElement('td');
  actions.className = 'files-actions';
  if (entry.kind === 'file') {
    const dl = document.createElement('button');
    dl.textContent = '下载';
    dl.onclick = () => fileDownload(entry).catch((e) => setFilesError(e.message));
    actions.append(dl);
  }
  if (!fileSession || !fileSession.readOnly) {
    if (entry.kind !== 'dir') {
      const rn = document.createElement('button');
      rn.textContent = '重命名';
      rn.onclick = () => fileRename(entry).catch((e) => setFilesError(e.message));
      actions.append(rn);
    }
    const rm = document.createElement('button');
    rm.textContent = '删除';
    rm.className = 'files-danger';
    rm.onclick = () => fileRemove(entry).catch((e) => setFilesError(e.message));
    actions.append(rm);
  }

  tr.append(nameCell, sizeCell, timeCell, modeCell, actions);
  return tr;
}

function fileReadChunk(path, offset, len) {
  if (!fileSession) return Promise.reject(new Error('未连接文件会话'));
  const streamId = fileStreamSeq++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      fileReads.delete(streamId);
      reject(new Error('读取分片超时'));
    }, 30000);
    fileReads.set(streamId, { resolve, reject, timer });
    sendJson(controlChannel, {
      type: 'file_read',
      session_id: fileSession.id,
      stream_id: streamId,
      path,
      offset,
      len,
    });
  });
}

async function fileDownload(entry) {
  if (!fileSession) throw new Error('未连接文件会话');
  if (fileBusy) throw new Error('另一个文件操作正在进行');
  fileBusy = true;
  const parts = [];
  let offset = 0;
  try {
    showProgress(entry.size ? 0 : 1, `下载 ${entry.name} …`);
    for (;;) {
      const frame = await fileReadChunk(entry.path, offset, fileSession.chunkBytes);
      if (frame.offset !== offset) {
        throw new Error(`分片位置异常：请求 ${offset} 收到 ${frame.offset}`);
      }
      parts.push(frame.data);
      offset += frame.data.length;
      setProgress(
        entry.size ? offset / entry.size : 1,
        `下载 ${entry.name} ${fmtSize(offset)}${entry.size ? `/${fmtSize(entry.size)}` : ''}`
      );
      if (frame.finalBlock || frame.data.length === 0) break;
    }
    const blob = new Blob(parts);
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = entry.name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    hideProgress();
  } finally {
    fileBusy = false;
  }
}

/** Upload one file. Chunks go out on the binary channel with at most
 *  FILE_WRITE_WINDOW in flight; the node acks the contiguous front, which is
 *  also the resume point after a reconnect. */
async function fileUploadOne(file, dir) {
  if (!fileSession) throw new Error('未连接文件会话');
  if (!fileChannel || fileChannel.readyState !== 'open') {
    throw new Error('文件通道已关闭');
  }
  const target = joinPath(dir, file.name);
  const streamId = fileStreamSeq++;
  const begin = waitForFile(
    (m) => m.type === 'file_write_ack' && m.stream_id === streamId,
    20000,
    '开始上传'
  );
  sendJson(controlChannel, {
    type: 'file_write_begin',
    session_id: fileSession.id,
    stream_id: streamId,
    path: target,
  });
  const ack0 = await begin;
  if (ack0.error) throw new Error(ack0.error);

  const chunkBytes = fileSession.chunkBytes;
  let sent = ack0.received || 0;
  let acked = ack0.received || 0;
  showProgress(file.size ? 0 : 1, `上传 ${file.name} 0/${fmtSize(file.size)}`);
  while (acked < file.size) {
    if (sent < file.size && sent - acked < chunkBytes * FILE_WRITE_WINDOW) {
      const len = Math.min(chunkBytes, file.size - sent);
      const buf = new Uint8Array(await file.slice(sent, sent + len).arrayBuffer());
      if (!fileChannel || fileChannel.readyState === 'closed') {
        throw new Error('文件通道已关闭，可重新连接后从已确认位置续传');
      }
      fileChannel.send(encodeFileFrame(FRAME_WRITE_CHUNK, streamId, sent, false, buf));
      sent += len;
      continue;
    }
    const wait = waitForFile(
      (m) => m.type === 'file_write_ack' && m.stream_id === streamId,
      60000,
      '上传确认'
    );
    const ack = await wait;
    if (ack.error) throw new Error(ack.error);
    if (ack.received > acked) {
      acked = ack.received;
      setProgress(
        file.size ? acked / file.size : 1,
        `上传 ${file.name} ${fmtSize(acked)}/${fmtSize(file.size)}`
      );
    }
  }

  const done = waitForFile(
    (m) => m.type === 'file_op_ack' && m.op === 'write_end' && m.path === target,
    30000,
    '提交上传'
  );
  sendJson(controlChannel, {
    type: 'file_write_end',
    session_id: fileSession.id,
    stream_id: streamId,
    path: target,
  });
  const ack = await done;
  if (!ack.ok) throw new Error(ack.error || '提交上传失败');
}

async function fileUploadSelected(files) {
  if (fileBusy) throw new Error('另一个文件操作正在进行');
  fileBusy = true;
  const dir = $('files-path').value || '/';
  const failures = [];
  try {
    for (const file of files) {
      try {
        await fileUploadOne(file, dir);
      } catch (e) {
        failures.push(`${file.name}: ${e.message}`);
      }
    }
  } finally {
    fileBusy = false;
    hideProgress();
  }
  await fileLs(dir).catch(() => {});
  if (failures.length) throw new Error(failures.join('；'));
}

async function fileSimpleOp(type, payload, op, label) {
  if (!fileSession) throw new Error('未连接文件会话');
  const wait = waitForFile(
    (m) => m.type === 'file_op_ack' && m.op === op,
    20000,
    label
  );
  sendJson(controlChannel, {
    type,
    session_id: fileSession.id,
    ...payload,
  });
  const ack = await wait;
  if (!ack.ok) throw new Error(ack.error || `${label}失败`);
  return ack;
}

async function fileMkdir() {
  const name = window.prompt('新建目录名（相对当前目录）');
  if (!name) return;
  const dir = $('files-path').value || '/';
  await fileSimpleOp('file_mkdir', { path: joinPath(dir, name) }, 'mkdir', '新建目录');
  await fileLs(dir);
}

async function fileRename(entry) {
  const name = window.prompt('新的名称', entry.name);
  if (!name || name === entry.name) return;
  const dir = parentPath(entry.path);
  await fileSimpleOp(
    'file_rename',
    { from: entry.path, to: joinPath(dir, name) },
    'rename',
    '重命名'
  );
  await fileLs(dir);
}

async function fileRemove(entry) {
  const recursive = entry.kind === 'dir';
  const hint = recursive ? '（目录及其内容）' : '';
  if (!window.confirm(`确认删除 ${entry.name}${hint}？此操作不可恢复。`)) return;
  const dir = parentPath(entry.path);
  await fileSimpleOp('file_remove', { path: entry.path, recursive }, 'remove', '删除');
  await fileLs(dir);
}

function showProgress(frac, text) {
  $('files-progress').hidden = false;
  setProgress(frac, text);
}

function setProgress(frac, text) {
  const clamped = Math.max(0, Math.min(1, frac || 0));
  $('files-progress-fill').style.width = `${Math.round(clamped * 100)}%`;
  $('files-progress-text').textContent = text || '';
}

function hideProgress() {
  const el = $('files-progress');
  if (el) el.hidden = true;
}

$('files-open').onclick = () => fileOpen().catch((e) => setFilesError(e.message));
$('files-refresh').onclick = () =>
  fileLs($('files-path').value || '/').catch((e) => setFilesError(e.message));
$('files-mkdir').onclick = () => fileMkdir().catch((e) => setFilesError(e.message));
$('files-upload').onclick = () => $('files-upload-input').click();
$('files-upload-input').onchange = (ev) => {
  const files = [...((ev.target && ev.target.files) || [])];
  ev.target.value = '';
  if (!files.length) return;
  fileUploadSelected(files).catch((e) => setFilesError(e.message));
};
$('files-path').addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') {
    ev.preventDefault();
    fileLs($('files-path').value || '/').catch((e) => setFilesError(e.message));
  }
});
renderFileTargets();
