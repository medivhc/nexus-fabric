'use strict';

/* Nexus Web Gateway browser client (MVP).
 *
 * - Generates an in-memory temporary identity (random 32-byte peer id).
 * - Joins the first-touch node via WSS signaling + RTCPeerConnection.
 * - Receives the mesh node list over the control DataChannel.
 * - Connects to every other node by relaying SDP offers through the
 *   established mesh (no external signaling service).
 * - Opens an SSH terminal: DataChannel -> target node -> local sshd.
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
const sessionId = randomHex(16);
let config = null;
let ws = null;
let firstPc = null;
let controlChannel = null; // DataChannel to the first-touch node
const nodeChannels = {};   // peer_id -> RTCDataChannel
const nodeState = {};      // peer_id -> { connected, pc }
const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];

let termNode = null;
let term = null;
let termFit = null;
let currentSshSession = null;

$('peer-id').textContent = `peer: ${peerId}`;

function setStatus(text, cls) {
  const el = $('status');
  el.textContent = text;
  el.className = `status ${cls || ''}`;
}

function createPc() {
  const pc = new RTCPeerConnection({ iceServers });
  pc.oniceconnectionstatechange = () => {
    console.log('ice state', pc.iceConnectionState);
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

  ws = new WebSocket(`wss://${location.host}/ws`);
  ws.onopen = () => setStatus('Signaling connected, negotiating WebRTC…', 'connecting');

  ws.onmessage = async (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === 'answer' && firstPc) {
      await firstPc.setRemoteDescription({ type: 'answer', sdp: msg.sdp.sdp });
      setStatus('WebRTC established', 'connecting');
    } else if (msg.type === 'error') {
      setStatus(`Signaling error: ${msg.error}`, 'error');
    }
  };

  ws.onclose = () => setStatus('Signaling closed', 'error');
  ws.onerror = () => setStatus('Signaling error', 'error');

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
}

function onControlOpen() {
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
      renderNodes(msg.node_list);
      setStatus(`Joined ${msg.node_name} (${msg.node_list.length} nodes)`, 'online');
      break;
    case 'relay_answer':
      finishRelay(msg.target, msg.session_id, msg.sdp);
      break;
    case 'relay_error':
      setNodeConn(msg.target, `relay error: ${msg.error}`);
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
      nodeState[node.peer_id] = { connected: true };
    } else {
      conn.textContent = 'connecting…';
      nodeState[node.peer_id] = { connected: false };
      connectToNode(node);
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
  const pc = createPc();
  nodeState[node.peer_id].pc = pc;
  const ch = openChannel(pc, 'control', () => {
    nodeState[node.peer_id].connected = true;
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
    setNodeConn(node.peer_id, `offer failed: ${e.message}`);
  }
}

async function finishRelay(target, sid, sdp) {
  const state = nodeState[target];
  if (!state || !state.pc) return;
  try {
    await state.pc.setRemoteDescription({ type: 'answer', sdp: sdp.sdp });
  } catch (e) {
    setNodeConn(target, `answer failed: ${e.message}`);
  }
}

/* ---------------- SSH terminal ---------------- */

function showTerminal(node) {
  termNode = node;
  $('terminal-card').hidden = false;
  $('terminal-node').textContent = `${node.name || node.peer_id}`;
  $('auth-form').hidden = false;
  $('terminal-container').hidden = true;
}

function channelFor(node) {
  if (node.peer_id === config.node_id) return controlChannel;
  return nodeChannels[node.peer_id];
}

function handleSshOpenAck(msg) {
  if (msg.status !== 'ok') {
    alert(`SSH open failed: ${msg.error || 'unknown error'}`);
    return;
  }
  currentSshSession = msg.session_id;
  $('auth-form').hidden = true;
  $('terminal-container').hidden = false;
  if (!term) {
    term = new Terminal({ cursorBlink: true, fontSize: 13 });
    termFit = new FitAddon.FitAddon();
    term.loadAddon(termFit);
    term.open($('terminal-container'));
    termFit.fit();
    term.onData((data) => {
      const ch = channelFor(termNode);
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
}

$('ssh-connect').onclick = () => {
  const node = termNode;
  if (!node) return;
  const ch = channelFor(node);
  if (!ch || ch.readyState !== 'open') {
    alert('DataChannel to this node is not open yet');
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
  sendJson(ch, {
    type: 'ssh_open',
    session_id: randomHex(16),
    target: node.peer_id,
    auth,
  });
};

init();