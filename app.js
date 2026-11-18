// PTP Share viewer: finds the host through public Nostr relays (encrypted,
// ephemeral messages) and then receives the stream directly over WebRTC.
import { schnorr } from './vendor/schnorr.js';

const KIND = 25050;
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
  'wss://nostr.mom',
];
const HELLO_INTERVAL_MS = 3000;
// Tolerated clock difference with the host (seconds). Relays apply `since`
// to live events too, so a tight window drops messages from skewed clocks.
const CLOCK_SKEW_SECS = 60;

const $ = (id) => document.getElementById(id);
const stage = $('stage');
const video = $('video');
const enc = new TextEncoder();
const dec = new TextDecoder();

// ───────────────────────── helpers ─────────────────────────

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromB64Url = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};
const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function setStatus(title, detail, { spinner = true, retry = false } = {}) {
  $('status-title').textContent = title;
  $('status-detail').textContent = detail;
  $('spinner').classList.toggle('hidden', !spinner);
  $('retry').hidden = !retry;
}

function browserLabel() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac/.test(ua) ? 'macOS'
    : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}

// ───────────────────────── room ─────────────────────────

function parseLink() {
  const params = new URLSearchParams(location.hash.slice(1));
  const k = params.get('k');
  if (!k) return null;
  const secret = fromB64Url(k);
  if (secret.length !== 32) return null;
  const relays = params.get('r')
    ? params.get('r').split(',').map((r) => decodeURIComponent(r)).filter(Boolean)
    : DEFAULT_RELAYS;
  return { secret, relays };
}

async function deriveRoom(secret) {
  const topic = hex(await sha256(concat(enc.encode('ptp-share/topic/v1'), secret)));
  const keyBytes = await sha256(concat(enc.encode('ptp-share/key/v1'), secret));
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { topic, key };
}

async function encrypt(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))));
  return toB64(concat(iv, ct));
}

async function decrypt(key, content) {
  const raw = fromB64(content);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
  return JSON.parse(dec.decode(pt));
}

// ───────────────────────── nostr ─────────────────────────

// Browsers answer Opus without `stereo=1`, and Chrome then decodes the
// host's stereo stream as mono. Ask for stereo and full-band bitrate.
function enableStereoOpus(sdp) {
  const m = sdp.match(/^a=rtpmap:(\d+) opus\/48000\/2(?=\r?\n|$)/m);
  if (!m) return sdp;
  const pt = m[1];
  const extra = { stereo: '1', 'sprop-stereo': '1', maxaveragebitrate: '510000' };
  const re = new RegExp(`^a=fmtp:${pt} ([^\\r\\n]*)`, 'm');
  if (!re.test(sdp)) return sdp.replace(m[0], `${m[0]}\r\na=fmtp:${pt} stereo=1;sprop-stereo=1;maxaveragebitrate=510000`);
  return sdp.replace(re, (line, params) => {
    const kv = new Map(params.split(';').filter(Boolean).map((p) => p.trim().split('=')));
    for (const [k, v] of Object.entries(extra)) kv.set(k, v);
    return `a=fmtp:${pt} ${[...kv].map(([k, v]) => `${k}=${v}`).join(';')}`;
  });
}

class Relays {
  constructor(urls, filter, onEvent) {
    this.urls = urls;
    this.filter = filter;
    this.onEvent = onEvent;
    this.sockets = new Map();
    this.seen = new Set();
    this.closed = false;
    this.onOpen = () => {};
    urls.forEach((u) => this.connect(u, 1000));
  }

  get openCount() {
    let n = 0;
    for (const ws of this.sockets.values()) if (ws.readyState === WebSocket.OPEN) n++;
    return n;
  }

  connect(url, backoff) {
    if (this.closed) return;
    let ws;
    try { ws = new WebSocket(url); } catch { return; }
    this.sockets.set(url, ws);
    ws.onopen = () => {
      backoff = 1000;
      const filter = { ...this.filter, since: Math.floor(Date.now() / 1000) - CLOCK_SKEW_SECS };
      ws.send(JSON.stringify(['REQ', 'ptp', filter]));
      this.onOpen(url);
    };
    ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (msg[0] === 'EVENT' && msg[2]) {
        const ev = msg[2];
        if (this.seen.has(ev.id)) return;
        this.seen.add(ev.id);
        this.onEvent(ev);
      } else if (msg[0] === 'OK' && msg[2] === false) {
        console.warn(`[${url}] rejected:`, msg[3]);
      } else if (msg[0] === 'NOTICE' || msg[0] === 'CLOSED') {
        console.warn(`[${url}]`, msg);
      }
    };
    ws.onclose = () => {
      if (this.closed) return;
      setTimeout(() => this.connect(url, Math.min(backoff * 2, 30000)), backoff);
    };
    ws.onerror = () => {};
  }

  publish(event) {
    const frame = JSON.stringify(['EVENT', event]);
    for (const ws of this.sockets.values()) if (ws.readyState === WebSocket.OPEN) ws.send(frame);
  }

  close() {
    this.closed = true;
    for (const ws of this.sockets.values()) ws.close();
  }
}

function signEvent(sk, pk, tags, content) {
  const created_at = Math.floor(Date.now() / 1000);
  const serialized = JSON.stringify([0, pk, created_at, KIND, tags, content]);
  return crypto.subtle.digest('SHA-256', enc.encode(serialized)).then((d) => {
    const id = new Uint8Array(d);
    const sig = schnorr.sign(id, sk);
    return { id: hex(id), pubkey: pk, created_at, kind: KIND, tags, content, sig: hex(sig) };
  });
}

// ───────────────────────── session ─────────────────────────

let session = null;

async function start() {
  const link = parseLink();
  if (!link) {
    setStatus('No room link', 'Open the link your friend shared with you — it ends with #k=…', { spinner: false });
    return;
  }
  if (session) session.close();
  session = new ViewerSession(link);
  await session.run();
}

class ViewerSession {
  constructor(link) {
    this.link = link;
    this.sid = hex(crypto.getRandomValues(new Uint8Array(8)));
    this.sk = schnorr.utils.randomPrivateKey();
    this.pk = hex(schnorr.getPublicKey(this.sk));
    this.pc = null;
    this.answer = null;
    this.gotOffer = false;
    this.closed = false;
    this.hostPubkey = null;
  }

  async run() {
    setStatus('Connecting…', 'Looking for the host on the signaling relays.');
    const { topic, key } = await deriveRoom(this.link.secret);
    this.topic = topic;
    this.key = key;
    this.relays = new Relays(
      this.link.relays,
      { kinds: [KIND], '#t': [topic], '#p': [this.pk] },
      (ev) => this.onEvent(ev),
    );
    this.relays.onOpen = () => { if (!this.gotOffer) this.sendHello(); };
    window.addEventListener('pagehide', () => this.sendBye());

    const startedAt = Date.now();
    while (!this.closed && !this.gotOffer) {
      await sleep(HELLO_INTERVAL_MS);
      if (this.closed || this.gotOffer) break;
      if (this.relays.openCount === 0) {
        setStatus('Connecting…', 'Can’t reach any signaling relay yet. Check your internet connection.');
        continue;
      }
      if (Date.now() - startedAt > 15000) {
        setStatus('Waiting for the host…', 'The host doesn’t seem to be live yet. This page will connect automatically when they start.');
      }
      this.sendHello();
    }
  }

  async send(msg) {
    if (!this.relays) return;
    const content = await encrypt(this.key, msg);
    const tags = [['t', this.topic]];
    if (this.hostPubkey) tags.push(['p', this.hostPubkey]);
    this.relays.publish(await signEvent(this.sk, this.pk, tags, content));
  }

  sendHello() { this.send({ type: 'hello', sid: this.sid, label: browserLabel() }); }

  sendBye() { if (this.gotOffer && !this.closed) this.send({ type: 'bye', sid: this.sid }); }

  async onEvent(ev) {
    if (this.closed) return;
    let msg;
    try { msg = await decrypt(this.key, ev.content); } catch { return; }
    if (msg.type === 'offer' && msg.sid === this.sid) {
      this.hostPubkey = ev.pubkey;
      if (this.answer) {
        // Host re-sent the offer (our answer may have been lost): re-send it.
        this.send({ type: 'answer', sid: this.sid, sdp: this.answer });
        return;
      }
      if (this.gotOffer) return;
      this.gotOffer = true;
      this.handleOffer(msg).catch((e) => {
        console.error(e);
        this.fail('Could not set up the connection', String(e.message || e));
      });
    } else if (msg.type === 'ended') {
      this.finish('The stream has ended', 'The host stopped sharing. Thanks for watching!');
    } else if (msg.type === 'bye' && msg.sid === this.sid) {
      this.finish('Disconnected', 'The host closed your connection.', true);
    }
  }

  async handleOffer(msg) {
    setStatus('Connecting…', 'Found the host. Establishing a direct connection…');
    this.fps = msg.fps;
    $('meta').textContent = `${msg.width}×${msg.height} · ${msg.fps} fps`;
    const pc = new RTCPeerConnection({ iceServers: msg.ice_servers || [] });
    this.pc = pc;
    const stream = new MediaStream();
    video.srcObject = stream;

    pc.ontrack = (e) => {
      // No low-latency playout hints: with a zero playout delay Chrome renders
      // each frame the moment it is decoded, so network and encoder jitter
      // show up as stutter. The default adaptive buffer (~50–100 ms) spaces
      // frames by their capture timestamps instead.
      stream.addTrack(e.track);
      if (e.track.kind === 'audio') this.hasAudio = true;
    };
    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      if (s === 'connected') this.onConnected();
      else if (s === 'disconnected') setStatus('Reconnecting…', 'The connection to the host dropped for a moment.');
      else if (s === 'failed') {
        this.fail('Connection failed', 'Couldn’t connect directly to the host. Your network (or theirs) may need a TURN server — ask the host to add one in the app settings.');
      }
    };

    await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
    const answer = await pc.createAnswer();
    if (/^m=video 0 /m.test(answer.sdp)) {
      this.send({ type: 'bye', sid: this.sid });
      this.fail('Unsupported browser', 'This browser can’t play H.264 video over WebRTC. Try Chrome, Edge, Safari or Firefox.');
      return;
    }
    answer.sdp = enableStereoOpus(answer.sdp);
    await pc.setLocalDescription(answer);
    await waitForIceGathering(pc, 2500);
    this.answer = pc.localDescription.sdp;
    this.send({ type: 'answer', sid: this.sid, sdp: this.answer });
  }

  onConnected() {
    stage.classList.add('playing');
    $('controls').hidden = false;
    video.muted = true;
    video.play().catch(() => {});
    // Try to start with sound; browsers usually block it until the user clicks.
    video.muted = false;
    video.play().then(() => updateMuteUi()).catch(() => {
      video.muted = true;
      video.play().catch(() => {});
      if (this.hasAudio !== false) $('unmute').hidden = false;
      updateMuteUi();
    });
  }

  fail(title, detail) {
    stage.classList.remove('playing');
    $('controls').hidden = true;
    setStatus(title, detail, { spinner: false, retry: true });
    this.close();
  }

  finish(title, detail, retry = false) {
    stage.classList.remove('playing');
    $('controls').hidden = true;
    $('unmute').hidden = true;
    setStatus(title, detail, { spinner: false, retry });
    this.close();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    try { this.pc && this.pc.close(); } catch {}
    setTimeout(() => this.relays && this.relays.close(), 500);
  }
}

function waitForIceGathering(pc, timeoutMs) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { pc.removeEventListener('icegatheringstatechange', check); resolve(); };
    const check = () => { if (pc.iceGatheringState === 'complete') done(); };
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(done, timeoutMs);
  });
}

// ───────────────────────── player controls ─────────────────────────

function updateMuteUi() {
  const muted = video.muted || video.volume === 0;
  $('ic-vol').hidden = muted;
  $('ic-muted').hidden = !muted;
  if (!video.muted) $('unmute').hidden = true;
}

function toggleMute() {
  video.muted = !video.muted;
  if (!video.muted && video.volume === 0) { video.volume = 1; $('volume').value = 1; }
  updateMuteUi();
}

function toggleFullscreen() {
  if (document.fullscreenElement) document.exitFullscreen();
  else if (stage.requestFullscreen) stage.requestFullscreen();
  else if (video.webkitEnterFullscreen) video.webkitEnterFullscreen();
}

$('unmute').onclick = () => { video.muted = false; video.play().catch(() => {}); updateMuteUi(); };
$('mute').onclick = toggleMute;
$('volume').oninput = (e) => { video.volume = Number(e.target.value); video.muted = video.volume === 0; updateMuteUi(); };
$('fullscreen').onclick = toggleFullscreen;
$('stats-btn').onclick = () => { $('stats').hidden = !$('stats').hidden; };
$('retry').onclick = () => start();
video.ondblclick = toggleFullscreen;

try {
  const v = localStorage.getItem('ptp-volume');
  if (v !== null) { video.volume = Number(v); $('volume').value = v; }
} catch {}
video.onvolumechange = () => { try { localStorage.setItem('ptp-volume', String(video.volume)); } catch {} };

document.addEventListener('keydown', (e) => {
  if (e.target instanceof HTMLInputElement) return;
  if (e.key === 'f') toggleFullscreen();
  else if (e.key === 'm') toggleMute();
  else if (e.key === 'i') $('stats').hidden = !$('stats').hidden;
});

let idleTimer;
document.addEventListener('mousemove', () => {
  stage.classList.remove('idle-mouse');
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => stage.classList.add('idle-mouse'), 2500);
});

// Stats overlay
let lastStats = null;
setInterval(async () => {
  const pc = session && session.pc;
  if (!pc || $('stats').hidden) return;
  const report = await pc.getStats();
  let v = null, a = null, pair = null;
  report.forEach((s) => {
    if (s.type === 'inbound-rtp' && s.kind === 'video') v = s;
    if (s.type === 'inbound-rtp' && s.kind === 'audio') a = s;
    if (s.type === 'candidate-pair' && s.nominated && s.state === 'succeeded') pair = s;
  });
  const now = performance.now();
  let kbps = 0;
  if (v && lastStats) kbps = ((v.bytesReceived - lastStats.bytes) * 8) / (now - lastStats.t);
  if (v) lastStats = { bytes: v.bytesReceived, t: now };
  let route = '';
  if (pair) {
    const local = report.get(pair.localCandidateId);
    route = local ? (local.candidateType === 'relay' ? 'TURN relay' : 'direct') : '';
  }
  const lines = [];
  if (v) {
    lines.push(`video   ${v.frameWidth || '?'}×${v.frameHeight || '?'} @ ${Math.round(v.framesPerSecond || 0)} fps`);
    lines.push(`bitrate ${(kbps / 1000).toFixed(1)} Mbps`);
    lines.push(`lost    ${v.packetsLost ?? 0} pkts · dropped ${v.framesDropped ?? 0} frames`);
    if (v.jitterBufferDelay && v.jitterBufferEmittedCount) {
      lines.push(`buffer  ${Math.round((v.jitterBufferDelay / v.jitterBufferEmittedCount) * 1000)} ms`);
    }
  }
  if (a) lines.push(`audio   ${a.packetsReceived ?? 0} pkts`);
  if (pair) lines.push(`rtt     ${Math.round((pair.currentRoundTripTime || 0) * 1000)} ms · ${route}`);
  $('stats').textContent = lines.join('\n');
}, 1000);

// ── canvas rendering ──
// Chrome on macOS shows <video> with the BT.709 "video gamma" (midtones
// lifted: grey 128 shows as 139). Drawing frames into a 2D canvas goes
// through the normal sRGB colour path, which matches the host's screen.
const screen = $('screen');
const screenCtx = screen.getContext('2d', { alpha: false });
let lastDraw = 0;
function drawFrame() {
  const w = video.videoWidth, h = video.videoHeight;
  if (!w || !h || video.readyState < 2) return;
  if (screen.width !== w || screen.height !== h) { screen.width = w; screen.height = h; }
  try {
    screenCtx.drawImage(video, 0, 0, w, h);
    lastDraw = performance.now();
    stage.classList.add('canvas');
  } catch {
    stage.classList.remove('canvas'); // fall back to the plain video element
  }
}
if ('requestVideoFrameCallback' in video) {
  const onFrame = () => { drawFrame(); video.requestVideoFrameCallback(onFrame); };
  video.requestVideoFrameCallback(onFrame);
}
// Fallback (no requestVideoFrameCallback, or it stops firing for an
// invisible video): draw on animation frames when no frame came for 50 ms.
(function tick() {
  if (performance.now() - lastDraw > 50) drawFrame();
  requestAnimationFrame(tick);
})();
screen.ondblclick = toggleFullscreen;

// The host resizes the stream when a shared window is resized.
video.addEventListener('resize', () => {
  if (!video.videoWidth || !session) return;
  $('meta').textContent = `${video.videoWidth}×${video.videoHeight}` + (session.fps ? ` · ${session.fps} fps` : '');
});

window.ptpDebug = () => session; // for troubleshooting from the dev console
window.ptpDebug.draw = () => drawFrame();
window.addEventListener('hashchange', () => start());
start();
