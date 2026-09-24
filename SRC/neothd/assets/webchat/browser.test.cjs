// Hosted browser contract tests execute the exact shipped HTML against an HTTP
// fixture. Native Rust tests separately exercise the gateway and turn runtime.
'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');

const html = fs.readFileSync(path.join(__dirname, 'index.html'));
let browser;
before(async () => { browser = await chromium.launch({ headless: true }); });
after(async () => { await browser?.close(); });

async function fixture(mode = 'ready') {
  const state = { bootstraps: 0, starts: 0, cancelled: false, decision: null, active: null, requests: [], authenticated: false };
  let releasePreflight;
  const preflightGate = new Promise(resolve => { releasePreflight = resolve; });
  const requestId = '019602f0-0000-7000-8000-000000000001';
  const server = http.createServer(async (req, res) => {
    const reply = (status, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
      res.end(JSON.stringify(body));
    };
    if (req.url === '/webchat') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(html); return; }
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : undefined;
    state.requests.push({ path: req.url, body });
    if (req.url === '/api/v1/webchat/bootstrap') {
      state.bootstraps++;
      if (body.handoff !== 'one-shot' || state.authenticated) { reply(401, { code: 'unauthorized', message: 'Invalid handoff' }); return; }
      state.authenticated = true;
      reply(200, { ok: true }, { 'Set-Cookie': 'neoth_webchat=fixture; HttpOnly; SameSite=Strict; Path=/' }); return;
    }
    if (!req.headers.cookie?.includes('neoth_webchat=fixture')) { reply(401, { code: 'unauthorized', message: 'Session required' }); return; }
    switch (req.url) {
      case '/api/v1/webchat/session': reply(200, { authenticated: true, active_request_id: state.active }); return;
      case '/api/v1/webchat/transcript': reply(200, { turns: [], truncated: false }); return;
      case '/api/v1/webchat/preflight':
        assert.equal(body.request_id, undefined, 'browser must not invent daemon UUIDs');
        assert.equal(body.origin_surface, undefined, 'browser cannot relabel the source');
        if (mode === 'delayed-preflight') await preflightGate;
        reply(200, { request_id: requestId, consent: mode === 'consent' ? { state: 'confirmation_required', prompt: { routes: [{ provider: 'Fixture provider', endpoint_origin: 'https://provider.example' }] } } : { state: 'ready' } }); return;
      case '/api/v1/webchat/decide':
        assert.deepEqual(Object.keys(body).sort(), ['decision', 'request_id']);
        state.decision = body.decision;
        reply(200, { outcome: body.decision === 'deny' ? 'denied' : 'approved' }); return;
      case '/api/v1/webchat/start':
        assert.deepEqual(body, { request_id: requestId });
        assert.equal(state.decision, 'allow_once');
        state.starts++; state.active = requestId;
        reply(200, { request_id: requestId, initial_sequence: 0 }); return;
      case '/api/v1/webchat/attach': {
        assert.deepEqual(Object.keys(body).sort(), ['after_sequence', 'request_id']);
        const frames = [
          { sequence: 1, payload: { type: 'accepted' } },
          { sequence: 2, payload: { type: 'delta', text: '<strong>Visible answer</strong>' } }
        ];
        if (mode !== 'active' || state.cancelled) {
          frames.push({ sequence: 3, payload: { type: 'terminal', terminal: { state: state.cancelled ? 'cancelled' : 'complete' } } });
          state.active = null;
        }
        reply(200, { frames: frames.filter(frame => frame.sequence > body.after_sequence) }); return;
      }
      case '/api/v1/webchat/cancel':
        assert.deepEqual(body, { request_id: requestId });
        state.cancelled = true; reply(200, { outcome: 'accepted' }); return;
      default: reply(404, { code: 'not_found', message: 'Missing fixture route' });
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const url = `http://127.0.0.1:${server.address().port}/webchat`;
  return {
    state, page, errors, url, releasePreflight,
    open: async () => { await page.goto(url + '#handoff=one-shot'); await page.waitForFunction(() => !document.getElementById('send').disabled); },
    close: async () => { releasePreflight(); await context.close(); await new Promise(resolve => server.close(resolve)); }
  };
}

test('shipped page authenticates, sends server request ID, renders frames as text and allows another turn', async () => {
  const f = await fixture();
  try {
    await f.open(); assert.equal(new URL(f.page.url()).hash, '');
    await f.page.getByLabel('Message', { exact: true }).fill('Hello');
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await f.page.waitForFunction(() => document.querySelector('.turn.agent .content')?.textContent === '<strong>Visible answer</strong>' && !document.getElementById('send').disabled);
    assert.equal(await f.page.locator('.turn.agent strong').count(), 0);
    assert.equal(f.state.starts, 1);
    await f.page.getByLabel('Message', { exact: true }).fill('Again');
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await f.page.waitForFunction(() => document.querySelectorAll('.turn.agent').length === 2 && !document.getElementById('send').disabled);
    assert.equal(f.state.starts, 2); assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});

test('confirmation displays the real route and only starts after Allow once', async () => {
  const f = await fixture('consent');
  try {
    await f.open(); await f.page.getByLabel('Message', { exact: true }).fill('Needs consent');
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await f.page.getByRole('dialog').waitFor();
    assert.match(await f.page.locator('#consent-routes').textContent(), /Fixture provider.*provider\.example/);
    assert.equal(f.state.starts, 0);
    await f.page.getByRole('button', { name: 'Allow once', exact: true }).click();
    await f.page.waitForFunction(() => document.getElementById('status').textContent === 'Ready' && document.querySelectorAll('.turn.agent').length === 1);
    assert.equal(f.state.starts, 1); assert.equal(f.state.decision, 'allow_once'); assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});

test('denied consent never starts a turn and preserves the message', async () => {
  const f = await fixture('consent');
  try {
    await f.open(); await f.page.getByLabel('Message', { exact: true }).fill('Keep this draft');
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await f.page.getByRole('button', { name: "Don't allow", exact: true }).click();
    await f.page.waitForFunction(() => document.getElementById('status').textContent === 'Request not sent');
    assert.equal(f.state.starts, 0); assert.equal(f.state.decision, 'deny');
    assert.equal(await f.page.getByLabel('Message', { exact: true }).inputValue(), 'Keep this draft');
    assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});

test('Stop waits for the cancelled terminal and does not claim completion', async () => {
  const f = await fixture('active');
  try {
    await f.open(); await f.page.getByLabel('Message', { exact: true }).fill('Long response');
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await f.page.waitForFunction(() => !document.getElementById('cancel').disabled);
    await f.page.getByRole('button', { name: 'Stop', exact: true }).click();
    await f.page.waitForFunction(() => document.getElementById('status').textContent === 'Stopped');
    assert.equal(f.state.cancelled, true); assert.equal(f.state.starts, 1); assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});

test('reload reuses the authenticated session and replays without another start', async () => {
  const f = await fixture('active');
  try {
    await f.open(); await f.page.getByLabel('Message', { exact: true }).fill('Reconnect');
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await f.page.waitForFunction(() => document.querySelector('.turn.agent .content')?.textContent.includes('Visible answer'));
    await f.page.reload();
    await f.page.waitForFunction(() => document.querySelector('.turn.agent .content')?.textContent.includes('Visible answer'));
    assert.equal(f.state.bootstraps, 1); assert.equal(f.state.starts, 1);
    assert.equal(await f.page.locator('.turn.agent').count(), 1); assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});

test('an unpaired page remains unavailable without sending provider work', async () => {
  const f = await fixture();
  try {
    await f.page.goto(f.url);
    await f.page.waitForFunction(() => !document.getElementById('error').hidden);
    assert.equal(await f.page.getByRole('button', { name: 'Send', exact: true }).isDisabled(), true);
    assert.equal(f.state.starts, 0); assert.equal(f.state.bootstraps, 0); assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});

test('reconnect invalidates an in-flight preflight before it can decide or start', async () => {
  const f = await fixture('delayed-preflight');
  try {
    await f.open(); await f.page.getByLabel('Message', { exact: true }).fill('Do not send after reconnect');
    const requested = f.page.waitForRequest(request => request.url().endsWith('/api/v1/webchat/preflight'));
    await f.page.getByRole('button', { name: 'Send', exact: true }).click();
    await requested;
    await f.page.getByRole('button', { name: 'Reconnect', exact: true }).click();
    await f.page.waitForFunction(() => document.getElementById('status').textContent === 'Ready');
    const completed = f.page.waitForResponse(response => response.url().endsWith('/api/v1/webchat/preflight'));
    f.releasePreflight(); await completed;
    await f.page.evaluate(() => new Promise(resolve => setTimeout(resolve, 100)));
    assert.equal(f.state.decision, null); assert.equal(f.state.starts, 0);
    assert.equal(await f.page.getByLabel('Message', { exact: true }).inputValue(), 'Do not send after reconnect');
    assert.deepEqual(f.errors, []);
  } finally { await f.close(); }
});
