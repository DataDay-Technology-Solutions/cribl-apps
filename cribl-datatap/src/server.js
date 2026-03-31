#!/usr/bin/env node
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const DataTap = require('./index');

const PORT = process.env.DATATAP_PORT || 3000;
let activeTap = null;
let sseClients = [];

function broadcast(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  sseClients = sseClients.filter(res => {
    try { res.write(msg); return true; } catch { return false; }
  });
}

const server = http.createServer((req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, `http://localhost:${PORT}`);

  // Serve UI
  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(path.join(__dirname, 'ui', 'index.html')));
    return;
  }

  // SSE endpoint — live event stream
  if (url.pathname === '/api/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.write('\n');
    sseClients.push(res);
    req.on('close', () => {
      sseClients = sseClients.filter(c => c !== res);
    });
    return;
  }

  // API: List sourcetypes
  if (url.pathname === '/api/sourcetypes' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(DataTap.listSourcetypes()));
    return;
  }

  // API: List scenarios
  if (url.pathname === '/api/scenarios' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(DataTap.listScenarios()));
    return;
  }

  // API: Start stream
  if (url.pathname === '/api/start' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      if (activeTap) { activeTap.stop(); activeTap = null; }
      const opts = JSON.parse(body);
      const sourcetypes = opts.sourcetypes || ['pan:traffic'];
      const eps = opts.eps || 10;
      const duration = opts.duration || 0;

      activeTap = new DataTap({ eps });
      let count = 0;
      const startTime = Date.now();

      activeTap.stream(sourcetypes, {
        eps,
        duration,
        onEvent: (evt) => {
          count++;
          broadcast({
            type: 'event',
            count,
            sourcetype: evt.sourcetype,
            raw: evt.raw,
            timestamp: evt.timestamp,
            elapsed: ((Date.now() - startTime) / 1000).toFixed(1),
          });
        },
      });

      // Send stats every 2 seconds
      const statsInterval = setInterval(() => {
        if (!activeTap || !activeTap.running) { clearInterval(statsInterval); return; }
        const stats = activeTap.scheduler ? activeTap.scheduler.getStats() : {};
        broadcast({ type: 'stats', count, elapsed: ((Date.now() - startTime) / 1000).toFixed(1), ...stats });
      }, 2000);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'started', sourcetypes, eps, duration }));
    });
    return;
  }

  // API: Start scenario
  if (url.pathname === '/api/scenario' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      if (activeTap) { activeTap.stop(); activeTap = null; }
      const opts = JSON.parse(body);
      activeTap = new DataTap({ eps: opts.eps || 20 });
      let count = 0;

      activeTap.runScenario(opts.name, {
        eps: opts.eps || 20,
        timeScale: opts.timeScale || 10,
        onEvent: (evt) => {
          count++;
          broadcast({ type: 'event', count, sourcetype: evt.sourcetype, raw: evt.raw, timestamp: evt.timestamp });
        },
        onPhaseChange: (phase, idx, total) => {
          broadcast({ type: 'phase', name: phase.name, index: idx, total });
        },
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'started', scenario: opts.name }));
    });
    return;
  }

  // API: Stop
  if (url.pathname === '/api/stop' && req.method === 'POST') {
    if (activeTap) { activeTap.stop(); activeTap = null; }
    broadcast({ type: 'stopped' });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'stopped' }));
    return;
  }

  // API: Generate single batch
  if (url.pathname === '/api/generate' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      const opts = JSON.parse(body);
      const dt = new DataTap();
      const events = [];
      for (let i = 0; i < (opts.count || 10); i++) {
        events.push(dt.generate(opts.sourcetype || 'pan:traffic'));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(events));
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n  DataTap UI running at http://localhost:${PORT}\n`);
});
