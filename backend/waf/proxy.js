/**
 * THE WAF PROXY — Track A (reverse proxy + blocking) wired to
 * Track B (brute-force + logging pipeline).
 *
 * Request lifecycle (this order matters):
 *
 *   client ──► [1] identify client IP
 *          ──► [2] already blocked?      -> 403, log, stop
 *          ──► [3] rate limit exceeded?  -> 429 + block IP, log, stop
 *          ──► [4] buffer the body (size-capped)
 *          ──► [5] detector.inspect() -> risk score
 *          ──► [6] risk >= threshold?    -> 403, log, strike counter, stop
 *          ──► [7] otherwise: log "allowed" and forward to the target
 *                  (http-proxy-middleware)
 *          ◄── [8] on the response: a 401/403 from a login path counts
 *                  as a failed login (brute-force counter)
 *
 * Cheap checks run first (IP block, rate limit) so a flood never
 * reaches the regex engine.
 */
const net = require('net');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const detector = require('./detector');

function getClientIp(req, trustXff) {
  if (trustXff) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const first = String(xff).split(',')[0].trim();
      if (net.isIP(first)) return first;
    }
  }
  let ip = req.socket.remoteAddress || 'unknown';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip.slice(0, 45);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { tooLarge = true; return; } // keep draining, don't keep data
      chunks.push(c);
    });
    req.on('end', () => resolve({ buffer: Buffer.concat(chunks), tooLarge }));
    req.on('error', reject);
  });
}

const BINARY_TYPE = /^(image|audio|video)\/|application\/(octet-stream|zip|pdf|gzip)/i;

function blockPage(req, res, status, title, detail, meta) {
  res.status(status);
  res.set('X-ThreatGate', 'blocked');
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.type('html').send(`<!doctype html><meta charset="utf-8"><title>${title}</title>
<body style="font-family:system-ui;background:#0b0f14;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0">
<div style="max-width:460px;padding:32px;border:1px solid #243244;border-radius:12px;background:#121922">
<div style="color:#ff5d5d;font:600 12px ui-monospace,monospace;letter-spacing:.08em">THREATGATE</div>
<h1 style="margin:8px 0 12px;font-size:22px">${title}</h1><p style="color:#8a97a6;line-height:1.5">${detail}</p>
<p style="color:#8a97a6;font:12px ui-monospace,monospace">risk ${meta.riskScore} · ${meta.category}</p></div></body>`);
  }
  return res.json({ blocked: true, error: title, reason: detail, category: meta.category, risk_score: meta.riskScore });
}

function createWafApp({ config, pipeline, bruteforce, rulesStore }) {
  const app = express();
  app.disable('x-powered-by');
  const orgId = config.wafOrgId;

  const target = createProxyMiddleware({
    target: config.targetUrl,
    changeOrigin: true,
    xfwd: true,
    on: {
      // We already consumed the request stream to inspect the body,
      // so re-send the buffered bytes to the upstream server.
      proxyReq: (proxyReq, req) => {
        proxyReq.removeHeader('transfer-encoding');
        if (req._wafBody && req._wafBody.length) {
          proxyReq.setHeader('Content-Length', req._wafBody.length);
          proxyReq.write(req._wafBody);
        }
      },
      proxyRes: (proxyRes, req, res) => {
        res.setHeader('X-ThreatGate', 'passed');
        const ip = req._wafIp;
        const isLogin = config.loginPathRegex.test(req.originalUrl.split('?')[0]);
        if (!ip || !isLogin) return;
        if (proxyRes.statusCode === 401 || proxyRes.statusCode === 403) {
          bruteforce.trackFailedLogin(orgId, ip).then(async (block) => {
            if (block) await logBruteForceBlock(req, ip, block.reason, 90);
          }).catch((e) => console.error('[waf] failed-login tracking error:', e.message));
        } else if (proxyRes.statusCode < 400 && req.method === 'POST') {
          bruteforce.clearFailedLogins(orgId, ip);
        }
      },
      error: (err, req, res) => {
        console.error('[waf] upstream error:', err.message);
        if (res && !res.headersSent && typeof res.writeHead === 'function') {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad gateway', detail: 'The protected application is unreachable.' }));
        }
      },
    },
  });

  // A block just happened (brute force / rate limit / strikes): log it
  // as its own event so it appears in the live feed, and tell admin
  // dashboards to refresh the Blocked IPs table.
  async function logBruteForceBlock(req, ip, reason, risk) {
    console.log(`[waf] AUTO-BLOCK ${ip} — ${reason}`);
    await pipeline.record(orgId, {
      ip, method: req.method, path: req.originalUrl, category: 'brute_force',
      riskScore: risk, action: 'blocked', matchedRuleId: null, userAgent: req.headers['user-agent'],
    });
    pipeline.blocksChanged(orgId);
  }

  app.get('/__threatgate/health', (req, res) => res.json({ ok: true, service: 'threatgate-waf', target: config.targetUrl }));

  app.use(async (req, res) => {
    const ip = getClientIp(req, config.trustXff);
    req._wafIp = ip;
    const base = { ip, method: req.method, path: req.originalUrl, userAgent: req.headers['user-agent'] };

    try {
      // [2] already blocked?
      const existing = await bruteforce.check(orgId, ip);
      if (existing) {
        await pipeline.record(orgId, { ...base, category: 'brute_force', riskScore: 100, action: 'blocked', matchedRuleId: null });
        return blockPage(req, res, 403, 'Access blocked', 'Your IP address is temporarily blocked: ' + (existing.reason || 'policy'), { riskScore: 100, category: 'brute_force' });
      }

      // [3] rate limit
      const limited = await bruteforce.trackRequest(orgId, ip);
      if (limited) {
        await logBruteForceBlock(req, ip, limited.reason, 95);
        return blockPage(req, res, 429, 'Too many requests', limited.reason, { riskScore: 95, category: 'brute_force' });
      }

      // [4] body
      let body = Buffer.alloc(0);
      if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        const { buffer, tooLarge } = await readBody(req, config.maxBodyBytes);
        if (tooLarge) {
          await pipeline.record(orgId, { ...base, category: 'none', riskScore: 0, action: 'blocked', matchedRuleId: null });
          return blockPage(req, res, 413, 'Payload too large', 'Request body exceeds the allowed size.', { riskScore: 0, category: 'none' });
        }
        body = buffer;
        req._wafBody = buffer;
      }

      // [5] inspect
      const ctype = req.headers['content-type'] || '';
      const bodyText = body.length && !BINARY_TYPE.test(ctype)
        ? body.subarray(0, config.inspectBodyBytes).toString('utf8') : '';
      const result = detector.inspect(req, bodyText, rulesStore.getCompiled());

      // [6] decide
      if (result.riskScore >= config.blockThreshold) {
        await pipeline.record(orgId, { ...base, category: result.category, riskScore: result.riskScore, action: 'blocked', matchedRuleId: result.matchedRuleId });
        const top = result.matches.sort((a, b) => b.weight - a.weight)[0];
        console.log(`[waf] BLOCK ${ip} ${req.method} ${req.originalUrl.slice(0, 80)} risk=${result.riskScore} ${result.category} (rule ${top.id}, in ${top.where})`);
        const strike = await bruteforce.trackAttack(orgId, ip);
        if (strike) await logBruteForceBlock(req, ip, strike.reason, 95);
        return blockPage(req, res, 403, 'Request blocked', 'This request was identified as a ' + result.category.replace('_', ' ') + ' attempt.', { riskScore: result.riskScore, category: result.category });
      }

      // [7] allow + forward
      await pipeline.record(orgId, { ...base, category: result.category === 'none' ? 'none' : result.category, riskScore: result.riskScore, action: 'allowed', matchedRuleId: result.matchedRuleId });
      return target(req, res, (err) => {
        if (err) res.status(502).json({ error: 'Bad gateway' });
      });
    } catch (err) {
      console.error('[waf] internal error:', err);
      if (!res.headersSent) res.status(500).json({ error: 'WAF internal error' });
    }
  });

  return app;
}

module.exports = { createWafApp, getClientIp };
