import { Controller, Get, Query, Res } from '@nestjs/common';
import type { Response } from 'express';
import { analyzeCsp, type CspFindings } from './csp-analyzer'; // ← nuevo
import { analyzeHtml, type HtmlFindings } from './html-analyzer'; // ← lo crearás en el paso 4

@Controller()
export class AppController {
  @Get('scan')
  async scan(@Query('url') url: string, @Res() res: Response) {
    if (!url) return res.status(400).json({ error: 'Falta url' });

    try {
      const r = await fetch(url, { method: 'GET', redirect: 'manual' });
      const status = r.status;
      const rawHeaders: Record<string, string> = {};
      r.headers.forEach((v, k) => (rawHeaders[k] = v));
      const allHeaders = toRecordLower(rawHeaders);

      const server  = allHeaders['server'] || 'N/D';
      const isHttps = url.startsWith('https://');

      // HSTS y 'preload'
      const hstsVal = allHeaders['strict-transport-security'] || '';
      const hsts    = !!hstsVal;
      const hstsPreload = /;\s*preload/i.test(hstsVal);

      // CSP
      const csp = allHeaders['content-security-policy'];
      const cspAnalysis: CspFindings = analyzeCsp(csp);
      // para compat con tu front actual:
      const cspWeak = cspAnalysis.present ? !cspAnalysis.strong : undefined;

      // CORS (educativo)
      const corsOrigin  = allHeaders['access-control-allow-origin'] ?? null;
      const corsMethods = (allHeaders['access-control-allow-methods'] ?? '')
        .split(',').map(s => s.trim()).filter(Boolean);
      const corsRisky   = corsOrigin === '*' && corsMethods.length > 0;

      // Redirect HTTP → HTTPS (si el usuario pasó https:// ya, probamos la versión http:// para medir)
      const httpUrl = url.replace(/^https:\/\//i, 'http://');
      let redirectsToHttps = false;
      if (/^http:\/\//i.test(httpUrl)) {
        try {
          const probe = await fetch(httpUrl, { method: 'GET', redirect: 'manual' });
          const loc = probe.headers.get('location') || '';
          redirectsToHttps = /^https:\/\//i.test(loc);
        } catch {}
      }

      // faltantes esperados
      const expected = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'referrer-policy',
        'permissions-policy',
        'cross-origin-opener-policy',
        'cross-origin-embedder-policy',
        'cross-origin-resource-policy',
      ];
      const missingHeaders = expected.filter((h) => !allHeaders[h]);

      // Score
      const score = calcScore({
        isHttps,
        hsts,
        hstsPreload,
        cspPresent: !!cspAnalysis.present,
        cspWeak: !cspAnalysis.strong && cspAnalysis.present,
        corsRisky,
        missingHeaders,
        redirectsToHttps,
      });

      // HTML findings (paso 4 puede retornar null si no es HTML)
      const htmlFindings: HtmlFindings | null = await analyzeHtml(url);

      return res.json({
        url,
        status,
        server,
        isHttps,
        hsts,
        hstsPreload,
        cspWeak,              // compat con tu front actual
        cspAnalysis,          // info pro
        cors: { origin: corsOrigin, methods: corsMethods, risky: corsRisky },
        redirectsToHttps,
        missingHeaders,
        allHeaders,
        score,
        htmlFindings,         // info pro
        timestamp: new Date().toISOString(),
      });
    } catch (e: any) {
      return res.status(500).json({ url, error: 'Falla al obtener headers del destino' });
    }
  }
}

// ---------- helpers ----------
function toRecordLower(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  Object.keys(h).forEach((k) => (out[k.toLowerCase()] = h[k]));
  return out;
}

function calcScore(input: {
  isHttps: boolean;
  hsts: boolean;
  hstsPreload: boolean;
  cspPresent: boolean;
  cspWeak: boolean;
  corsRisky: boolean;
  missingHeaders: string[];
  redirectsToHttps: boolean;
}) {
  let score = 100;

  if (!input.isHttps) score -= 30;
  if (!input.hsts) score -= 20;
  if (input.hstsPreload) score += 3; // pequeño plus

  if (!input.cspPresent) score -= 25;
  else if (input.cspWeak) score -= 10;

  if (input.corsRisky) score -= 10;
  if (!input.redirectsToHttps) score -= 5; // si no fuerza redirección, restamos un poco

  const weights: Record<string, number> = {
    'strict-transport-security': 15,
    'content-security-policy': 15,
    'x-frame-options': 5,
    'x-content-type-options': 5,
    'referrer-policy': 5,
    'permissions-policy': 5,
    'cross-origin-opener-policy': 5,
    'cross-origin-embedder-policy': 5,
    'cross-origin-resource-policy': 5,
  };
  for (const h of input.missingHeaders) score -= weights[h] ?? 3;

  return Math.max(0, Math.min(100, Math.round(score)));
}
