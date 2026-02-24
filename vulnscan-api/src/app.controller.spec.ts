import { Controller, Get, Query, Res } from '@nestjs/common';
import type { Response } from 'express';

@Controller()
export class AppController {
  @Get('scan')
  async scan(@Query('url') url: string, @Res() res: Response) {
    if (!url) return res.status(400).json({ error: 'Falta url' });

    try {
      const r = await fetch(url, { method: 'GET' });
      const status = r.status;
      const rawHeaders: Record<string, string> = {};
      r.headers.forEach((v, k) => (rawHeaders[k] = v));

      const allHeaders = toRecordLower(rawHeaders);
      const server = allHeaders['server'] || 'N/D';
      const isHttps = url.startsWith('https://');

      // detecciones
      const hsts = !!allHeaders['strict-transport-security'];
      const csp = allHeaders['content-security-policy'];
      const cspWeak = csp ? /unsafe-inline|unsafe-eval|\*/i.test(csp) : false;

      // CORS (super básico/educativo)
      const corsOrigin = allHeaders['access-control-allow-origin'] ?? null;
      const corsMethods = (allHeaders['access-control-allow-methods'] ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const corsRisky = corsOrigin === '*' && corsMethods.length > 0;

      // faltantes
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

      // score
      const score = calcScore({
        isHttps,
        hsts,
        cspPresent: !!csp,
        cspWeak,
        corsRisky,
        missingHeaders,
      });

      // recomendaciones (cortas)
      const recommendations = buildRecommendations(missingHeaders, { csp, cspWeak, hsts, corsRisky });

      return res.json({
        url,
        status,
        server,
        isHttps,
        hsts,
        cspWeak,
        cors: { origin: corsOrigin, methods: corsMethods, risky: corsRisky },
        missingHeaders,
        allHeaders,
        score,
        recommendations,
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
  cspPresent: boolean;
  cspWeak: boolean;
  corsRisky: boolean;
  missingHeaders: string[];
}) {
  let score = 100;
  if (!input.isHttps) score -= 30;
  if (!input.hsts) score -= 20;

  if (!input.cspPresent) score -= 25;
  else if (input.cspWeak) score -= 10;

  if (input.corsRisky) score -= 10;

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

function buildRecommendations(missing: string[], flags: { csp?: string; cspWeak: boolean; hsts: boolean; corsRisky: boolean }) {
  const recs: string[] = [];
  if (!flags.hsts) recs.push("Habilita HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
  if (!flags.csp) recs.push("Define CSP fuerte: sin unsafe-inline/unsafe-eval; orígenes restringidos.");
  else if (flags.cspWeak) recs.push("Refuerza CSP: elimina 'unsafe-inline'/'unsafe-eval' (usa nonce/hash).");
  if (flags.corsRisky) recs.push("CORS: evita Access-Control-Allow-Origin: * en endpoints sensibles.");

  const map: Record<string, string> = {
    'x-frame-options': 'Agrega X-Frame-Options: DENY o SAMEORIGIN.',
    'x-content-type-options': 'Agrega X-Content-Type-Options: nosniff.',
    'referrer-policy': 'Configura Referrer-Policy: strict-origin-when-cross-origin.',
    'permissions-policy': 'Agrega Permissions-Policy: camera=(), microphone=(), geolocation=().',
    'cross-origin-opener-policy': 'COOP: same-origin.',
    'cross-origin-embedder-policy': 'COEP: require-corp.',
    'cross-origin-resource-policy': 'CORP: same-site.',
  };
  for (const h of missing) if (map[h]) recs.push(map[h]);

  return recs;
}
