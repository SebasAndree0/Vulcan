import { Injectable } from '@nestjs/common';
import axios, { AxiosRequestHeaders } from 'axios';
import * as urlLib from 'url';

type ScanReport = {
  url: string;
  status?: number;
  server?: string;
  isHttps?: boolean;
  hsts?: boolean;
  cspWeak?: boolean;
  cors?: { origin?: string | null; methods?: string[]; risky: boolean };
  methods?: string[];
  missingHeaders?: string[];
  allHeaders?: Record<string, string | string[]>;
  secure?: boolean;
  error?: string;
};

@Injectable()
export class ScanService {
  private readonly importantHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
  ];

  async analyzeUrl(rawUrl: string): Promise<ScanReport> {
    let normalized = rawUrl?.trim() || '';
    if (!/^https?:\/\//i.test(normalized)) normalized = 'https://' + normalized;

    // User-Agent propio y timeout defensivo
    const commonConfig = {
      timeout: 7000,
      maxRedirects: 5,
      headers: { 'User-Agent': 'VulnScanCL/1.0 (+educational)' } as AxiosRequestHeaders,
      validateStatus: () => true,
    };

    try {
      // Pedimos GET para asegurar headers “reales”
      const resp = await axios.get(normalized, commonConfig);

      const headers = this.normalizeHeaders(resp.headers);
      const status = resp.status;

      // Hechos clave
      const parsed = urlLib.parse(normalized);
      const isHttps = parsed.protocol === 'https:';
      const server = (headers['server'] as string) || 'Desconocido';

      // HSTS
      const hstsHeader = (headers['strict-transport-security'] as string) || '';
      const hsts = !!hstsHeader;

      // CSP y debilidades obvias
      const csp = (headers['content-security-policy'] as string) || '';
      const cspWeak = !!csp && /unsafe-inline|unsafe-eval/i.test(csp);

      // CORS
      const allowOrigin = (headers['access-control-allow-origin'] as string) || null;
      const allowMethodsRaw = (headers['access-control-allow-methods'] as string) || '';
      const corsMethods = allowMethodsRaw
        ? allowMethodsRaw.split(',').map((m) => m.trim().toUpperCase())
        : undefined;
      const corsRisky = allowOrigin === '*' || (!!allowOrigin && /https?:\/\/.+/i.test(allowOrigin) && allowOrigin.length > 0);

      // Methods permitidos (si el server lo expone)
      const allowHeader = (headers['allow'] as string) || '';
      const methods = allowHeader ? allowHeader.split(',').map((m) => m.trim().toUpperCase()) : undefined;

      // Headers faltantes (de los importantes)
      const missingHeaders = this.importantHeaders.filter((h) => !(h in headers));

      const secure =
        !!isHttps &&
        !!hsts &&
        missingHeaders.length === 0 &&
        !cspWeak &&
        !(corsRisky ?? false);

      return {
        url: normalized,
        status,
        server,
        isHttps,
        hsts,
        cspWeak,
        cors: { origin: allowOrigin, methods: corsMethods, risky: !!corsRisky },
        methods,
        missingHeaders,
        allHeaders: headers,
        secure,
      };
    } catch (err: any) {
      return {
        url: normalized,
        error: err?.message || 'No se pudo conectar al sitio',
      };
    }
  }

  private normalizeHeaders(h: Record<string, any>): Record<string, string | string[]> {
    const out: Record<string, string | string[]> = {};
    for (const k of Object.keys(h || {})) {
      out[k.toLowerCase()] = h[k];
    }
    return out;
  }
}
