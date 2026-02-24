import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';

type CorsInfo = {
  origin?: string | null;
  methods?: string[];
  risky?: boolean;
};

type CspAnalysis = {
  present: boolean;
  weakReasons: string[];
  strong: boolean;
};

type HtmlFindings = {
  inlineScripts: number;
  inlineStyles: number;
  externalScriptHosts: string[];
  externalStyleHosts: string[];
  mixedContentCount: number;
};

type ScanResult = {
  url: string;
  status?: number;
  server?: string;
  isHttps?: boolean;
  hsts?: boolean;
  cspWeak?: boolean; // true: CSP existe pero débil; false: fuerte; undefined: ausente
  cors?: CorsInfo;
  missingHeaders?: string[];
  allHeaders?: Record<string, string | string[]>;
  error?: string;

  // Campos adicionales
  hstsPreload?: boolean;
  redirectsToHttps?: boolean;
  cspAnalysis?: CspAnalysis;
  htmlFindings?: HtmlFindings | null;
};

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent {
  targetUrl = '';
  result: ScanResult | null = null;
  loading = false;

  // UI del puntaje
  score = 0;
  scoreLabel = 'Desconocido';
  scoreBarClass = 'bg-secondary';

  detailsOpen = false;

  // Historial
  history: Array<ScanResult & { score: number; addedAt: string }> = [];

  // Base API (ajusta si usas otro puerto)
  private readonly apiBase = 'http://localhost:3000';

  constructor(private http: HttpClient) {}

  // 🚀 Ejecuta el escaneo
  scan() {
    const trimmed = this.targetUrl.trim();
    if (!trimmed) {
      alert('Por favor ingresa una URL válida');
      return;
    }

    this.loading = true;
    this.result = null;
    this.detailsOpen = false;

    const apiUrl = `${this.apiBase}/scan?url=${encodeURIComponent(trimmed)}`;
    this.http.get<ScanResult>(apiUrl).subscribe({
      next: (res) => {
        this.result = res;
        this.computeScore(res);

        this.history.unshift({
          ...res,
          score: this.score,
          addedAt: new Date().toISOString(),
        });
        this.history = this.history.slice(0, 20);

        this.loading = false;
      },
      error: () => {
        this.result = { url: trimmed, error: 'No se pudo conectar con la API' };
        this.score = 0;
        this.scoreLabel = 'Riesgoso';
        this.scoreBarClass = 'bg-danger';
        this.loading = false;
      },
    });
  }

  // 🧮 Calcula el puntaje de seguridad (VulnScore)
  private computeScore(res: ScanResult) {
    let score = 100;

    if (!res.isHttps) score -= 30;
    if (!res.hsts) score -= 20;

    // CSP
    if (res.cspWeak === true) score -= 10;
    if (res.cspWeak === false && !this.hasHeader(res, 'content-security-policy')) score -= 25;
    if (res.cspWeak === undefined && !this.hasHeader(res, 'content-security-policy')) score -= 25;

    // CORS
    if (res.cors?.risky) score -= 10;

    // Headers faltantes
    const missing = (res.missingHeaders ?? []).map((h) => h.toLowerCase());
    const weight: Record<string, number> = {
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
    for (const h of missing) score -= weight[h] ?? 3;

    // Normalizar
    score = Math.min(100, Math.max(0, Math.round(score)));
    this.score = score;

    // Etiquetas y colores
    if (score >= 90) {
      this.scoreLabel = 'Excelente';
      this.scoreBarClass = 'bg-success';
    } else if (score >= 80) {
      this.scoreLabel = 'Seguro';
      this.scoreBarClass = 'bg-success';
    } else if (score >= 60) {
      this.scoreLabel = 'Mejorable';
      this.scoreBarClass = 'bg-warning';
    } else if (score >= 40) {
      this.scoreLabel = 'Bajo';
      this.scoreBarClass = 'bg-orange';
    } else {
      this.scoreLabel = 'Riesgoso';
      this.scoreBarClass = 'bg-danger';
    }
  }

  // 🔍 Verifica si existe una cabecera en el resultado
  hasHeader(res: ScanResult, key: string): boolean {
    const headers = Object.keys(res.allHeaders ?? {}).map((h) => h.toLowerCase());
    return headers.includes(key.toLowerCase());
  }

  // 🧰 Formatea métodos CORS (fix para error en el template)
  formatMethods(methods?: string[] | null): string {
    return Array.isArray(methods) && methods.length > 0 ? methods.join(', ') : 'N/D';
  }

  // 📘 Recomendaciones para el panel
  recommendationFor(h: string): string {
    const key = h.toLowerCase();
    switch (key) {
      case 'strict-transport-security':
        return 'Habilita HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload';
      case 'content-security-policy':
        return 'Define una CSP fuerte sin unsafe-inline ni unsafe-eval; limita orígenes.';
      case 'x-frame-options':
        return 'Usa X-Frame-Options: DENY o SAMEORIGIN contra clickjacking.';
      case 'x-content-type-options':
        return 'Usa X-Content-Type-Options: nosniff para prevenir MIME sniffing.';
      case 'referrer-policy':
        return 'Configura Referrer-Policy: strict-origin-when-cross-origin.';
      case 'permissions-policy':
        return 'Agrega Permissions-Policy para restringir cámara, micrófono y geolocalización.';
      case 'cross-origin-opener-policy':
        return 'Usa Cross-Origin-Opener-Policy: same-origin para aislar el contexto.';
      case 'cross-origin-embedder-policy':
        return 'Agrega Cross-Origin-Embedder-Policy: require-corp para prevenir fugas de recursos.';
      case 'cross-origin-resource-policy':
        return 'Configura Cross-Origin-Resource-Policy: same-site o same-origin.';
      default:
        return 'Agrega esta cabecera si aplica en tu contexto.';
    }
  }

  // 🧾 Herramientas UI
  clearHistory() {
    this.history = [];
  }

  downloadJson() {
    if (!this.result) return;
    const payload = { ...this.result, score: this.score };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const safeName = (this.result.url || 'sitio')
      .replace(/^https?:\/\//, '')
      .replace(/[^\w.-]/g, '_');
    a.href = url;
    a.download = `vulnscan_${safeName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  openHtmlReport() {
    if (!this.result?.url) return;
    const reportUrl = `${this.apiBase}/report?url=${encodeURIComponent(this.result.url)}`;
    window.open(reportUrl, '_blank', 'noopener,noreferrer');
  }
}
