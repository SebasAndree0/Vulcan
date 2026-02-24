export function buildHtmlReport(payload: any): string {
  const esc = (s: any) => String(s ?? '').replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]!));
  const headersHtml = Object.entries(payload.allHeaders ?? {})
    .map(([k, v]) => `<div><code>${esc(k)}:</code> ${esc(v)}</div>`)
    .join('');

  const recs = (payload.recommendations ?? [])
    .map((r: string) => `<li>${esc(r)}</li>`).join('');

  return `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><title>Informe VulnScan CL</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial,sans-serif;margin:24px;color:#222}
h1{margin:0 0 8px} .muted{color:#666}
.badge{display:inline-block;padding:4px 8px;border-radius:8px;font-size:12px}
.success{background:#eaf7f0;color:#1e8e3e} .warn{background:#fff5cc;color:#9a6b00}
.danger{background:#fdecea;color:#c62828} code{background:#f5f5f5;padding:2px 6px;border-radius:4px}
.card{border:1px solid #eee;border-radius:12px;padding:16px;margin:12px 0}
</style></head>
<body>
<h1>🔒 Informe VulnScan CL</h1>
<div class="muted">Generado: ${esc(payload.timestamp)}</div>

<div class="card">
  <div><strong>URL:</strong> ${esc(payload.url)}</div>
  <div><strong>Servidor:</strong> ${esc(payload.server)}</div>
  <div><strong>Estado HTTP:</strong> ${esc(payload.status)}</div>
  <div><strong>HTTPS:</strong> ${payload.isHttps ? 'Sí' : 'No'}</div>
  <div><strong>HSTS:</strong> ${payload.hsts ? 'Sí' : 'No'}</div>
  <div><strong>CSP débil:</strong> ${payload.cspWeak ? 'Sí' : 'No'}</div>
  <div><strong>VulnScore:</strong> ${payload.score}%</div>
</div>

<div class="card">
  <h3>⚠️ Recomendaciones</h3>
  ${recs ? `<ul>${recs}</ul>` : '<div class="muted">Sin recomendaciones.</div>'}
</div>

<div class="card">
  <h3>🔎 Headers completos</h3>
  ${headersHtml || '<div class="muted">Sin datos.</div>'}
</div>

<div class="muted" style="margin-top:16px">* Informe pasivo/educativo — sin pruebas intrusivas.</div>
</body></html>`;
}
