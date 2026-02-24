export type HtmlFindings = {
  inlineScripts: number;
  inlineStyles: number;
  externalScriptHosts: string[];
  externalStyleHosts: string[];
  mixedContentCount: number;
};

export async function analyzeHtml(url: string): Promise<HtmlFindings | null> {
  const r = await fetch(url, { method: 'GET' });
  const ctype = r.headers.get('content-type') || '';
  if (!/text\/html/i.test(ctype)) return null;

  const html = await r.text();
  const hostFrom = (u: string) => { try { return new URL(u, url).host; } catch { return ''; } };

  const inlineScripts = (html.match(/<script(?![^>]*src=)[\s\S]*?>/gi) || []).length;
  const inlineStyles  = (html.match(/<style[\s\S]*?>/gi) || []).length;

  const scriptSrcs = Array.from(html.matchAll(/<script[^>]*\ssrc=["']([^"']+)["']/gi)).map(m => m[1]);
  const styleHrefs = Array.from(html.matchAll(/<link[^>]*rel=["']stylesheet["'][^>]*\shref=["']([^"']+)["']/gi)).map(m => m[1]);

  const assetSrcs = Array.from(html.matchAll(/<(?:img|iframe|source|video|audio)[^>]*\ssrc=["']([^"']+)["']/gi)).map(m => m[1]);
  const allUrls   = [...scriptSrcs, ...styleHrefs, ...assetSrcs];

  const mixedContentCount = allUrls.filter(u => /^http:\/\//i.test(u)).length;

  return {
    inlineScripts,
    inlineStyles,
    externalScriptHosts: [...new Set(scriptSrcs.map(hostFrom))].filter(Boolean),
    externalStyleHosts:  [...new Set(styleHrefs.map(hostFrom))].filter(Boolean),
    mixedContentCount,
  };
}
