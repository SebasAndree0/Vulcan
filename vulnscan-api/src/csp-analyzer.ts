export type CspFindings = {
  present: boolean;
  weakReasons: string[]; // razones de debilidad
  strong: boolean;       // true si no hay razones
};

export function analyzeCsp(csp?: string): CspFindings {
  if (!csp) return { present: false, weakReasons: [], strong: false };

  const p = (name: string) =>
    new RegExp(`(^|;)\\s*${name}\\s+([^;]+)`, 'i').exec(csp)?.[2] || '';
  const has = (name: string) =>
    new RegExp(`(^|;)\\s*${name}\\s+`, 'i').test(csp);

  const reasons: string[] = [];
  const script = p('script-src');
  const style  = p('style-src');

  // Riesgos típicos
  if (/(\s|\W)\*(\s|\W|$)/.test(script)) reasons.push("script-src excesivamente amplio ('*').");
  if (/unsafe-inline/i.test(script)) reasons.push("script-src permite 'unsafe-inline'.");
  if (/unsafe-eval/i.test(script)) reasons.push("script-src permite 'unsafe-eval'.");
  if (/unsafe-inline/i.test(style))  reasons.push("style-src permite 'unsafe-inline'.");

  if (!has('object-src') || !/object-src\s+'none'/i.test(csp)) reasons.push("falta object-src 'none'.");
  if (!has('frame-ancestors')) reasons.push('falta frame-ancestors.');
  if (!has('base-uri') || !/base-uri\s+'self'/i.test(csp)) reasons.push("falta base-uri 'self'.");
  if (!has('form-action')) reasons.push('falta form-action.');
  if (!has('upgrade-insecure-requests')) reasons.push('falta upgrade-insecure-requests.');
  if (!/require-trusted-types-for\s+'script'/i.test(csp)) reasons.push("falta require-trusted-types-for 'script'.");

  return { present: true, weakReasons: reasons, strong: reasons.length === 0 };
}
