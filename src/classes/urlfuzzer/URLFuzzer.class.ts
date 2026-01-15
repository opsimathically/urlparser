/**
 * URLFuzzer (corrected design)
 *
 * Design correction:
 * - The `complexity` scalar (0..1) now *consistently* influences generation decisions.
 * - `weightedPick(...)` now uses `complexity` to bias selection toward later (more complex) options.
 * - Previously “complexity was threaded but unused” at certain decision points; that is now fixed.
 *
 * Contract:
 * - genParsableURLs: always parse via `new URL(url)` (Node.js WHATWG URL)
 * - genUnparsableURLs: intended to throw in `new URL(url)` (no base URL)
 */

type UrlGenerationOptions = {
  seed?: number;

  /**
   * 0..1: controls typical complexity distribution for parsable URLs.
   * - 0 => mostly simple
   * - 1 => mostly complex
   */
  complexityBias?: number;

  includeTrickyValidCases?: boolean;

  /**
   * Strength of complexity bias within weightedPick.
   * 0 => weightedPick ignores complexity (but other logic still uses it)
   * 1 => strong push toward later options as complexity grows
   */
  complexityWeightingStrength?: number;
};

export class URLFuzzer {
  private rng: () => number;
  private complexityBias: number;
  private includeTrickyValidCases: boolean;
  private complexityWeightingStrength: number;

  constructor(opts: UrlGenerationOptions = {}) {
    this.rng = this.makeRng(opts.seed);
    this.complexityBias = this.clamp(opts.complexityBias ?? 0.5, 0, 1);
    this.includeTrickyValidCases = !!opts.includeTrickyValidCases;
    this.complexityWeightingStrength = this.clamp(
      opts.complexityWeightingStrength ?? 0.85,
      0,
      1
    );
  }

  public genParsableURLs(count: number): string[] {
    const out: string[] = [];
    for (let i = 0; i < count; i++) out.push(this.generateParsableUrl());
    return out;
  }

  public genUnparsableURLs(count: number): string[] {
    const out: string[] = [];
    for (let i = 0; i < count; i++) out.push(this.generateUnparsableUrl());
    return out;
  }

  // ----------------------------
  // Parsable generation
  // ----------------------------

  private generateParsableUrl(): string {
    const complexity = this.pickComplexity(); // 0..1
    const scheme = this.pickOne(['http', 'https', 'ws', 'wss', 'ftp']);

    // Order matters: later entries are treated as "more complex" by weightedPick.
    const authorityType = this.weightedPick(
      [
        { v: 'domain', w: 0.75 },
        { v: 'ipv4', w: 0.15 },
        { v: 'ipv6', w: 0.1 }
      ],
      complexity
    );

    const host =
      authorityType === 'domain'
        ? this.generateDomain(complexity)
        : authorityType === 'ipv4'
          ? this.generateIPv4(complexity)
          : this.wrapIPv6(this.generateIPv6(complexity));

    const includeAuth = this.prob(0.15 + 0.5 * complexity);
    const includePort = this.prob(0.2 + 0.55 * complexity);
    const includePath = this.prob(0.55 + 0.4 * complexity);
    const includeQuery = this.prob(0.35 + 0.55 * complexity);
    const includeFragment = this.prob(0.2 + 0.45 * complexity);

    const userInfo = includeAuth ? this.generateUserInfo(complexity) : '';
    const port = includePort ? `:${this.generatePort(complexity)}` : '';

    const path = includePath ? this.generatePath(complexity) : '/';
    const query = includeQuery ? this.generateQuery(complexity) : '';
    const fragment = includeFragment ? this.generateFragment(complexity) : '';

    const url = `${scheme}://${userInfo}${host}${port}${path}${query}${fragment}`;

    // Guarantee parsable output.
    try {
      // eslint-disable-next-line no-new
      new URL(url);
      return url;
    } catch {
      return 'https://example.com/';
    }
  }

  private generateDomain(complexity: number): string {
    const tlds = ['com', 'net', 'org', 'io', 'dev', 'info', 'co', 'app'];
    const tld = this.pickOne(tlds);

    const labelCount = this.intBetween(2, 2 + Math.floor(3 * complexity)); // 2..5
    const labels: string[] = [];
    for (let i = 0; i < labelCount; i++)
      labels.push(this.generateDnsLabel(complexity));

    if (this.prob(0.1 * complexity)) {
      labels[0] = `xn--${this.generateDnsLabel(complexity).slice(0, 10)}`;
    }

    return `${labels.join('.')}.${tld}`;
  }

  private generateDnsLabel(complexity: number): string {
    const minLen = 3;
    const maxLen = 6 + Math.floor(10 * complexity); // up to ~16
    const len = this.intBetween(minLen, maxLen);

    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let label = '';
    for (let i = 0; i < len; i++) {
      if (this.prob(0.15 * complexity) && i !== 0 && i !== len - 1)
        label += '-';
      else label += chars[this.intBetween(0, chars.length - 1)];
    }
    label = label.replace(/^-+/, 'a').replace(/-+$/, 'z');
    return label;
  }

  private generateUserInfo(complexity: number): string {
    const user = this.generateToken('user', complexity, { allowPercent: true });
    const includePass = this.prob(0.35 + 0.45 * complexity);
    const pass = includePass
      ? `:${this.generateToken('pass', complexity, { allowPercent: true })}`
      : '';
    return `${user}${pass}@`;
  }

  private generatePort(complexity: number): number {
    const common = [80, 443, 8080, 8443, 21, 22, 3000, 5000, 8000, 8888];

    // Low complexity: stick to common ports more often.
    // High complexity: explore more arbitrary ports.
    const useCommon = this.prob(this.lerp(0.75, 0.35, complexity));
    if (useCommon) return this.pickOne(common);

    // High complexity: include more edge-ish values (1, 65535) sometimes.
    if (this.prob(0.08 + 0.12 * complexity))
      return this.pickOne([1, 65535, 1024, 49152]);
    return this.intBetween(1, 65535);
  }

  private generatePath(complexity: number): string {
    const segmentCount = this.intBetween(0, 1 + Math.floor(6 * complexity)); // 0..7
    if (segmentCount === 0) return '/';

    const segments: string[] = [];
    for (let i = 0; i < segmentCount; i++) {
      // Order matters: later options = “more complex”
      const kind = this.weightedPick(
        [
          { v: 'word', w: 0.55 },
          { v: 'id', w: 0.2 },
          { v: 'file', w: 0.15 },
          { v: 'mixed', w: 0.1 }
        ],
        complexity
      );

      if (kind === 'word') {
        segments.push(
          this.generateToken('seg', complexity, {
            allowPercent:
              this.includeTrickyValidCases && this.prob(0.35 * complexity)
          })
        );
      } else if (kind === 'id') {
        segments.push(String(this.intBetween(1, 999999)));
      } else if (kind === 'file') {
        segments.push(this.generateFilename(complexity));
      } else {
        segments.push(this.generateMixedSegment(complexity));
      }
    }

    const trailingSlash = this.prob(0.2 + 0.25 * complexity) ? '/' : '';
    return `/${segments.join('/')}${trailingSlash}`;
  }

  private generateFilename(complexity: number): string {
    const bases = [
      'index',
      'api',
      'health',
      'metrics',
      'report',
      'image',
      'download',
      'search'
    ];
    const exts = ['html', 'json', 'txt', 'png', 'jpg', 'csv', 'pdf'];

    const base = this.prob(this.lerp(0.7, 0.4, complexity))
      ? this.pickOne(bases)
      : this.generateToken('file', complexity);
    const ext = this.pickOne(exts);
    return `${base}.${ext}`;
  }

  private generateMixedSegment(complexity: number): string {
    const parts = [
      this.generateToken('p', complexity),
      String(this.intBetween(1, 9999)),
      this.prob(0.5) ? this.generateToken('q', complexity) : 'v'
    ];
    let s = parts.join(this.pickOne(['_', '-', '.']));
    if (this.includeTrickyValidCases && this.prob(0.25 * complexity))
      s = this.percentEncodeSome(s);
    return s;
  }

  private generateQuery(complexity: number): string {
    const paramCount = this.intBetween(1, 2 + Math.floor(8 * complexity)); // 1..10
    const params: string[] = [];

    const commonKeys = [
      'q',
      'query',
      'page',
      'limit',
      'offset',
      'sort',
      'order',
      'filter',
      'lang',
      'region',
      'token',
      'session',
      'debug',
      'redirect',
      'callback',
      'utm_source',
      'utm_medium',
      'utm_campaign'
    ];

    for (let i = 0; i < paramCount; i++) {
      const key = this.prob(0.65)
        ? this.pickOne(commonKeys)
        : this.generateToken('k', complexity, { maxLen: 12 });

      // Order matters: later kinds = “more complex”
      const valueKind = this.weightedPick(
        [
          { v: 'word', w: 0.3 },
          { v: 'number', w: 0.2 },
          { v: 'bool', w: 0.1 },
          { v: 'date', w: 0.1 },
          { v: 'token', w: 0.15 },
          { v: 'miniurl', w: 0.1 },
          { v: 'jsonish', w: 0.05 }
        ],
        complexity
      );

      let value: string;
      switch (valueKind) {
        case 'word':
          value = this.generateToken('v', complexity, {
            allowSpaces:
              this.includeTrickyValidCases && this.prob(0.25 * complexity)
          });
          break;
        case 'number':
          value = String(
            this.intBetween(0, this.prob(0.2) ? 1_000_000 : 10_000)
          );
          break;
        case 'bool':
          value = this.pickOne(['true', 'false', '0', '1']);
          break;
        case 'date':
          value = this.generateIsoDateTime(complexity);
          break;
        case 'token':
          value = this.generateToken('t', complexity, {
            allowPercent: true,
            maxLen: 24
          });
          break;
        case 'miniurl':
          value = encodeURIComponent(
            `https://${this.generateDomain(0.6)}/r/${this.intBetween(1, 9999)}`
          );
          break;
        case 'jsonish':
          value = encodeURIComponent(
            JSON.stringify({
              a: this.intBetween(1, 9),
              b: this.generateToken('x', 0.4)
            })
          );
          break;
        default:
          value = this.generateToken('v', complexity);
      }

      const encodedKey = this.safeEncodeQueryComponent(key);
      const encodedValue = this.safeEncodeQueryComponent(value);
      params.push(`${encodedKey}=${encodedValue}`);
    }

    if (this.prob(0.1 + 0.2 * complexity)) {
      const k = this.prob(0.6)
        ? 'flag'
        : this.generateToken('flag', complexity);
      params.push(this.safeEncodeQueryComponent(k));
    }

    if (this.prob(0.1 + 0.2 * complexity) && params.length >= 2) {
      const duplicated =
        params[this.intBetween(0, params.length - 1)].split('=')[0];
      params.push(
        `${duplicated}=${this.safeEncodeQueryComponent(this.generateToken('dup', complexity))}`
      );
    }

    return `?${params.join('&')}`;
  }

  private generateFragment(complexity: number): string {
    const kind = this.weightedPick(
      [
        { v: 'anchor', w: 0.55 },
        { v: 'state', w: 0.25 },
        { v: 'route', w: 0.2 }
      ],
      complexity
    );

    let frag: string;
    if (kind === 'anchor') frag = this.generateToken('section', complexity);
    else if (kind === 'state')
      frag = `state=${encodeURIComponent(this.generateToken('s', complexity, { allowPercent: true }))}`;
    else
      frag = `/app/${this.generateToken('view', complexity)}/${this.intBetween(1, 999)}`;

    if (this.includeTrickyValidCases && this.prob(0.2 * complexity))
      frag = this.percentEncodeSome(frag);
    return `#${frag}`;
  }

  // ----------------------------
  // Unparsable generation
  // ----------------------------

  private generateUnparsableUrl(): string {
    const pattern = this.pickOne([
      'invalidSchemeChar',
      'missingSchemeNoBase',
      'badIPv6Literal',
      'schemeMissingColon',
      'illegalWhitespaceInScheme',
      'nonsensePrefix',
      'invalidAuthoritySlashes',
      'unclosedBracket'
    ] as const);

    let candidate = '';
    switch (pattern) {
      case 'invalidSchemeChar':
        candidate = `ht*tp://example.com/${this.generateToken('x', 0.4)}`;
        break;

      case 'missingSchemeNoBase':
        candidate = `//${this.generateDomain(0.5)}/${this.generateToken('path', 0.5)}`;
        break;

      case 'badIPv6Literal':
        candidate = `http://[2001:db8:::1]/`;
        break;

      case 'schemeMissingColon':
        candidate = `https//${this.generateDomain(0.4)}/${this.generateToken('p', 0.4)}`;
        break;

      case 'illegalWhitespaceInScheme':
        candidate = `ht tp://example.com/`;
        break;

      case 'nonsensePrefix':
        candidate = `???${this.generateToken('x', 0.4)}://example.com/`;
        break;

      case 'invalidAuthoritySlashes':
        candidate = `http:/\\${this.generateDomain(0.4)}/`;
        break;

      case 'unclosedBracket':
        candidate = `http://[2001:db8::1/`;
        break;
    }

    for (let i = 0; i < 8; i++) {
      if (this.isUnparsable(candidate)) return candidate;
      candidate = this.makeMoreLikelyUnparsable(candidate);
    }

    return 'ht*tp://example.com';
  }

  private isUnparsable(url: string): boolean {
    try {
      // eslint-disable-next-line no-new
      new URL(url);
      return false;
    } catch {
      return true;
    }
  }

  private makeMoreLikelyUnparsable(s: string): string {
    const m = this.pickOne([
      () => s.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*/, 'h ttp'),
      () => s.replace('://', ':/'),
      () => `http://[:::]/${this.generateToken('x', 0.3)}`,
      () => s.replace(/^http/, 'ht*tp'),
      () => `//${this.generateDomain(0.5)}/${this.generateToken('rel', 0.4)}`,
      () => 'http://[2001:db8::1'
    ]);
    return m();
  }

  // ----------------------------
  // Helpers: IPs, encoding, tokens, RNG
  // ----------------------------

  private generateIPv4(complexity: number): string {
    // Higher complexity: include more edge-ish octets (0, 255) more frequently.
    const edgeProb = this.lerp(0.05, 0.2, complexity);

    const octet = () => {
      if (this.prob(edgeProb)) return this.pickOne([0, 255]);
      // Also vary typical ranges a bit with complexity.
      const lo = this.prob(0.15 * complexity) ? 1 : 10;
      const hi = this.prob(0.15 * complexity) ? 254 : 240;
      return this.intBetween(lo, hi);
    };

    return `${octet()}.${octet()}.${octet()}.${octet()}`;
  }

  private generateIPv6(complexity: number): string {
    // Higher complexity: more groups, more chance of compression, and shorter groups.
    const groups = this.intBetween(
      3,
      Math.max(3, 5 + Math.floor(3 * complexity)) // 5..8
    );

    const parts: string[] = [];
    for (let i = 0; i < groups; i++) {
      const n = this.intBetween(0, 0xffff);
      // Higher complexity: allow shorter hex (less padding) more often.
      const hex = n.toString(16);
      parts.push(
        this.prob(0.25 + 0.35 * complexity)
          ? hex.replace(/^0+/, '') || '0'
          : hex
      );
    }

    // Compression chance rises with complexity.
    if (this.prob(this.lerp(0.15, 0.55, complexity))) {
      const start = this.intBetween(0, parts.length - 1);
      const run = this.intBetween(
        1,
        Math.min(3 + Math.floor(2 * complexity), parts.length - start)
      );
      parts.splice(start, run, '');
      // ensure at most one empty marker
      let seen = false;
      for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '') {
          if (!seen) seen = true;
          else parts[i] = '0';
        }
      }
    }

    let joined = parts.join(':').replace(/(^:|:$)/g, '');
    joined = joined.replace(/:::+/g, '::');
    return joined;
  }

  private wrapIPv6(v6: string): string {
    return `[${v6}]`;
  }

  private generateIsoDateTime(complexity: number): string {
    // Higher complexity: sometimes include fractional seconds and/or offsets.
    const year = this.intBetween(2000, 2035);
    const month = this.intBetween(1, 12);
    const day = this.intBetween(1, 28);
    const hour = this.intBetween(0, 23);
    const min = this.intBetween(0, 59);
    const sec = this.intBetween(0, 59);
    const pad = (n: number) => String(n).padStart(2, '0');

    const frac = this.prob(0.1 + 0.35 * complexity)
      ? `.${String(this.intBetween(0, 999)).padStart(3, '0')}`
      : '';

    // Offset handling: mostly Z at low complexity; include +/-HH:MM sometimes at high complexity.
    let tz = 'Z';
    if (this.prob(0.05 + 0.35 * complexity)) {
      const sign = this.pickOne(['+', '-']);
      const oh = pad(this.intBetween(0, 14));
      const om = pad(this.pickOne([0, 15, 30, 45]));
      tz = `${sign}${oh}:${om}`;
    }

    return `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(min)}:${pad(sec)}${frac}${tz}`;
  }

  private generateToken(
    prefix: string,
    complexity: number,
    opts: {
      allowPercent?: boolean;
      allowSpaces?: boolean;
      maxLen?: number;
    } = {}
  ): string {
    const maxLen = opts.maxLen ?? 6 + Math.floor(12 * complexity);
    const minLen = Math.max(2, Math.floor(maxLen / 3));
    const len = this.intBetween(minLen, maxLen);

    const alpha = 'abcdefghijklmnopqrstuvwxyz';
    const alnum = alpha + '0123456789';
    const extra = '-_.';
    const pool = alnum + (this.prob(0.25 * complexity) ? extra : '');

    let s = prefix ? prefix : '';
    if (s.length > 0) s += this.prob(0.5) ? '-' : '';

    while (s.length < len) s += pool[this.intBetween(0, pool.length - 1)];

    if (opts.allowSpaces && this.prob(0.25)) {
      const idx = this.intBetween(1, Math.max(1, s.length - 2));
      s = s.slice(0, idx) + ' ' + s.slice(idx);
    }

    if (opts.allowPercent && this.prob(0.3)) s = this.percentEncodeSome(s);

    return s;
  }

  private percentEncodeSome(s: string): string {
    if (s.length < 2) return encodeURIComponent(s);

    const chars = s.split('');
    const encodeCount = this.intBetween(1, Math.min(3, chars.length));
    for (let i = 0; i < encodeCount; i++) {
      const idx = this.intBetween(0, chars.length - 1);
      const c = chars[idx];
      if (/[a-z0-9]/i.test(c) && this.prob(0.7)) continue;
      chars[idx] = encodeURIComponent(c);
    }
    return chars.join('');
  }

  private safeEncodeQueryComponent(s: string): string {
    if (/%[0-9A-Fa-f]{2}/.test(s)) return s;
    return encodeURIComponent(s);
  }

  private pickComplexity(): number {
    // Bias the distribution toward 0 or 1 based on complexityBias
    const r = this.rng();
    const bias = this.complexityBias;

    // Simple skew curve: bias > 0.5 => skew toward 1; bias < 0.5 => toward 0.
    const k = bias >= 0.5 ? 1 / (1.0001 - (bias - 0.5)) : 1 + (0.5 - bias) * 3;

    const x = Math.pow(r, 1 / k);
    return this.clamp(x, 0, 1);
  }

  /**
   * Complexity-aware weighted pick.
   *
   * Interpretation:
   * - Items earlier in the list are treated as "simpler" choices.
   * - Items later in the list are treated as "more complex" choices.
   * - As `complexity` increases, weights are smoothly shifted toward later items.
   *
   * This is the key “design correction” you called out: complexity now materially affects selection.
   */
  private weightedPick<T extends string>(
    items: Array<{ v: T; w: number }>,
    complexity: number
  ): T {
    const strength = this.complexityWeightingStrength;

    // complexityFactor in [-1, +1]
    const complexityFactor = (complexity - 0.5) * 2;

    // Adjust weights using item position as a proxy for "complexity level".
    // posFactor in [-1, +1] (earlier => -1, later => +1)
    const n = items.length;
    const adjusted = items.map((it, idx) => {
      const posFactor = n <= 1 ? 0 : (idx / (n - 1)) * 2 - 1;
      // shift multiplier in [~(1-strength), ~(1+strength)] depending on alignment
      const multiplier = 1 + strength * complexityFactor * posFactor;
      // keep weights positive and avoid collapse
      const w = Math.max(1e-9, it.w * multiplier);
      return { v: it.v, w };
    });

    const total = adjusted.reduce((s, it) => s + it.w, 0);
    let r = this.rng() * total;
    for (const it of adjusted) {
      r -= it.w;
      if (r <= 0) return it.v;
    }
    return adjusted[adjusted.length - 1].v;
  }

  private prob(p: number): boolean {
    return this.rng() < p;
  }

  private intBetween(min: number, max: number): number {
    const r = this.rng();
    return min + Math.floor(r * (max - min + 1));
  }

  private pickOne<T>(arr: T[]): T {
    return arr[this.intBetween(0, arr.length - 1)];
  }

  private lerp(a: number, b: number, t: number): number {
    return a + (b - a) * this.clamp(t, 0, 1);
  }

  private clamp(n: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, n));
  }

  private makeRng(seed?: number): () => number {
    if (seed === undefined) return () => Math.random();

    // Mulberry32
    let a = seed >>> 0;
    return () => {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
}

// Example usage:
// const fuzzer = new URLFuzzer({ seed: 1234, complexityBias: 0.75, includeTrickyValidCases: true });
// console.log(fuzzer.genParsableURLs(10));
// console.log(fuzzer.genUnparsableURLs(10));
