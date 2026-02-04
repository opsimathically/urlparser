/* eslint-disable @typescript-eslint/no-unused-vars */

/**
 * Blob URL fuzzer.
 *
 * Goals:
 * - Generate "should-parse" blob URLs that a modern, spec-aligned parser should accept.
 * - Generate "should-not-parse" blob URLs that a modern parser should reject, or that stress edge-cases.
 *
 * Notes:
 * - blob URLs have the general form:
 *      blob:<origin>/<uuid-or-opaque-id>
 *   where <origin> is commonly an http(s) origin, and the path is typically a UUID.
 * - This generator intentionally varies origin components, path/UUID forms, and encoding.
 * - This does not attempt to be a fully normative blob URL implementation; it is a fuzz input generator.
 */

// Example usage (remove in production):
// const fuzzer = new BlobUrlFuzzer({seed: 123});
// const good = fuzzer.generateValidBlobUrls({count: 20});
// const bad = fuzzer.generateInvalidBlobUrls({count: 50});

type rng_t = () => number;

interface blob_url_fuzzer_i {
  generateValidBlobUrls(params: { count: number; seed?: number }): string[];
  generateInvalidBlobUrls(params: { count: number; seed?: number }): string[];
}

import { BlobURLValidator } from '../bloburlvalidator/BlobURLValidator.class';

export class BlobURLFuzzer implements blob_url_fuzzer_i {
  private rng: rng_t;

  public constructor(params: { seed?: number }) {
    this.rng = this.createRng({ seed: params.seed });
  }

  public generateValidBlobUrls(params: {
    count: number;
    seed?: number;
  }): string[] {
    const rng =
      params.seed !== undefined
        ? this.createRng({ seed: params.seed })
        : this.rng;
    const urls: string[] = [];
    const seen = new Set<string>();

    // Strategy: combine valid origins + valid-ish blob path IDs; include mild, spec-plausible variations.
    // Ensure uniqueness as best-effort.
    let safety_counter = 0;
    while (urls.length < params.count && safety_counter < params.count * 50) {
      safety_counter += 1;

      const origin = this.generateValidOrigin({ rng });
      const id = this.generateValidBlobId({ rng });
      const delimiter = this.pickOne({ rng, items: ['/'] }); // keep conservative for "should-parse"
      const url = `blob:${origin}${delimiter}${id}`;

      if (!seen.has(url)) {
        seen.add(url);
        urls.push(url);
      }
    }

    // If uniqueness pressure prevented full count, pad with deterministic variants.
    while (urls.length < params.count) {
      const origin = 'https://example.com';
      const id = this.generateUuidV4({ rng });
      const url = `blob:${origin}/${id}`;
      urls.push(url);
    }

    return urls;
  }

  public generateInvalidBlobUrls(params: {
    count: number;
    seed?: number;
  }): string[] {
    const rng =
      params.seed !== undefined
        ? this.createRng({ seed: params.seed })
        : this.rng;
    const urls: string[] = [];
    const seen = new Set<string>();
    const validator = new BlobURLValidator();

    // Strategy:
    // - Wrong schemes / confusing prefixes
    // - Missing origin / missing delimiter
    // - Bad origins (illegal characters, malformed authority, userinfo oddities, invalid ports)
    // - Path payloads designed to break parsers (very long, control chars, bad UTF-8 sequences, nulls)
    // - Over-encoding, mixed encoding, percent-encoding edge cases
    // - "Looks like" valid but subtly broken UUID forms
    // - Ambiguous separators, extra slashes, backslashes
    //
    // Some of these may still parse in permissive implementations; they are intended for stress.
    let safety_counter = 0;
    while (urls.length < params.count && safety_counter < params.count * 500) {
      safety_counter += 1;

      const url = this.generateOneInvalidBlobUrl({ rng });
      if (validator.validate({ blob_url_str: url }).is_valid_bool) {
        continue;
      }
      if (!seen.has(url)) {
        seen.add(url);
        urls.push(url);
      }
    }

    // Pad if needed.
    while (urls.length < params.count) {
      const fallback = `blob:invalid${urls.length}`;
      if (!validator.validate({ blob_url_str: fallback }).is_valid_bool) {
        urls.push(fallback);
      }
    }

    return urls;
  }

  private generateOneInvalidBlobUrl(params: { rng: rng_t }): string {
    const rng = params.rng;

    const category = this.pickOne({
      rng,
      items: [
        'wrong_scheme',
        'missing_parts',
        'bad_origin',
        'bad_delimiter',
        'bad_percent_encoding',
        'control_chars',
        'huge_input',
        'uuid_near_miss',
        'confusable_separators',
        'embedded_nul',
        'weird_unicode',
        'authority_tricks'
      ]
    });

    if (category === 'wrong_scheme') {
      // Not actually blob:, but close enough to test scheme matching.
      const prefix = this.pickOne({
        rng,
        items: ['Blob:', 'BLOB:', 'bl0b:', 'blob;', 'blob//', 'blob://']
      });
      return `${prefix}https://example.com/${this.generateUuidV4({ rng })}`;
    }

    if (category === 'missing_parts') {
      // Missing origin or id or both.
      const variant = this.pickOne({
        rng,
        items: [
          'blob:',
          'blob:/',
          'blob://',
          'blob:////',
          'blob:https://',
          'blob:https://example.com',
          'blob:https://example.com/'
        ]
      });
      return variant;
    }

    if (category === 'bad_origin') {
      const bad_origin = this.pickOne({
        rng,
        items: [
          'http://ex ample.com',
          'https://exa<mple>.com',
          'https://example.com:999999',
          'https://example.com:-1',
          'https://example.com:00',
          'https://example..com',
          'https://.example.com',
          'https://example.com.',
          'https://[::1', // missing ]
          'https://[]', // empty IPv6
          'https://[::1]]',
          'https://[::g]', // invalid hex
          'https://user:pa ss@example.com',
          'https://@example.com',
          'https:///example.com',
          'https://example.com:1a',
          'https://example.com:\t80'
        ]
      });

      const tail = this.pickOne({
        rng,
        items: [
          this.generateUuidV4({ rng }),
          this.generateAsciiGarbage({ rng, min_len: 1, max_len: 32 }),
          ''
        ]
      });

      const maybe_slash = this.pickOne({ rng, items: ['/', '', '//'] });
      return `blob:${bad_origin}${maybe_slash}${tail}`;
    }

    if (category === 'bad_delimiter') {
      const origin = this.generateValidOrigin({ rng });
      const id = this.generateValidBlobId({ rng });
      const delimiter = this.pickOne({
        rng,
        items: ['', '///', '\\', '/\\', '/%2F', '/%5C', '?#', '#', '?', '/?']
      });
      return `blob:${origin}${delimiter}${id}`;
    }

    if (category === 'bad_percent_encoding') {
      const origin = this.generateValidOrigin({ rng });
      const bad = this.pickOne({
        rng,
        items: [
          '%', // incomplete
          '%2', // incomplete
          '%GG',
          '%zz',
          '%0', // incomplete
          '%u1234', // non-standard escape
          '%E0%A4', // truncated multibyte
          '%C3%28', // invalid UTF-8 sequence
          '%F0%28%8C%BC', // invalid UTF-8
          '%00', // NUL percent-encoded
          '%2F%2F%2F', // encoded slashes
          '%5C%5C' // encoded backslashes
        ]
      });

      const id = this.generateValidBlobId({ rng });
      const mix = this.pickOne({
        rng,
        items: [
          `${bad}${id}`,
          `${id}${bad}`,
          `${bad}${this.generateAsciiGarbage({ rng, min_len: 0, max_len: 16 })}`
        ]
      });
      return `blob:${origin}/${mix}`;
    }

    if (category === 'control_chars') {
      const origin = this.generateValidOrigin({ rng });
      const ctrl = this.pickOne({
        rng,
        items: [
          '\u0001',
          '\u0008',
          '\u0009',
          '\u000a',
          '\u000d',
          '\u001f',
          '\u007f'
        ]
      });
      const id = `${this.generateUuidV4({ rng })}${ctrl}${this.generateAsciiGarbage({ rng, min_len: 0, max_len: 8 })}`;
      return `blob:${origin}/${id}`;
    }

    if (category === 'huge_input') {
      const origin = this.generateValidOrigin({ rng });
      const huge_len = this.pickInt({ rng, min: 8_192, max: 200_000 });
      const payload = this.generateRepeatingPayload({ rng, length: huge_len });
      return `blob:${origin}/${payload}`;
    }

    if (category === 'uuid_near_miss') {
      const origin = this.generateValidOrigin({ rng });
      const near = this.pickOne({
        rng,
        items: [
          this.generateUuidV4({ rng }).replace(/-/g, ''), // no hyphens
          this.generateUuidV4({ rng }).toUpperCase() + '-', // trailing hyphen
          this.generateUuidV4({ rng }).slice(0, 35), // too short
          this.generateUuidV4({ rng }) + '0', // too long
          '00000000-0000-0000-0000-00000000000Z', // non-hex
          'gggggggg-gggg-gggg-gggg-gggggggggggg', // non-hex
          '12345678-1234-1234-1234-123456789ab', // 35 chars
          '12345678-1234-1234-1234-123456789abcd' // 37 chars
        ]
      });
      return `blob:${origin}/${near}`;
    }

    if (category === 'confusable_separators') {
      const origin = this.generateValidOrigin({ rng });
      const id = this.generateValidBlobId({ rng });
      const sep = this.pickOne({
        rng,
        items: ['／', '∕', '⁄', '⧸', '⧹', '＼']
      }); // unicode slash/backslash lookalikes
      return `blob:${origin}${sep}${id}`;
    }

    if (category === 'embedded_nul') {
      const origin = this.generateValidOrigin({ rng });
      const id = `${this.generateUuidV4({ rng })}\u0000${this.generateUuidV4({ rng })}`;
      return `blob:${origin}/${id}`;
    }

    if (category === 'weird_unicode') {
      const origin = this.generateValidOrigin({ rng });
      const weird = this.pickOne({
        rng,
        items: [
          '\u202e', // RTL override
          '\u2066', // LRI
          '\u2069', // PDI
          '\ufeff', // BOM
          '\u200d' // ZWJ
        ]
      });
      const id = `${this.generateUuidV4({ rng })}${weird}${this.generateAsciiGarbage({ rng, min_len: 0, max_len: 12 })}`;
      return `blob:${origin}/${id}`;
    }

    // authority_tricks
    {
      const trick_origin = this.pickOne({
        rng,
        items: [
          'https://example.com@evil.com',
          'https://example.com:80@evil.com',
          'https://user:pass@example.com@evil.com',
          'https://example.com%2F.evil.com',
          'https://example.com%5C.evil.com',
          'https://example.com#@evil.com',
          'https://example.com?@evil.com'
        ]
      });
      const id = this.generateValidBlobId({ rng });
      const delimiter = this.pickOne({ rng, items: ['/', '//', '///'] });
      return `blob:${trick_origin}${delimiter}${id}`;
    }
  }

  private generateValidOrigin(params: { rng: rng_t }): string {
    const rng = params.rng;

    const scheme = this.pickOne({ rng, items: ['https', 'http'] });
    const host = this.generateValidHost({ rng });
    const port = this.pickOne({
      rng,
      items: [
        '', // default
        '', // bias towards no port
        `:${this.pickInt({ rng, min: 1, max: 65535 })}`,
        ':443',
        ':80'
      ]
    });

    // Optional path/query/fragment are generally not part of the origin; keep conservative.
    // Still, some implementations may accept a serialized origin only; we keep it origin-like.
    return `${scheme}://${host}${port}`;
  }

  private generateValidHost(params: { rng: rng_t }): string {
    const rng = params.rng;

    const kind = this.pickOne({
      rng,
      items: ['domain', 'localhost', 'ipv4', 'ipv6']
    });
    if (kind === 'localhost') {
      return 'localhost';
    }
    if (kind === 'ipv4') {
      const a = this.pickInt({ rng, min: 1, max: 223 });
      const b = this.pickInt({ rng, min: 0, max: 255 });
      const c = this.pickInt({ rng, min: 0, max: 255 });
      const d = this.pickInt({ rng, min: 1, max: 254 });
      return `${a}.${b}.${c}.${d}`;
    }
    if (kind === 'ipv6') {
      // Basic, valid IPv6 literal forms.
      const v6 = this.pickOne({
        rng,
        items: [
          '[::1]',
          '[2001:db8::1]',
          '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]',
          '[fe80::1]'
        ]
      });
      return v6;
    }

    // domain
    const labels_count = this.pickInt({ rng, min: 2, max: 4 });
    const labels: string[] = [];
    for (let i = 0; i < labels_count; i += 1) {
      const label_len = this.pickInt({ rng, min: 1, max: 12 });
      labels.push(this.generateDnsLabel({ rng, length: label_len }));
    }
    const tld = this.pickOne({
      rng,
      items: ['com', 'net', 'org', 'dev', 'test', 'io']
    });
    return `${labels.join('.')}.${tld}`;
  }

  private generateDnsLabel(params: { rng: rng_t; length: number }): string {
    const rng = params.rng;
    const length = Math.max(1, params.length);

    // Start/end with alnum, interior may contain hyphen.
    const alnum = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const alnum_hyphen = 'abcdefghijklmnopqrstuvwxyz0123456789-';

    let label = '';
    label += alnum[this.pickInt({ rng, min: 0, max: alnum.length - 1 })];

    for (let i = 1; i < length - 1; i += 1) {
      label +=
        alnum_hyphen[
          this.pickInt({ rng, min: 0, max: alnum_hyphen.length - 1 })
        ];
    }

    if (length > 1) {
      label += alnum[this.pickInt({ rng, min: 0, max: alnum.length - 1 })];
    }

    // Avoid all-hyphen or trailing hyphen already guaranteed.
    return label;
  }

  private generateValidBlobId(params: { rng: rng_t }): string {
    const rng = params.rng;

    // Keep valid IDs aligned with BlobURLValidator's strict RFC 4122 checks.
    return this.generateUuidV4({ rng });
  }

  private generateUuidV4(params: { rng: rng_t }): string {
    const rng = params.rng;

    // Generate UUID v4 with correct version and variant bits at string level.
    const hex = '0123456789abcdef';

    const part1 = this.generateHex({ rng, length: 8 });
    const part2 = this.generateHex({ rng, length: 4 });
    const part3 = '4' + this.generateHex({ rng, length: 3 }); // version 4
    const variant_choices = ['8', '9', 'a', 'b']; // RFC 4122 variant
    const part4 =
      variant_choices[
        this.pickInt({ rng, min: 0, max: variant_choices.length - 1 })
      ] + this.generateHex({ rng, length: 3 });
    const part5 = this.generateHex({ rng, length: 12 });

    return `${part1}-${part2}-${part3}-${part4}-${part5}`;
  }

  private generateUuidLike(params: { rng: rng_t }): string {
    const rng = params.rng;
    return `${this.generateHex({ rng, length: 8 })}-${this.generateHex({ rng, length: 4 })}-${this.generateHex({ rng, length: 4 })}-${this.generateHex({ rng, length: 4 })}-${this.generateHex({ rng, length: 12 })}`;
  }

  private generateHex(params: { rng: rng_t; length: number }): string {
    const rng = params.rng;
    const hex = '0123456789abcdef';
    let out = '';
    for (let i = 0; i < params.length; i += 1) {
      out += hex[this.pickInt({ rng, min: 0, max: hex.length - 1 })];
    }
    return out;
  }

  private generateUrlSafeToken(params: { rng: rng_t; length: number }): string {
    const rng = params.rng;
    const alphabet =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';
    let out = '';
    for (let i = 0; i < params.length; i += 1) {
      out += alphabet[this.pickInt({ rng, min: 0, max: alphabet.length - 1 })];
    }
    return out;
  }

  private generateAsciiGarbage(params: {
    rng: rng_t;
    min_len: number;
    max_len: number;
  }): string {
    const rng = params.rng;
    const len = this.pickInt({ rng, min: params.min_len, max: params.max_len });
    // Intentionally includes characters that frequently trip parsers.
    const alphabet =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%\\ \t";
    let out = '';
    for (let i = 0; i < len; i += 1) {
      out += alphabet[this.pickInt({ rng, min: 0, max: alphabet.length - 1 })];
    }
    return out;
  }

  private generateRepeatingPayload(params: {
    rng: rng_t;
    length: number;
  }): string {
    const rng = params.rng;
    const chunk = this.pickOne({
      rng,
      items: [
        'A',
        'a',
        '0',
        'f',
        '-',
        '_',
        '.',
        '%41',
        '%00',
        '../',
        '..%2f',
        '%2e%2e%2f'
      ]
    });

    let out = '';
    while (out.length < params.length) {
      out += chunk;
    }
    return out.slice(0, params.length);
  }

  private pickOne<T>(params: { rng: rng_t; items: T[] }): T {
    const idx = this.pickInt({
      rng: params.rng,
      min: 0,
      max: params.items.length - 1
    });
    return params.items[idx];
  }

  private pickInt(params: { rng: rng_t; min: number; max: number }): number {
    const min = Math.ceil(params.min);
    const max = Math.floor(params.max);
    if (max < min) {
      return min;
    }
    const r = params.rng();
    const n = Math.floor(r * (max - min + 1)) + min;
    return n;
  }

  private createRng(params: { seed?: number }): rng_t {
    // Deterministic PRNG (Mulberry32).
    // If no seed is provided, seed from time + a little entropy.
    let seed =
      params.seed ??
      Date.now() ^ (Math.floor(Math.random() * 0xffffffff) >>> 0);
    seed = seed >>> 0;

    return function Rng(): number {
      seed += 0x6d2b79f5;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
}
