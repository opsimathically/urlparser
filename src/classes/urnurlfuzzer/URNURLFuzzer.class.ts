import { URNURLValidator } from '../urnurlvalidator/URNURLValidator.class';

type urn_url_fuzzer_options_t = {
  seed_u32?: number;

  max_total_length_u32?: number;

  // Component inclusion rates for valid URNs
  include_r_component_bool?: boolean;
  include_q_component_bool?: boolean;
  include_f_component_bool?: boolean;

  // If true, generate some well-known real URNs alongside random ones
  include_known_examples_bool?: boolean;

  // If true, include percent-encoded bytes in NSS/components
  include_pct_encoding_bool?: boolean;

  // If true, include non-ASCII characters in NSS/components (some parsers accept, some reject)
  include_non_ascii_bool?: boolean;
};

export class URNURLFuzzer {
  private rng_state_u32: number;

  private max_total_length_u32: number;

  private include_r_component_bool: boolean;
  private include_q_component_bool: boolean;
  private include_f_component_bool: boolean;

  private include_known_examples_bool: boolean;
  private include_pct_encoding_bool: boolean;
  private include_non_ascii_bool: boolean;

  public constructor(params: urn_url_fuzzer_options_t = {}) {
    this.rng_state_u32 = params.seed_u32 ?? 0xc0ffee11;

    this.max_total_length_u32 = params.max_total_length_u32 ?? 64_000;

    this.include_r_component_bool = params.include_r_component_bool ?? true;
    this.include_q_component_bool = params.include_q_component_bool ?? true;
    this.include_f_component_bool = params.include_f_component_bool ?? true;

    this.include_known_examples_bool =
      params.include_known_examples_bool ?? true;
    this.include_pct_encoding_bool = params.include_pct_encoding_bool ?? true;
    this.include_non_ascii_bool = params.include_non_ascii_bool ?? false;
  }

  // -----------------------------
  // Public API
  // -----------------------------

  public generateValidUrnUrls(params: { count_u32: number }): string[] {
    const count_u32 = params.count_u32 >>> 0;
    const out_arr: string[] = [];

    const validator = new URNURLValidator({
      allow_any_valid_nid_bool: true,
      allow_f_component_bool: true,
      allow_q_component_bool: true,
      allow_r_component_bool: true,
      require_well_formed_pct_encoding_in_nss_bool: true
    });

    for (let i_u32 = 0; i_u32 < count_u32; ) {
      const url = this.generateOneValidUrnUrl();
      const validation_result = validator.validate({ urn_url_str: url });
      if (!validation_result?.is_valid_bool) continue;
      out_arr.push(url);
      i_u32++;
    }

    return out_arr;
  }

  public generateInvalidUrnUrls(params: { count_u32: number }): string[] {
    const count_u32 = params.count_u32 >>> 0;
    const out_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
      out_arr.push(this.generateOneInvalidUrnUrl());
    }

    return out_arr;
  }

  // -----------------------------
  // Valid URN generation (RFC 8141-ish)
  // urn:<NID>:<NSS>[?+r][?=q][#f]
  // -----------------------------

  private generateOneValidUrnUrl(): string {
    if (
      this.include_known_examples_bool &&
      this.nextBool({ chance_f64: 0.12 })
    ) {
      const examples_arr = [
        'urn:ietf:rfc:3986',
        'urn:ietf:rfc:8141',
        'urn:isbn:0451450523',
        'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
        'URN:EXAMPLE:a123,z456',
        'urn:oid:1.2.840.113549.1.1.5'
      ];
      return examples_arr[this.nextU32({ max_u32: examples_arr.length })];
    }

    const scheme_str = this.nextBool({ chance_f64: 0.2 }) ? 'URN' : 'urn';

    const nid_str = this.generateValidNid();
    const nss_str = this.generateValidNss();

    let r_str: string | undefined = undefined;
    let q_str: string | undefined = undefined;
    let f_str: string | undefined = undefined;

    if (this.include_r_component_bool && this.nextBool({ chance_f64: 0.35 })) {
      r_str = this.generateValidComponent({ max_len_u32: 48 });
    }
    if (this.include_q_component_bool && this.nextBool({ chance_f64: 0.35 })) {
      q_str = this.generateValidComponent({ max_len_u32: 48 });
    }
    if (this.include_f_component_bool && this.nextBool({ chance_f64: 0.35 })) {
      f_str = this.generateValidComponent({ max_len_u32: 48 });
    }

    // RFC 8141 ordering is r then q then f; generate in that order (most parsers expect it)
    let urn_str = `${scheme_str}:${nid_str}:${nss_str}`;
    if (r_str !== undefined) {
      urn_str += `?+${r_str}`;
    }
    if (q_str !== undefined) {
      urn_str += `?=${q_str}`;
    }
    if (f_str !== undefined) {
      urn_str += `#${f_str}`;
    }

    if (urn_str.length > this.max_total_length_u32) {
      urn_str = urn_str.slice(0, this.max_total_length_u32);
    }
    return urn_str;
  }

  private generateValidNid(): string {
    // RFC 8141: NID length 1..31, first char alnum, remaining alnum or '-'
    const len_u32 = 1 + this.nextU32({ max_u32: 31 });

    let out_str = this.randomAlnumChar();
    for (let i_u32 = 1; i_u32 < len_u32; i_u32++) {
      if (this.nextBool({ chance_f64: 0.15 })) {
        out_str += '-';
      } else {
        out_str += this.randomAlnumChar();
      }
    }

    // Bias to some realistic NIDs sometimes
    if (this.nextBool({ chance_f64: 0.25 })) {
      const common_arr = [
        'ietf',
        'uuid',
        'isbn',
        'oid',
        'example',
        'w3',
        'urn-1'
      ];
      return common_arr[this.nextU32({ max_u32: common_arr.length })];
    }

    return out_str.toLowerCase();
  }

  private generateValidNss(): string {
    // NSS is namespace-specific; RFC 8141 allows a broad char set (pchar + some extras),
    // excluding whitespace/controls. We'll generate a conservative "pchar-ish" set + ':' and '/'.
    const base_len_u32 = 1 + this.nextU32({ max_u32: 80 });

    const nss_mode_u32 = this.nextU32({ max_u32: 6 });
    if (nss_mode_u32 === 0) {
      // uuid style
      return this.generateUuidLike();
    }
    if (nss_mode_u32 === 1) {
      // rfc-ish: "rfc:3986"
      return `rfc:${1000 + this.nextU32({ max_u32: 9000 })}`;
    }
    if (nss_mode_u32 === 2) {
      // oid-ish dotted numbers
      return this.generateOidLike();
    }

    let out_str = '';
    for (let i_u32 = 0; i_u32 < base_len_u32; i_u32++) {
      const mode_u32 = this.nextU32({ max_u32: 12 });

      if (mode_u32 <= 6) {
        out_str += this.randomUrnChar({
          allow_non_ascii_bool: this.include_non_ascii_bool
        });
        continue;
      }

      if (mode_u32 <= 8 && this.include_pct_encoding_bool) {
        const byte_u32 = this.nextU32({ max_u32: 256 });
        out_str += '%' + byte_u32.toString(16).toUpperCase().padStart(2, '0');
        continue;
      }

      // delimiters commonly used in NSS
      const delim_arr = [
        ':',
        '/',
        '.',
        ',',
        '-',
        '_',
        '~',
        '!',
        '$',
        '&',
        "'",
        '(',
        ')',
        '*',
        '+',
        ';',
        '='
      ];
      out_str += delim_arr[this.nextU32({ max_u32: delim_arr.length })];
    }

    // Avoid accidental component markers that would prematurely start r/q or fragment
    out_str = out_str.replace(/\?=|\?\+|#/g, ':');

    // Avoid whitespace/controls by construction; trim to reasonable size
    return out_str.slice(0, 200);
  }

  private generateValidComponent(params: { max_len_u32: number }): string {
    const max_len_u32 = params.max_len_u32 >>> 0;
    const len_u32 = this.nextU32({ max_u32: Math.max(1, max_len_u32 + 1) });

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const mode_u32 = this.nextU32({ max_u32: 10 });

      if (mode_u32 <= 6) {
        out_str += this.randomUrnChar({
          allow_non_ascii_bool: this.include_non_ascii_bool
        });
        continue;
      }

      if (mode_u32 <= 8 && this.include_pct_encoding_bool) {
        const byte_u32 = this.nextU32({ max_u32: 256 });
        out_str += '%' + byte_u32.toString(16).toUpperCase().padStart(2, '0');
        continue;
      }

      // safe delimiters; do NOT include "#", and avoid "?+" "?=" sequences
      const delim_arr = [
        ':',
        '/',
        '.',
        ',',
        '-',
        '_',
        '~',
        '!',
        '$',
        '&',
        "'",
        '(',
        ')',
        '*',
        '+',
        ';',
        '=',
        '@'
      ];
      out_str += delim_arr[this.nextU32({ max_u32: delim_arr.length })];
    }

    // Prevent accidentally generating marker sequences inside the component
    out_str = out_str.replace(/\?=|\?\+/g, '%3F');
    out_str = out_str.replace(/#/g, '%23');

    return out_str;
  }

  private randomUrnChar(params: { allow_non_ascii_bool: boolean }): string {
    const unreserved_str =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    const subdelims_str = "!$&'()*+,;=";

    const roll_u32 = this.nextU32({ max_u32: 100 });

    if (roll_u32 < 70) {
      return unreserved_str[this.nextU32({ max_u32: unreserved_str.length })];
    }
    if (roll_u32 < 92) {
      return subdelims_str[this.nextU32({ max_u32: subdelims_str.length })];
    }
    if (roll_u32 < 98) {
      const extra_arr = [':', '@', '/'];
      return extra_arr[this.nextU32({ max_u32: extra_arr.length })];
    }

    if (params.allow_non_ascii_bool) {
      const unicode_arr = ['✓', 'é', '中', 'λ', 'Ω'];
      return unicode_arr[this.nextU32({ max_u32: unicode_arr.length })];
    }

    return 'a';
  }

  private generateUuidLike(): string {
    // 8-4-4-4-12 hex
    const hex_str = '0123456789abcdef';
    const part_lens_arr = [8, 4, 4, 4, 12];
    let out_str = '';

    for (let p_u32 = 0; p_u32 < part_lens_arr.length; p_u32++) {
      if (p_u32 > 0) {
        out_str += '-';
      }
      const part_len_u32 = part_lens_arr[p_u32];
      for (let i_u32 = 0; i_u32 < part_len_u32; i_u32++) {
        out_str += hex_str[this.nextU32({ max_u32: hex_str.length })];
      }
    }

    return out_str;
  }

  private generateOidLike(): string {
    const arc_count_u32 = 2 + this.nextU32({ max_u32: 8 });
    let out_str = '';

    for (let i_u32 = 0; i_u32 < arc_count_u32; i_u32++) {
      const arc_u32 =
        i_u32 === 0
          ? this.nextU32({ max_u32: 3 })
          : 1 + this.nextU32({ max_u32: 5000 });
      out_str += arc_u32.toString(10);
      if (i_u32 + 1 < arc_count_u32) {
        out_str += '.';
      }
    }

    return out_str;
  }

  // -----------------------------
  // Invalid URN generation
  // -----------------------------

  private generateOneInvalidUrnUrl(): string {
    // Broad set of "should not parse" or "parser breaker" cases:
    // - missing pieces, wrong separators, invalid NID chars/length
    // - whitespace/control injection
    // - malformed percent-encoding
    // - duplicate / out-of-order components
    // - extremely long segments (stress)
    // - marker confusion (?+ ?= # inside NSS)
    const mode_u32 = this.nextU32({ max_u32: 18 });

    if (mode_u32 === 0) {
      return 'urn'; // missing ':'
    }
    if (mode_u32 === 1) {
      return 'urn:'; // missing nid:nss
    }
    if (mode_u32 === 2) {
      return 'urn::nss'; // empty nid
    }
    if (mode_u32 === 3) {
      return 'urn:nid:'; // empty nss
    }
    if (mode_u32 === 4) {
      return 'urn:-bad:nss'; // nid must start with alnum
    }
    if (mode_u32 === 5) {
      return 'urn:ni$d:nss'; // invalid nid char
    }
    if (mode_u32 === 6) {
      return `urn:${'a'.repeat(40)}:nss`; // nid too long
    }
    if (mode_u32 === 7) {
      return 'urn:ietf:rfc:3986#frag#again'; // multiple fragments
    }
    if (mode_u32 === 8) {
      return 'urn:ietf:rfc:3986?=q?=q2'; // duplicate q
    }
    if (mode_u32 === 9) {
      return 'urn:ietf:rfc:3986?+r?+r2'; // duplicate r
    }
    if (mode_u32 === 10) {
      // out-of-order / confusing markers
      return 'urn:ietf:rfc:3986?=q?+r';
    }
    if (mode_u32 === 11) {
      // marker in NSS (can confuse naive splitters)
      return 'urn:example:abc?+def:ghi';
    }
    if (mode_u32 === 12) {
      return 'urn:example:abc%2'; // malformed percent
    }
    if (mode_u32 === 13) {
      return 'urn:example:abc%GG'; // malformed percent hex
    }
    if (mode_u32 === 14) {
      return 'urn:example:abc def'; // space in NSS
    }
    if (mode_u32 === 15) {
      return 'urn:example:abc\u0001def'; // control in NSS
    }
    if (mode_u32 === 16) {
      // Huge NSS to stress parser (still syntactically questionable because of markers)
      const big_str = 'a'.repeat(
        Math.min(this.max_total_length_u32 + 1024, 200_000)
      );
      return `urn:example:${big_str}`;
    }

    // mode 17: wrong scheme and mixed casing confusion
    return 'uRnX:example:nss';
  }

  // -----------------------------
  // RNG helpers
  // -----------------------------

  private nextU32(params: { max_u32: number }): number {
    const max_u32 = params.max_u32 >>> 0;
    if (max_u32 === 0) {
      return 0;
    }

    // xorshift32
    let x_u32 = this.rng_state_u32 >>> 0;
    x_u32 ^= (x_u32 << 13) >>> 0;
    x_u32 ^= (x_u32 >>> 17) >>> 0;
    x_u32 ^= (x_u32 << 5) >>> 0;
    this.rng_state_u32 = x_u32 >>> 0;

    return this.rng_state_u32 % max_u32 >>> 0;
  }

  private nextBool(params: { chance_f64: number }): boolean {
    const roll_u32 = this.nextU32({ max_u32: 1_000_000 });
    return roll_u32 < Math.floor(params.chance_f64 * 1_000_000);
  }

  private randomAlnumChar(): string {
    const alphabet_str =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return alphabet_str[this.nextU32({ max_u32: alphabet_str.length })];
  }
}
