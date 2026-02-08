type prng_state_t = {
  state_u32: number;
};

type about_url_fuzzer_options_t = {
  seed_u32?: number;
  max_component_length_u32?: number;
  max_total_length_u32?: number;
};

export class AboutURLFuzzer {
  private prng_state: prng_state_t;
  private max_component_length_u32: number;
  private max_total_length_u32: number;

  public constructor(params: about_url_fuzzer_options_t = {}) {
    const seed_u32 = (params.seed_u32 ?? 0x9e3779b9) >>> 0;

    this.prng_state = { state_u32: seed_u32 === 0 ? 0x1a2b3c4d : seed_u32 };
    this.max_component_length_u32 = params.max_component_length_u32 ?? 128;
    this.max_total_length_u32 = params.max_total_length_u32 ?? 2048;
  }

  public generateValidAboutUrls(params: { count_u32: number }): string[] {
    const urls_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < params.count_u32; i_u32++) {
      urls_arr.push(this.makeValidAboutUrl());
    }

    return urls_arr;
  }

  public generateInvalidAboutUrls(params: { count_u32: number }): string[] {
    const urls_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < params.count_u32; i_u32++) {
      urls_arr.push(this.makeInvalidAboutUrl());
    }

    return urls_arr;
  }

  private makeValidAboutUrl(): string {
    // Conservative "known good" tokens for modern about parsing.
    const scheme_str = this.pickOne({
      items_arr: ['about', 'About', 'ABOUT', 'aBoUt']
    });

    const primary_path_str = this.pickOne({
      items_arr: ['blank', 'srcdoc']
    });

    const include_query_bool = this.chance({ prct_u32: 20 });
    const include_fragment_bool = this.chance({ prct_u32: 35 });

    const query_str = include_query_bool ? this.makeValidQuery() : '';
    const fragment_str = include_fragment_bool ? this.makeValidFragment() : '';

    const path_variant_str = this.pickOne({
      items_arr: [
        primary_path_str,
        primary_path_str.toUpperCase(),
        primary_path_str[0].toUpperCase() + primary_path_str.slice(1),
        this.percentEncodeAsciiToken({ token_str: primary_path_str })
      ]
    });

    const url_str = `${scheme_str}:${path_variant_str}${query_str}${fragment_str}`;
    return this.truncateTotal({ url_str });
  }

  private makeInvalidAboutUrl(): string {
    const base_str = this.pickOne({
      items_arr: [
        'about',
        'About',
        'ABOUT',
        'aBoUt',
        'ab\u0000out',
        'abo\u000dt',
        'abo\u000at',
        'abo\u001bt'
      ]
    });

    const variant_str = this.pickOne({
      items_arr: [
        // Scheme delimiter issues
        `${base_str}`, // missing colon
        `${base_str}::blank`, // extra colon
        `${base_str} :blank`, // whitespace around colon
        `${base_str}:\tblank`, // tab after colon
        `${base_str}:\nblank`, // newline after colon
        `${base_str}:\r\nblank`, // CRLF injection
        `${base_str}:\u0000blank`, // NUL injection

        // Authority-like / slash confusion
        `${base_str}://blank`,
        `${base_str}:///blank`,
        `${base_str}:////blank`,
        `${base_str}://?q=1`,
        `${base_str}://#frag`,
        `${base_str}://user:pass@host/`,
        `${base_str}://host/%2e%2e/%2e%2e/`,

        // Malformed percent encoding
        `${base_str}:%`,
        `${base_str}:%0`,
        `${base_str}:%GG`,
        `${base_str}:%zz`,
        `${base_str}:blank%`,
        `${base_str}:blank%2`,
        `${base_str}:blank%G0`,
        `${base_str}:blank%0G`,

        // Delimiter storms / ambiguous parsing
        `${base_str}:`,
        `${base_str}:?`,
        `${base_str}:#`,
        `${base_str}:??`,
        `${base_str}:##`,
        `${base_str}:blank??q==&&`,
        `${base_str}:blank###frag`,
        `${base_str}:blank?#`,
        `${base_str}:blank#?`,
        `${base_str}:blank?%GG=1`,
        `${base_str}:blank?x=%`,
        `${base_str}:blank?x=%0`,
        `${base_str}:blank?x=%2`,
        `${base_str}:blank?x=%zz`,

        // Confusing path tokens / separators
        `${base_str}:\\blank`,
        `${base_str}:/blank`,
        `${base_str}://\\blank`,
        `${base_str}:blank/../../etc/passwd`,
        `${base_str}:blank\u0000`,
        `${base_str}:blank\u000d\u000aHeader: injected`,

        // Unicode edge cases
        `${base_str}:bl\u202eank`, // RTL override
        `${base_str}:\u202dblank`, // LTR override
        `${base_str}:\ufeffblank`, // BOM
        `${base_str}:\ud800`, // unpaired surrogate
        `${base_str}:bl\u0301ank` // combining mark
      ]
    });

    const add_random_payload_bool = this.chance({ prct_u32: 60 });
    const payload_str = add_random_payload_bool ? this.makeNastyPayload() : '';

    const url_str = `${variant_str}${payload_str}`;
    return this.truncateTotal({ url_str });
  }

  private makeValidQuery(): string {
    const pairs_count_u32 = this.randRangeU32({ min_u32: 1, max_u32: 4 });
    const pairs_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < pairs_count_u32; i_u32++) {
      const key_str = this.makeValidToken({ min_len_u32: 1, max_len_u32: 12 });
      const value_str = this.makeValidToken({
        min_len_u32: 0,
        max_len_u32: 24
      });

      const encoded_key_str = this.percentEncodeLimited({ token_str: key_str });
      const encoded_value_str = this.percentEncodeLimited({
        token_str: value_str
      });

      pairs_arr.push(`${encoded_key_str}=${encoded_value_str}`);
    }

    return `?${pairs_arr.join('&')}`;
  }

  private makeValidFragment(): string {
    const frag_str = this.makeValidToken({ min_len_u32: 0, max_len_u32: 48 });
    const encoded_frag_str = this.percentEncodeLimited({ token_str: frag_str });
    return `#${encoded_frag_str}`;
  }

  private makeValidToken(params: {
    min_len_u32: number;
    max_len_u32: number;
  }): string {
    const len_u32 = this.randRangeU32({
      min_u32: params.min_len_u32,
      max_u32: params.max_len_u32
    });

    const alphabet_str =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
    let out_str = '';

    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const idx_u32 = this.randRangeU32({
        min_u32: 0,
        max_u32: alphabet_str.length - 1
      });
      out_str += alphabet_str[idx_u32];
    }

    if (
      this.chance({ prct_u32: 20 }) &&
      out_str.length < this.max_component_length_u32 - 2
    ) {
      const safe_unicode_str = this.pickOne({
        items_arr: ['é', 'ß', 'Ω', '中', 'あ']
      });
      const insert_at_u32 = this.randRangeU32({
        min_u32: 0,
        max_u32: out_str.length
      });
      out_str =
        out_str.slice(0, insert_at_u32) +
        safe_unicode_str +
        out_str.slice(insert_at_u32);
    }

    return out_str.slice(0, this.max_component_length_u32);
  }

  private percentEncodeAsciiToken(params: { token_str: string }): string {
    let out_str = '';

    for (let i_u32 = 0; i_u32 < params.token_str.length; i_u32++) {
      const ch_str = params.token_str[i_u32];
      const code_u32 = params.token_str.charCodeAt(i_u32);

      const is_ascii_alnum_bool =
        (code_u32 >= 0x30 && code_u32 <= 0x39) ||
        (code_u32 >= 0x41 && code_u32 <= 0x5a) ||
        (code_u32 >= 0x61 && code_u32 <= 0x7a);

      if (is_ascii_alnum_bool) {
        out_str += ch_str;
      } else {
        out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
      }
    }

    return out_str;
  }

  private percentEncodeLimited(params: { token_str: string }): string {
    const unreserved_set = new Set<string>([
      ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'
    ]);

    let out_str = '';

    for (let i_u32 = 0; i_u32 < params.token_str.length; i_u32++) {
      const ch_str = params.token_str[i_u32];

      if (unreserved_set.has(ch_str)) {
        out_str += ch_str;
        continue;
      }

      const code_u32 = params.token_str.charCodeAt(i_u32);

      if (code_u32 <= 0xff) {
        out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
      } else {
        out_str += this.pctByte({ byte_u8: (code_u32 >>> 8) & 0xff });
        out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
      }
    }

    return out_str.slice(0, this.max_component_length_u32);
  }

  private makeNastyPayload(): string {
    const mode_str = this.pickOne({
      items_arr: [
        'controls',
        'slashes',
        'percent',
        'delimiters',
        'unicode',
        'long'
      ]
    });

    if (mode_str === 'controls') {
      return this.makeControlsString({ max_len_u32: 64 });
    }

    if (mode_str === 'slashes') {
      const slash_count_u32 = this.randRangeU32({ min_u32: 1, max_u32: 64 });
      const backslash_count_u32 = this.randRangeU32({
        min_u32: 0,
        max_u32: 32
      });
      return '/'.repeat(slash_count_u32) + '\\'.repeat(backslash_count_u32);
    }

    if (mode_str === 'percent') {
      const patterns_arr = [
        '%',
        '%0',
        '%GG',
        '%2',
        '%zz',
        '%u0000',
        '%\n',
        '%\r\n'
      ];
      const count_u32 = this.randRangeU32({ min_u32: 1, max_u32: 32 });

      let out_str = '';
      for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
        out_str += this.pickOne({ items_arr: patterns_arr });
      }
      return out_str;
    }

    if (mode_str === 'delimiters') {
      const pieces_arr = [
        '?',
        '#',
        '&',
        '=',
        ':',
        '@',
        ';',
        ',',
        '!',
        '$',
        "'",
        '"',
        '<',
        '>',
        '{',
        '}',
        '[',
        ']'
      ];
      const count_u32 = this.randRangeU32({ min_u32: 8, max_u32: 128 });

      let out_str = '';
      for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
        out_str += this.pickOne({ items_arr: pieces_arr });
      }
      return out_str;
    }

    if (mode_str === 'unicode') {
      const tricky_arr = [
        '\u202e', // RTL override
        '\u202d', // LTR override
        '\u2066', // LRI
        '\u2067', // RLI
        '\u2069', // PDI
        '\ufeff', // BOM
        '\ud800', // unpaired surrogate
        '\u0000' // NUL
      ];

      const count_u32 = this.randRangeU32({ min_u32: 1, max_u32: 32 });

      let out_str = '';
      for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
        out_str += this.pickOne({ items_arr: tricky_arr });
      }
      return out_str;
    }

    // mode_str === "long"
    {
      const min_len_u32 = 512;
      const max_len_u32 = Math.max(512, this.max_total_length_u32 * 2);
      const target_len_u32 = this.randRangeU32({
        min_u32: min_len_u32,
        max_u32: max_len_u32
      });

      const alphabet_str =
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let out_str = '';

      while (out_str.length < target_len_u32) {
        const idx_u32 = this.randRangeU32({
          min_u32: 0,
          max_u32: alphabet_str.length - 1
        });
        out_str += alphabet_str[idx_u32];
      }

      return out_str;
    }
  }

  private makeControlsString(params: { max_len_u32: number }): string {
    const controls_arr = [
      '\u0000',
      '\u0001',
      '\u0002',
      '\u0003',
      '\u0004',
      '\u0008',
      '\u0009',
      '\u000a',
      '\u000b',
      '\u000c',
      '\u000d',
      '\u001b',
      '\u007f'
    ];

    const len_u32 = this.randRangeU32({
      min_u32: 1,
      max_u32: params.max_len_u32
    });

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      out_str += this.pickOne({ items_arr: controls_arr });
    }

    return out_str;
  }

  private truncateTotal(params: { url_str: string }): string {
    if (params.url_str.length <= this.max_total_length_u32) {
      return params.url_str;
    }
    return params.url_str.slice(0, this.max_total_length_u32);
  }

  private pctByte(params: { byte_u8: number }): string {
    const hex_str = (params.byte_u8 & 0xff)
      .toString(16)
      .toUpperCase()
      .padStart(2, '0');
    return `%${hex_str}`;
  }

  private randU32(): number {
    // xorshift32
    let x_u32 = this.prng_state.state_u32 >>> 0;

    x_u32 ^= (x_u32 << 13) >>> 0;
    x_u32 ^= (x_u32 >>> 17) >>> 0;
    x_u32 ^= (x_u32 << 5) >>> 0;

    this.prng_state.state_u32 = x_u32 >>> 0;
    return this.prng_state.state_u32;
  }

  private randRangeU32(params: { min_u32: number; max_u32: number }): number {
    const min_u32 = params.min_u32 >>> 0;
    const max_u32 = params.max_u32 >>> 0;

    if (max_u32 <= min_u32) {
      return min_u32;
    }

    const span_u32 = (max_u32 - min_u32 + 1) >>> 0;
    const value_u32 = this.randU32();
    return (min_u32 + (value_u32 % span_u32)) >>> 0;
  }

  private chance(params: { prct_u32: number }): boolean {
    const prct_u32 = Math.max(0, Math.min(100, params.prct_u32 >>> 0));
    const roll_u32 = this.randRangeU32({ min_u32: 1, max_u32: 100 });
    return roll_u32 <= prct_u32;
  }

  private pickOne<T>(params: { items_arr: T[] }): T {
    if (params.items_arr.length === 0) {
      throw new Error('pickOne called with empty array');
    }

    const idx_u32 = this.randRangeU32({
      min_u32: 0,
      max_u32: params.items_arr.length - 1
    });
    return params.items_arr[idx_u32];
  }
}
