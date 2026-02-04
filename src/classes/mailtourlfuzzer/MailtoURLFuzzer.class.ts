type prng_state_t = {
  state_u32: number;
};

interface mailto_url_fuzzer_options_i {
  seed_u32?: number;

  max_total_length_u32?: number;
  max_addr_count_u32?: number;

  max_local_part_length_u32?: number;
  max_domain_length_u32?: number;

  max_query_pairs_u32?: number;
  max_query_value_length_u32?: number;

  // If true, valid generator will sometimes emit internationalized local/domain labels (still URL-escaped where needed).
  allow_smtp_utf8_bool?: boolean;
}

export class MailtoURLFuzzer {
  private prng_state: prng_state_t;

  private max_total_length_u32: number;
  private max_addr_count_u32: number;

  private max_local_part_length_u32: number;
  private max_domain_length_u32: number;

  private max_query_pairs_u32: number;
  private max_query_value_length_u32: number;

  private allow_smtp_utf8_bool: boolean;

  public constructor(params: mailto_url_fuzzer_options_i = {}) {
    const seed_u32 = (params.seed_u32 ?? 0x9e3779b9) >>> 0;

    this.prng_state = { state_u32: seed_u32 === 0 ? 0x1a2b3c4d : seed_u32 };

    this.max_total_length_u32 = params.max_total_length_u32 ?? 2048;
    this.max_addr_count_u32 = params.max_addr_count_u32 ?? 6;

    this.max_local_part_length_u32 = params.max_local_part_length_u32 ?? 64;
    this.max_domain_length_u32 = params.max_domain_length_u32 ?? 253;

    this.max_query_pairs_u32 = params.max_query_pairs_u32 ?? 8;
    this.max_query_value_length_u32 = params.max_query_value_length_u32 ?? 256;

    this.allow_smtp_utf8_bool = params.allow_smtp_utf8_bool ?? false;
  }

  public generateValidMailtoUrls(params: { count_u32: number }): string[] {
    const urls_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < params.count_u32; i_u32++) {
      urls_arr.push(this.makeValidMailtoURL());
    }

    return urls_arr;
  }

  public generateInvalidMailtoUrls(params: { count_u32: number }): string[] {
    const urls_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < params.count_u32; i_u32++) {
      urls_arr.push(this.makeInvalidMailtoURL());
    }

    return urls_arr;
  }

  // -----------------------------
  // Valid generator
  // -----------------------------

  private makeValidMailtoURL(): string {
    const scheme_str = this.pickOne({
      items_arr: ['mailto', 'MAILTO', 'Mailto', 'mAiLtO']
    });

    const addr_count_u32 = this.randRangeU32({
      min_u32: 1,
      max_u32: this.max_addr_count_u32
    });
    const addrs_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < addr_count_u32; i_u32++) {
      addrs_arr.push(this.makeValidAddrSpec());
    }

    const to_part_str = addrs_arr.join(',');

    const include_query_bool = this.chance({ prct_u32: 60 });
    const query_str = include_query_bool ? this.makeValidQuery() : '';

    const url_str = `${scheme_str}:${to_part_str}${query_str}`;
    return this.truncateTotal({ url_str });
  }

  private makeValidAddrSpec(): string {
    // Generate either:
    // - a normal addr-spec local@domain
    // - or a "local-only" (allowed by RFC 6068, interpreted as local-part without a domain in some contexts)
    const choose_local_only_bool = this.chance({ prct_u32: 10 });

    const local_str = this.makeValidLocalPart();

    if (choose_local_only_bool) {
      return this.percentEncodeMailtoTo({ input_str: local_str });
    }

    const domain_str = this.makeValidDomain();

    // Encode only characters that must be percent-encoded in the "to" component
    return this.percentEncodeMailtoTo({
      input_str: `${local_str}@${domain_str}`
    });
  }

  private makeValidLocalPart(): string {
    const use_quoted_bool = this.chance({ prct_u32: 20 });

    if (use_quoted_bool) {
      // Quoted-string local-part: "...."
      const inner_str = this.makeQuotedLocalInner({
        max_len_u32: this.randRangeU32({ min_u32: 1, max_u32: 24 })
      });
      return `"${inner_str}"`;
    }

    // Dot-atom: atext / "." separated, no leading/trailing dot and no consecutive dots.
    const atom_count_u32 = this.randRangeU32({ min_u32: 1, max_u32: 4 });
    const atoms_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < atom_count_u32; i_u32++) {
      atoms_arr.push(
        this.makeDotAtomText({
          max_len_u32: this.randRangeU32({ min_u32: 1, max_u32: 12 })
        })
      );
    }

    let local_str = atoms_arr.join('.');

    // Occasionally include SMTPUTF8 in local-part if allowed (still can be valid for modern stacks).
    if (this.allow_smtp_utf8_bool && this.chance({ prct_u32: 15 })) {
      const utf8_piece_str = this.pickOne({
        items_arr: ['é', 'ß', 'Ω', '中', 'あ']
      });
      const insert_at_u32 = this.randRangeU32({
        min_u32: 0,
        max_u32: local_str.length
      });
      local_str =
        local_str.slice(0, insert_at_u32) +
        utf8_piece_str +
        local_str.slice(insert_at_u32);
    }

    return local_str.slice(0, this.max_local_part_length_u32);
  }

  private makeDotAtomText(params: { max_len_u32: number }): string {
    const alphabet_str =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~";
    const len_u32 = this.randRangeU32({
      min_u32: 1,
      max_u32: Math.max(1, params.max_len_u32)
    });

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const idx_u32 = this.randRangeU32({
        min_u32: 0,
        max_u32: alphabet_str.length - 1
      });
      out_str += alphabet_str[idx_u32];
    }

    return out_str;
  }

  private makeQuotedLocalInner(params: { max_len_u32: number }): string {
    // qtext / quoted-pair; avoid CR/LF, but allow escaped specials.
    const safe_arr = [
      ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ',
      '!',
      '#',
      '$',
      '%',
      '&',
      "'",
      '(',
      ')',
      '*',
      '+',
      ',',
      '-',
      '.',
      '/',
      ':',
      ';',
      '<',
      '=',
      '>',
      '?',
      '@',
      '[',
      ']',
      '^',
      '_',
      '`',
      '{',
      '|',
      '}',
      '~'
    ];

    const len_u32 = this.randRangeU32({
      min_u32: 1,
      max_u32: Math.max(1, params.max_len_u32)
    });

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const ch_str = this.pickOne({ items_arr: safe_arr });

      // Escape backslash or double-quote
      if (ch_str === '\\' || ch_str === '"') {
        out_str += `\\${ch_str}`;
        continue;
      }

      out_str += ch_str;
    }

    return out_str;
  }

  private makeValidIpv6DomainLiteral(): string {
    const groups_arr: string[] = [];

    // Always generate 8 hextets (valid baseline)
    for (let i_u32 = 0; i_u32 < 8; i_u32++) {
      // Bias toward zeros so compression is meaningful and exercised
      const make_zero_bool = this.chance({ prct_u32: 25 });
      groups_arr.push(make_zero_bool ? '0' : this.hexGroup());
    }

    let ipv6_str = groups_arr.join(':');

    // Optionally compress a run of zero groups into "::"
    if (this.chance({ prct_u32: 35 })) {
      ipv6_str = this.compressIpv6Zeros({ ipv6_str });
    }

    return `[IPv6:${ipv6_str}]`;
  }

  private compressIpv6Zeros(params: { ipv6_str: string }): string {
    const parts_arr = params.ipv6_str.split(':');
    const norm_parts_arr = parts_arr.map((p_str) =>
      this.normalizeHextet({ hextet_str: p_str })
    );

    // Find the longest run of "0" hextets to compress
    let best_start_i32 = -1;
    let best_len_i32 = 0;

    let cur_start_i32 = -1;
    let cur_len_i32 = 0;

    for (let i_i32 = 0; i_i32 < norm_parts_arr.length; i_i32++) {
      const is_zero_bool = norm_parts_arr[i_i32] === '0';
      if (is_zero_bool) {
        if (cur_start_i32 === -1) {
          cur_start_i32 = i_i32;
          cur_len_i32 = 1;
        } else {
          cur_len_i32++;
        }
      } else {
        if (cur_len_i32 > best_len_i32) {
          best_start_i32 = cur_start_i32;
          best_len_i32 = cur_len_i32;
        }
        cur_start_i32 = -1;
        cur_len_i32 = 0;
      }
    }

    if (cur_len_i32 > best_len_i32) {
      best_start_i32 = cur_start_i32;
      best_len_i32 = cur_len_i32;
    }

    // RFC-ish behavior: only compress if run length >= 2
    if (best_len_i32 < 2) {
      return norm_parts_arr.join(':');
    }

    const left_arr = norm_parts_arr.slice(0, best_start_i32);
    const right_arr = norm_parts_arr.slice(best_start_i32 + best_len_i32);

    const left_str = left_arr.join(':');
    const right_str = right_arr.join(':');

    if (left_str.length === 0 && right_str.length === 0) {
      return '::';
    }
    if (left_str.length === 0) {
      return `::${right_str}`;
    }
    if (right_str.length === 0) {
      return `${left_str}::`;
    }
    return `${left_str}::${right_str}`;
  }

  private normalizeHextet(params: { hextet_str: string }): string {
    // normalize empty -> 0 (shouldn't happen with our generator), trim leading zeros
    let hextet_str = params.hextet_str.toLowerCase();
    if (hextet_str.length === 0) {
      return '0';
    }
    hextet_str = hextet_str.replace(/^0+/, '');
    return hextet_str.length === 0 ? '0' : hextet_str;
  }

  private hexGroup(): string {
    const len_u32 = this.randRangeU32({ min_u32: 1, max_u32: 4 });
    const hex_str = '0123456789abcdef';

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      out_str +=
        hex_str[this.randRangeU32({ min_u32: 0, max_u32: hex_str.length - 1 })];
    }
    return out_str;
  }

  private makeValidDomain(): string {
    // Generate either:
    // - reg-name style domain labels, or
    // - an IPv4 domain-literal, or
    // - an IPv6 domain-literal.
    const mode_str = this.pickOne({
      items_arr: ['dns', 'ipv4_lit', 'ipv6_lit']
    });

    if (mode_str === 'ipv4_lit') {
      const o1_u32 = this.randRangeU32({ min_u32: 0, max_u32: 255 });
      const o2_u32 = this.randRangeU32({ min_u32: 0, max_u32: 255 });
      const o3_u32 = this.randRangeU32({ min_u32: 0, max_u32: 255 });
      const o4_u32 = this.randRangeU32({ min_u32: 0, max_u32: 255 });
      return `[${o1_u32}.${o2_u32}.${o3_u32}.${o4_u32}]`;
    }

    if (mode_str === 'ipv6_lit') {
      return this.makeValidIpv6DomainLiteral();
    }

    // dns
    const labels_count_u32 = this.randRangeU32({ min_u32: 2, max_u32: 5 });
    const labels_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < labels_count_u32; i_u32++) {
      labels_arr.push(this.makeDNSLabel());
    }

    const domain_str = labels_arr.join('.');
    return domain_str.slice(0, this.max_domain_length_u32);
  }

  private makeDNSLabel(): string {
    // LDH label: letter/digit, interior letter/digit/hyphen, not starting/ending with hyphen.
    const start_alphabet_str =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const mid_alphabet_str =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-';

    const len_u32 = this.randRangeU32({ min_u32: 1, max_u32: 24 });

    let out_str = '';
    out_str +=
      start_alphabet_str[
        this.randRangeU32({
          min_u32: 0,
          max_u32: start_alphabet_str.length - 1
        })
      ];

    for (let i_u32 = 1; i_u32 < len_u32 - 1; i_u32++) {
      out_str +=
        mid_alphabet_str[
          this.randRangeU32({
            min_u32: 0,
            max_u32: mid_alphabet_str.length - 1
          })
        ];
    }

    if (len_u32 > 1) {
      out_str +=
        start_alphabet_str[
          this.randRangeU32({
            min_u32: 0,
            max_u32: start_alphabet_str.length - 1
          })
        ];
    }

    return out_str;
  }

  private makeValidQuery(): string {
    // RFC 6068 header fields commonly supported: subject, body, cc, bcc, in-reply-to
    // Also include arbitrary x- headers for parser robustness.
    const max_pairs_u32 = this.randRangeU32({
      min_u32: 1,
      max_u32: this.max_query_pairs_u32
    });
    const pairs_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < max_pairs_u32; i_u32++) {
      const key_str = this.pickOne({
        items_arr: [
          'subject',
          'body',
          'cc',
          'bcc',
          'in-reply-to',
          'to',
          'x-test',
          'x-foo',
          'x-bar'
        ]
      });

      const value_str = this.makeQueryValue({
        max_len_u32: this.randRangeU32({
          min_u32: 0,
          max_u32: this.max_query_value_length_u32
        })
      });

      // Use application/x-www-form-urlencoded style for common mailto handling:
      // space -> %20 (not '+', to avoid ambiguity between implementations)
      pairs_arr.push(
        `${this.percentEncodeQueryComponent({ input_str: key_str })}=${this.percentEncodeQueryComponent({ input_str: value_str })}`
      );
    }

    return `?${pairs_arr.join('&')}`;
  }

  private makeQueryValue(params: { max_len_u32: number }): string {
    const alphabet_arr = [
      ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
      ' ',
      '.',
      ',',
      '!',
      '?',
      '-',
      '_',
      ':',
      ';',
      '/',
      '\\',
      '@'
    ];

    const len_u32 = this.randRangeU32({
      min_u32: 0,
      max_u32: Math.max(0, params.max_len_u32)
    });

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      out_str += this.pickOne({ items_arr: alphabet_arr });
    }

    if (
      this.allow_smtp_utf8_bool &&
      this.chance({ prct_u32: 10 }) &&
      out_str.length < params.max_len_u32
    ) {
      out_str += this.pickOne({ items_arr: ['é', '中', 'Ω'] });
    }

    return out_str;
  }

  // -----------------------------
  // Invalid generator
  // -----------------------------

  private makeInvalidMailtoURL(): string {
    const scheme_str = this.pickOne({
      items_arr: [
        'mailto',
        'MAILTO',
        'Mailto',
        'mail\u0000to',
        'mail to',
        'mailto\u000d'
      ]
    });

    const variant_str = this.pickOne({
      items_arr: [
        // Missing colon / wrong delimiter
        `${scheme_str}`,
        `${scheme_str};user@example.com`,
        `${scheme_str}::user@example.com`,

        // Hierarchical form confusion
        `${scheme_str}://user@example.com`,
        `${scheme_str}:///user@example.com`,

        // Empty to-part when not allowed (some parsers allow, but many validators reject)
        `${scheme_str}:`,

        // Obvious addr-spec violations
        `${scheme_str}:@example.com`,
        `${scheme_str}:user@`,
        `${scheme_str}:user@@example.com`,
        `${scheme_str}:user example@example.com`,
        `${scheme_str}:user..dots@example.com`,
        `${scheme_str}:.leadingdot@example.com`,
        `${scheme_str}:trailingdot.@example.com`,
        `${scheme_str}:"unterminated@example.com`,
        `${scheme_str}:"bad\\escape@example.com`,

        // Domain issues
        `${scheme_str}:user@-example.com`,
        `${scheme_str}:user@example-.com`,
        `${scheme_str}:user@exa..mple.com`,
        `${scheme_str}:user@.example.com`,
        `${scheme_str}:user@example.com.`,
        `${scheme_str}:user@[300.1.1.1]`,
        `${scheme_str}:user@[IPv6:GGGG::1]`,

        // Percent-encoding hazards
        `${scheme_str}:user%`,
        `${scheme_str}:user%2`,
        `${scheme_str}:user%GG@example.com`,
        `${scheme_str}:user@example.com?subject=%`,
        `${scheme_str}:user@example.com?subject=%0`,
        `${scheme_str}:user@example.com?subject=%GG`,
        `${scheme_str}:user@example.com?body=%0d%0aInjected: header`,

        // Delimiter storms
        `${scheme_str}:user@example.com??subject=test`,
        `${scheme_str}:user@example.com&&subject=test`,
        `${scheme_str}:user@example.com?subject=test#frag`,
        `${scheme_str}:user@example.com#frag?subject=test`,

        // CRLF / control injection
        `${scheme_str}:user@example.com?\r\nsubject=x`,
        `${scheme_str}:user@example.com?subject=x\r\nbcc=evil@example.com`,
        `${scheme_str}:\u0000user@example.com`
      ]
    });

    const add_payload_bool = this.chance({ prct_u32: 70 });
    const payload_str = add_payload_bool ? this.makeNastyPayload() : '';

    const url_str = `${variant_str}${payload_str}`;
    return this.truncateTotal({ url_str });
  }

  private makeNastyPayload(): string {
    const mode_str = this.pickOne({
      items_arr: ['controls', 'percent', 'delimiters', 'unicode', 'long']
    });

    if (mode_str === 'controls') {
      return this.makeControlsString({ max_len_u32: 64 });
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
        '"',
        '<',
        '>',
        '{',
        '}',
        '[',
        ']',
        ' '
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
        '\u202e',
        '\u202d',
        '\u2066',
        '\u2067',
        '\u2069',
        '\ufeff',
        '\ud800',
        '\u0000'
      ];

      const count_u32 = this.randRangeU32({ min_u32: 1, max_u32: 32 });

      let out_str = '';
      for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
        out_str += this.pickOne({ items_arr: tricky_arr });
      }
      return out_str;
    }

    // long
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

  // -----------------------------
  // Encoding helpers
  // -----------------------------

  private percentEncodeMailtoTo(params: { input_str: string }): string {
    // For the "to" component, keep unreserved + a limited set of safe email chars.
    // Encode: space, controls, and delimiters that break URL structure.
    const input_str = params.input_str;

    let out_str = '';
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const ch_str = input_str[i_u32];
      const code_u32 = input_str.charCodeAt(i_u32);

      if (
        this.isUnreserved({ ch_str }) ||
        "@.!$&'()*+,;=-_~".includes(ch_str)
      ) {
        out_str += ch_str;
        continue;
      }

      if (code_u32 <= 0xff) {
        out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
        continue;
      }

      // Encode UTF-16 code units (parser input fuzz; still "URL string" safe)
      out_str += this.pctByte({ byte_u8: (code_u32 >>> 8) & 0xff });
      out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
    }

    return out_str;
  }

  private percentEncodeQueryComponent(params: { input_str: string }): string {
    const input_str = params.input_str;

    let out_str = '';
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const ch_str = input_str[i_u32];
      const code_u32 = input_str.charCodeAt(i_u32);

      // Keep unreserved; encode everything else (including space).
      if (this.isUnreserved({ ch_str })) {
        out_str += ch_str;
        continue;
      }

      if (code_u32 <= 0xff) {
        out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
      } else {
        out_str += this.pctByte({ byte_u8: (code_u32 >>> 8) & 0xff });
        out_str += this.pctByte({ byte_u8: code_u32 & 0xff });
      }
    }

    return out_str;
  }

  // -----------------------------
  // Utilities
  // -----------------------------

  private truncateTotal(params: { url_str: string }): string {
    if (params.url_str.length <= this.max_total_length_u32) {
      return params.url_str;
    }
    return params.url_str.slice(0, this.max_total_length_u32);
  }

  private hex_group(): string {
    const len_u32 = this.randRangeU32({ min_u32: 1, max_u32: 4 });
    const hex_str = '0123456789abcdef';
    let out_str = '';

    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      out_str +=
        hex_str[this.randRangeU32({ min_u32: 0, max_u32: hex_str.length - 1 })];
    }

    return out_str;
  }

  private pctByte(params: { byte_u8: number }): string {
    const hex_str = (params.byte_u8 & 0xff)
      .toString(16)
      .toUpperCase()
      .padStart(2, '0');
    return `%${hex_str}`;
  }

  private isUnreserved(params: { ch_str: string }): boolean {
    const ch_str = params.ch_str;
    if (ch_str.length !== 1) {
      return false;
    }

    const code_u32 = ch_str.charCodeAt(0);

    const is_alpha_bool =
      (code_u32 >= 0x41 && code_u32 <= 0x5a) ||
      (code_u32 >= 0x61 && code_u32 <= 0x7a);

    const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;

    const is_mark_bool =
      ch_str === '-' || ch_str === '.' || ch_str === '_' || ch_str === '~';

    return is_alpha_bool || is_digit_bool || is_mark_bool;
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
