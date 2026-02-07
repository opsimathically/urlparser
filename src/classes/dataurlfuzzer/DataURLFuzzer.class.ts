import { DataURLValidator } from '../dataurlvalidator/DataURLValidator.class';

type data_url_fuzzer_options_t = {
  seed_u32?: number;

  // Size controls
  max_total_length_u32?: number;
  max_data_length_u32?: number;

  // Generation knobs
  include_non_ascii_bool?: boolean;
  include_quoted_param_values_bool?: boolean;

  // If true, generate some "minimal" data URLs like "data:,"
  include_minimal_cases_bool?: boolean;
};

export class DataURLFuzzer {
  private rng_state_u32: number;

  private max_total_length_u32: number;
  private max_data_length_u32: number;

  private include_non_ascii_bool: boolean;
  private include_quoted_param_values_bool: boolean;
  private include_minimal_cases_bool: boolean;

  public constructor(params: data_url_fuzzer_options_t = {}) {
    this.rng_state_u32 = params.seed_u32 ?? 0xa5a5a5a5;

    this.max_total_length_u32 = params.max_total_length_u32 ?? 200_000;
    this.max_data_length_u32 = params.max_data_length_u32 ?? 100_000;

    this.include_non_ascii_bool = params.include_non_ascii_bool ?? true;
    this.include_quoted_param_values_bool =
      params.include_quoted_param_values_bool ?? true;
    this.include_minimal_cases_bool = params.include_minimal_cases_bool ?? true;
  }

  // -----------------------------
  // Public API
  // -----------------------------

  public generateValidDataUrls(params: { count_u32: number }): string[] {
    const count_u32 = params.count_u32 >>> 0;
    const out_arr: string[] = [];

    const data_validator = new DataURLValidator({
      allow_ascii_whitespace_in_data_bool: true,
      require_well_formed_pct_encoding_in_data_bool: true,
      strict_base64_bool: false,
      strict_media_type_bool: false
    });

    for (let i_u32 = 0; i_u32 < count_u32; ) {
      const url = this.generateOneValidDataUrl();
      const validation_result = data_validator.validate({
        data_url_str: url
      });
      if (!validation_result?.is_valid_bool) continue;
      out_arr.push(url);
      i_u32++;
    }

    return out_arr;
  }

  public generateInvalidDataUrls(params: { count_u32: number }): string[] {
    const count_u32 = params.count_u32 >>> 0;
    const out_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
      const url = this.generateOneInvalidDataUrl();
      out_arr.push(url);
    }
    return out_arr;
  }

  // -----------------------------
  // Valid generation
  // -----------------------------

  private generateOneValidDataUrl(): string {
    // RFC 2397: data:[<mediatype>][;base64],<data>
    // We generate a mix of:
    // - empty meta vs explicit media type
    // - charset param (token or quoted)
    // - additional params
    // - base64 and non-base64 payloads
    // - percent-encoded bytes in non-base64 data
    if (
      this.include_minimal_cases_bool &&
      this.nextBool({ chance_f64: 0.08 })
    ) {
      // Minimal valid forms seen in the wild
      const minimal_arr = [
        'data:,',
        'DATA:,Hello',
        'data:text/plain,Hello',
        'data:text/plain;charset=us-ascii,Hello'
      ];
      return minimal_arr[this.nextU32({ max_u32: minimal_arr.length })];
    }

    const use_explicit_media_type_bool = this.nextBool({ chance_f64: 0.75 });
    const include_base64_bool = this.nextBool({ chance_f64: 0.45 });

    const meta_parts_arr: string[] = [];

    if (use_explicit_media_type_bool) {
      meta_parts_arr.push(this.generateValidMediaType());
    } else {
      // empty mediatype is allowed
    }

    // Optionally add parameters (charset + arbitrary token params)
    const include_charset_bool = this.nextBool({ chance_f64: 0.55 });
    if (include_charset_bool) {
      meta_parts_arr.push(this.generateValidCharsetParam());
    }

    const extra_param_count_u32 = this.nextU32({ max_u32: 3 }); // 0..2
    for (let j_u32 = 0; j_u32 < extra_param_count_u32; j_u32++) {
      meta_parts_arr.push(this.generateValidTokenParam());
    }

    if (include_base64_bool) {
      meta_parts_arr.push('base64');
    }

    const meta_str =
      meta_parts_arr.length === 0 ? '' : meta_parts_arr.join(';');

    let data_str = '';
    if (include_base64_bool) {
      data_str = this.generateValidBase64Payload({
        max_len_u32: Math.min(8192, this.max_data_length_u32)
      });
    } else {
      data_str = this.generateValidNonBase64Payload({
        max_len_u32: Math.min(8192, this.max_data_length_u32)
      });
    }

    let url_str = `data:${meta_str},${data_str}`;
    if (url_str.length > this.max_total_length_u32) {
      url_str = url_str.slice(0, this.max_total_length_u32);
    }
    return url_str;
  }

  private generateValidMediaType(): string {
    // token "/" token
    const type_arr = [
      'text',
      'image',
      'application',
      'audio',
      'video',
      'font',
      'message',
      'multipart'
    ];
    const subtype_arr = [
      'plain',
      'html',
      'css',
      'javascript',
      'json',
      'xml',
      'svg+xml',
      'png',
      'jpeg',
      'gif',
      'webp',
      'octet-stream',
      'x-www-form-urlencoded'
    ];

    const type_str = type_arr[this.nextU32({ max_u32: type_arr.length })];
    const subtype_str =
      subtype_arr[this.nextU32({ max_u32: subtype_arr.length })];

    // Add some token-ish variation
    if (this.nextBool({ chance_f64: 0.15 })) {
      return `${type_str}/${this.randomToken({ min_len_u32: 3, max_len_u32: 12 })}`;
    }

    return `${type_str}/${subtype_str}`;
  }

  private generateValidCharsetParam(): string {
    const charset_arr = ['us-ascii', 'utf-8', 'iso-8859-1', 'windows-1252'];
    const charset_str =
      charset_arr[this.nextU32({ max_u32: charset_arr.length })];

    if (
      this.include_quoted_param_values_bool &&
      this.nextBool({ chance_f64: 0.2 })
    ) {
      // quoted-string value
      return `charset="${charset_str}"`;
    }

    return `charset=${charset_str}`;
  }

  private generateValidTokenParam(): string {
    const key_str = this.randomToken({
      min_len_u32: 1,
      max_len_u32: 12
    }).toLowerCase();
    const val_mode_u32 = this.nextU32({ max_u32: 3 });

    if (val_mode_u32 === 0) {
      return `${key_str}=${this.randomToken({ min_len_u32: 1, max_len_u32: 16 })}`;
    }

    if (val_mode_u32 === 1 && this.include_quoted_param_values_bool) {
      const inner_str = this.randomQuotedStringInner({
        min_len_u32: 0,
        max_len_u32: 12
      });
      return `${key_str}="${inner_str}"`;
    }

    // token value with some safe punctuation
    return `${key_str}=${this.randomToken({ min_len_u32: 1, max_len_u32: 10 })}`;
  }

  private generateValidBase64Payload(params: { max_len_u32: number }): string {
    // Strict base64: length multiple of 4; chars A-Z a-z 0-9 + / and optional '=' padding.
    const max_len_u32 = params.max_len_u32 >>> 0;

    // Choose a raw byte length, then encode with base64-ish alphabet (we don't need semantic decoding here)
    const quad_count_u32 =
      1 + this.nextU32({ max_u32: Math.max(1, Math.floor(max_len_u32 / 4)) });
    const total_len_u32 = Math.min(max_len_u32, quad_count_u32 * 4);

    let out_str = '';
    for (let i_u32 = 0; i_u32 < total_len_u32; i_u32++) {
      out_str += this.randomBase64Char();
    }

    // Add correct padding sometimes
    if (this.nextBool({ chance_f64: 0.35 })) {
      const pad_mode_u32 = this.nextU32({ max_u32: 3 }); // 0 none, 1 one "=", 2 two "=="
      if (pad_mode_u32 === 1) {
        out_str = out_str.slice(0, Math.max(0, out_str.length - 1)) + '=';
      } else if (pad_mode_u32 === 2) {
        out_str = out_str.slice(0, Math.max(0, out_str.length - 2)) + '==';
      }
    }

    // Ensure multiple of 4
    const mod_u32 = out_str.length % 4;
    if (mod_u32 !== 0) {
      out_str += 'A'.repeat(4 - mod_u32);
    }

    return out_str.slice(0, max_len_u32);
  }

  private randomBase64Char(): string {
    const alphabet_str =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    return alphabet_str[this.nextU32({ max_u32: alphabet_str.length })];
  }

  private generateValidNonBase64Payload(params: {
    max_len_u32: number;
  }): string {
    const max_len_u32 = params.max_len_u32 >>> 0;
    const target_len_u32 = this.nextU32({
      max_u32: Math.max(1, max_len_u32 + 1)
    }); // 0..max
    let out_str = '';

    for (let i_u32 = 0; i_u32 < target_len_u32; i_u32++) {
      const mode_u32 = this.nextU32({ max_u32: 10 });

      // Safe unreserved and some reserved
      if (mode_u32 <= 5) {
        out_str += this.randomDataChar({
          allow_non_ascii_bool: this.include_non_ascii_bool
        });
        continue;
      }

      // Percent-encoded byte
      if (mode_u32 <= 8) {
        const byte_u32 = this.nextU32({ max_u32: 256 });
        out_str += '%' + byte_u32.toString(16).toUpperCase().padStart(2, '0');
        continue;
      }

      // Include some delimiters commonly seen in data payloads
      const delim_arr = [
        ';',
        ':',
        '/',
        '?',
        '@',
        '&',
        '=',
        '+',
        ',',
        '.',
        '-',
        '_',
        '~'
      ];
      out_str += delim_arr[this.nextU32({ max_u32: delim_arr.length })];
    }

    // Avoid ASCII whitespace by default (modern parsers vary, but many treat it as invalid/unwanted)
    out_str = out_str.replace(/[ \t\r\n]/g, '%20');
    return out_str.slice(0, max_len_u32);
  }

  private randomDataChar(params: { allow_non_ascii_bool: boolean }): string {
    // Prefer URL-safe-ish visible characters
    const base_arr =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'.split(
        ''
      );
    if (this.nextBool({ chance_f64: 0.12 })) {
      const extra_str = "!$'()*+-./:;=?@_~";
      return extra_str[this.nextU32({ max_u32: extra_str.length })];
    }

    if (params.allow_non_ascii_bool && this.nextBool({ chance_f64: 0.08 })) {
      // A small set of non-ASCII code points (avoid surrogate ranges)
      const unicode_arr = ['✓', 'é', '中', 'λ', '💾'];
      return unicode_arr[this.nextU32({ max_u32: unicode_arr.length })];
    }

    return base_arr[this.nextU32({ max_u32: base_arr.length })];
  }

  private randomToken(params: {
    min_len_u32: number;
    max_len_u32: number;
  }): string {
    const min_len_u32 = params.min_len_u32 >>> 0;
    const max_len_u32 = params.max_len_u32 >>> 0;
    const len_u32 =
      min_len_u32 +
      this.nextU32({ max_u32: Math.max(1, max_len_u32 - min_len_u32 + 1) });

    // token chars (approx RFC 7230 tchar)
    const tchar_str =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~";
    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      out_str += tchar_str[this.nextU32({ max_u32: tchar_str.length })];
    }
    return out_str;
  }

  private randomQuotedStringInner(params: {
    min_len_u32: number;
    max_len_u32: number;
  }): string {
    const min_len_u32 = params.min_len_u32 >>> 0;
    const max_len_u32 = params.max_len_u32 >>> 0;
    const len_u32 =
      min_len_u32 +
      this.nextU32({ max_u32: Math.max(1, max_len_u32 - min_len_u32 + 1) });

    const vchar_str =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._-';
    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const ch_str = vchar_str[this.nextU32({ max_u32: vchar_str.length })];
      // Escape backslash or quote if present
      if (ch_str === '\\' || ch_str === '"') {
        out_str += '\\';
      }
      out_str += ch_str;
    }
    return out_str;
  }

  // -----------------------------
  // Invalid generation
  // -----------------------------

  private generateOneInvalidDataUrl(): string {
    // We generate deliberately malformed or parser-hostile cases:
    // - missing comma
    // - empty data: but missing comma or missing payload
    // - malformed pct-encoding
    // - invalid base64 chars / wrong padding / bad length
    // - whitespace injection
    // - invalid media type tokens
    // - empty params / broken key=value
    // - duplicate base64 marker or base64 not as a ;token
    // - huge meta or data lengths
    const mode_u32 = this.nextU32({ max_u32: 16 });

    if (mode_u32 === 0) {
      return 'data:'; // missing everything
    }

    if (mode_u32 === 1) {
      return 'data:text/plain;base64'; // missing comma
    }

    if (mode_u32 === 2) {
      return 'data:text/plain,Hello%2'; // malformed pct
    }

    if (mode_u32 === 3) {
      return 'data:text/plain,Hello%GG'; // malformed pct hex
    }

    if (mode_u32 === 4) {
      return 'data:text/plain;base64,AAAA==='; // too much padding
    }

    if (mode_u32 === 5) {
      return 'data:text/plain;base64,AAA'; // base64 length not multiple of 4
    }

    if (mode_u32 === 6) {
      return 'data:text/plain;base64,AA*A'; // invalid base64 char '*'
    }

    if (mode_u32 === 7) {
      return 'data:text/plain;charset=,Hello'; // empty param value
    }

    if (mode_u32 === 8) {
      return 'data:text/plain;;base64,AAAA'; // empty param between ;;
    }

    if (mode_u32 === 9) {
      return 'data:text plain,Hello'; // space in media type token
    }

    if (mode_u32 === 10) {
      return 'data:tex$t/plain,Hello'; // invalid token char '$' in type
    }

    if (mode_u32 === 11) {
      return 'data:text/plain;base64;base64,AAAA'; // duplicate base64 marker (as param tokens)
    }

    if (mode_u32 === 12) {
      // Whitespace in data portion (often invalid under strict rules)
      return 'data:text/plain,Hello World';
    }

    if (mode_u32 === 13) {
      // Control chars in data portion (raw)
      return 'data:text/plain,Hello\u0001World';
    }

    if (mode_u32 === 14) {
      // Misplaced comma / multiple commas in meta
      return 'data:text/plain,;base64,AAAA';
    }

    // Mode 15: Oversized / stress case but still syntactically broken
    const huge_piece_str = 'A'.repeat(
      Math.min(this.max_data_length_u32 + 32, 200_000)
    );
    return `data:text/plain;base64,${huge_piece_str}=`; // length likely not multiple of 4 and oversized
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

    // modulo bias is acceptable for fuzzing
    return this.rng_state_u32 % max_u32 >>> 0;
  }

  private nextBool(params: { chance_f64: number }): boolean {
    const chance_f64 = params.chance_f64;
    const roll_u32 = this.nextU32({ max_u32: 1_000_000 });
    return roll_u32 < Math.floor(chance_f64 * 1_000_000);
  }
}
