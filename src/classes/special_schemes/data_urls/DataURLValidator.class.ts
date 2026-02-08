type data_url_validation_result_t = {
  is_valid_bool: boolean;
  reason_str?: string;

  // Populated on success
  mime_type_str?: string; // lowercased, default "text/plain"
  mime_subtype_str?: string; // lowercased, default "charset=US-ASCII" handled via charset_str
  media_type_str?: string; // e.g. "text/plain"
  charset_str?: string; // e.g. "us-ascii" (default per RFC 2397)
  is_base64_bool?: boolean;

  // Raw segments (no decoding performed here)
  media_type_raw_str?: string; // portion before first comma
  data_raw_str?: string; // portion after first comma

  normalized_data_url_str?: string;
};

type data_url_validator_options_t = {
  max_total_length_u32?: number;

  // Limit size of data portion to avoid parser/memory abuse
  max_data_length_u32?: number;

  // If true, allow ASCII whitespace in the data portion (some parsers are permissive). Default false.
  allow_ascii_whitespace_in_data_bool?: boolean;

  // If true, require base64 data to be strictly valid (no invalid chars, correct padding).
  strict_base64_bool?: boolean;

  // If true, require that percent-encoding in non-base64 data is well-formed.
  require_well_formed_pct_encoding_in_data_bool?: boolean;

  // If true, require a syntactically valid media type if present (type "/" subtype, params).
  strict_media_type_bool?: boolean;
};

export class DataURLValidator {
  private max_total_length_u32: number;
  private max_data_length_u32: number;

  private allow_ascii_whitespace_in_data_bool: boolean;
  private strict_base64_bool: boolean;
  private require_well_formed_pct_encoding_in_data_bool: boolean;
  private strict_media_type_bool: boolean;

  public constructor(params: data_url_validator_options_t = {}) {
    this.max_total_length_u32 = params.max_total_length_u32 ?? 1_000_000;
    this.max_data_length_u32 = params.max_data_length_u32 ?? 800_000;

    this.allow_ascii_whitespace_in_data_bool =
      params.allow_ascii_whitespace_in_data_bool ?? false;
    this.strict_base64_bool = params.strict_base64_bool ?? true;
    this.require_well_formed_pct_encoding_in_data_bool =
      params.require_well_formed_pct_encoding_in_data_bool ?? true;
    this.strict_media_type_bool = params.strict_media_type_bool ?? true;
  }

  public validate(params: {
    data_url_str: string;
  }): data_url_validation_result_t {
    const data_url_str = params.data_url_str;

    const precheck_result = this.precheckInput({ input_str: data_url_str });
    if (!precheck_result.is_valid_bool) {
      return precheck_result;
    }

    if (!this.startsWithDataScheme({ input_str: data_url_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'must start with data: (case-insensitive)'
      };
    }

    const after_scheme_str = data_url_str.slice(5);
    if (after_scheme_str.length === 0) {
      return {
        is_valid_bool: false,
        reason_str: 'missing data URL body after data:'
      };
    }

    // RFC 2397: data:[<mediatype>][;base64],<data>
    const comma_idx_i32 = after_scheme_str.indexOf(',');
    if (comma_idx_i32 < 0) {
      return {
        is_valid_bool: false,
        reason_str: "missing ',' separator between mediatype and data"
      };
    }

    const meta_raw_str = after_scheme_str.slice(0, comma_idx_i32);
    const data_raw_str = after_scheme_str.slice(comma_idx_i32 + 1);

    if (data_raw_str.length > this.max_data_length_u32) {
      return {
        is_valid_bool: false,
        reason_str: 'data portion exceeds max_data_length'
      };
    }

    if (!this.allow_ascii_whitespace_in_data_bool) {
      if (this.containsAsciiWhitespace({ input_str: data_raw_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'data portion contains ASCII whitespace'
        };
      }
    }

    const meta_parse_result = this.parseMeta({ meta_raw_str });
    if (!meta_parse_result.is_valid_bool) {
      return { is_valid_bool: false, reason_str: meta_parse_result.reason_str };
    }

    const is_base64_bool = meta_parse_result.is_base64_bool as boolean;

    if (is_base64_bool) {
      const b64_result = this.validateBase64Data({ data_str: data_raw_str });
      if (!b64_result.is_valid_bool) {
        return b64_result;
      }
    } else {
      if (this.require_well_formed_pct_encoding_in_data_bool) {
        if (!this.isPctEncodingWellFormed({ input_str: data_raw_str })) {
          return {
            is_valid_bool: false,
            reason_str: 'malformed percent-encoding in data portion'
          };
        }
      }

      if (this.containsAsciiControls({ input_str: data_raw_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'data portion contains ASCII control characters'
        };
      }
    }

    const normalized_media_type_str =
      meta_parse_result.media_type_str as string;
    const charset_str = meta_parse_result.charset_str as string;

    const normalized_data_url_str = this.normalizeDataUrl({
      media_type_str: normalized_media_type_str,
      charset_str,
      is_base64_bool,
      meta_params_arr: meta_parse_result.meta_params_arr as Array<
        [string, string]
      >,
      data_raw_str
    });

    return {
      is_valid_bool: true,
      media_type_str: normalized_media_type_str,
      charset_str,
      is_base64_bool,
      media_type_raw_str: meta_raw_str,
      data_raw_str,
      normalized_data_url_str
    };
  }

  // -----------------------------
  // Meta parsing
  // -----------------------------

  private parseMeta(params: { meta_raw_str: string }): {
    is_valid_bool: boolean;
    reason_str?: string;
    media_type_str?: string;
    charset_str?: string;
    is_base64_bool?: boolean;
    meta_params_arr?: Array<[string, string]>;
  } {
    const meta_raw_str = params.meta_raw_str;

    // Defaults per RFC 2397
    let media_type_str = 'text/plain';
    let charset_str = 'us-ascii';
    let is_base64_bool = false;

    // We'll preserve additional params (lowercased keys) for normalization.
    const meta_params_arr: Array<[string, string]> = [];

    if (meta_raw_str.length === 0) {
      return {
        is_valid_bool: true,
        media_type_str,
        charset_str,
        is_base64_bool,
        meta_params_arr
      };
    }

    const parts_arr = meta_raw_str.split(';');

    // First token may be a media type (type/subtype) OR omitted.
    let idx_u32 = 0;

    if (
      parts_arr.length > 0 &&
      parts_arr[0].length > 0 &&
      parts_arr[0].includes('/')
    ) {
      const mt_candidate_str = parts_arr[0];
      if (this.strict_media_type_bool) {
        const mt_ok = this.validateMediaType({
          media_type_str: mt_candidate_str
        });
        if (!mt_ok.is_valid_bool) {
          return mt_ok;
        }
      } else {
        if (
          this.containsAsciiControlsOrSpaces({ input_str: mt_candidate_str })
        ) {
          return {
            is_valid_bool: false,
            reason_str: 'media type contains spaces or controls'
          };
        }
      }

      media_type_str = mt_candidate_str.toLowerCase();
      idx_u32 = 1;
    }

    for (; idx_u32 < parts_arr.length; idx_u32++) {
      const tok_str = parts_arr[idx_u32];
      if (tok_str.length === 0) {
        // ";;" is not meaningful; treat as invalid (strict)
        return {
          is_valid_bool: false,
          reason_str: 'empty parameter in mediatype'
        };
      }

      if (tok_str.toLowerCase() === 'base64') {
        is_base64_bool = true;
        continue;
      }

      const eq_idx_i32 = tok_str.indexOf('=');
      if (eq_idx_i32 < 0) {
        return {
          is_valid_bool: false,
          reason_str: 'invalid parameter (expected key=value) in mediatype'
        };
      }

      const key_str = tok_str.slice(0, eq_idx_i32).toLowerCase();
      const val_str = tok_str.slice(eq_idx_i32 + 1);

      if (key_str.length === 0 || val_str.length === 0) {
        return {
          is_valid_bool: false,
          reason_str: 'invalid parameter (empty key or value) in mediatype'
        };
      }

      if (!this.isToken({ token_str: key_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'invalid parameter name in mediatype'
        };
      }

      // Values in RFC 2045 parameters can be token or quoted-string; data: URLs often carry raw tokens.
      // We'll accept token or quoted-string conservatively.
      if (
        !this.isToken({ token_str: val_str }) &&
        !this.isQuotedString({ input_str: val_str })
      ) {
        return {
          is_valid_bool: false,
          reason_str: 'invalid parameter value in mediatype'
        };
      }

      meta_params_arr.push([key_str, val_str]);

      if (key_str === 'charset') {
        // If quoted, strip quotes for normalized charset field
        const normalized_charset_str = this.stripOptionalQuotes({
          input_str: val_str
        }).toLowerCase();
        charset_str = normalized_charset_str;
      }
    }

    return {
      is_valid_bool: true,
      media_type_str,
      charset_str,
      is_base64_bool,
      meta_params_arr
    };
  }

  private validateMediaType(params: { media_type_str: string }): {
    is_valid_bool: boolean;
    reason_str?: string;
    media_type_str?: string;
    charset_str?: string;
    is_base64_bool?: boolean;
    meta_params_arr?: Array<[string, string]>;
  } {
    const media_type_str = params.media_type_str;

    if (this.containsAsciiControlsOrSpaces({ input_str: media_type_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'media type contains spaces or control characters'
      };
    }

    const slash_idx_i32 = media_type_str.indexOf('/');
    if (slash_idx_i32 <= 0 || slash_idx_i32 >= media_type_str.length - 1) {
      return {
        is_valid_bool: false,
        reason_str: 'media type must be type/subtype'
      };
    }

    const type_str = media_type_str.slice(0, slash_idx_i32);
    const subtype_str = media_type_str.slice(slash_idx_i32 + 1);

    if (
      !this.isToken({ token_str: type_str }) ||
      !this.isToken({ token_str: subtype_str })
    ) {
      return {
        is_valid_bool: false,
        reason_str: 'media type contains invalid token characters'
      };
    }

    return { is_valid_bool: true };
  }

  private isToken(params: { token_str: string }): boolean {
    // RFC 2045 token: 1*tchar; we approximate with allowed set from RFC 7230 tchar
    const token_str = params.token_str;
    if (token_str.length === 0) {
      return false;
    }

    const allowed_str = "!#$%&'*+-.^_`|~";

    for (let i_u32 = 0; i_u32 < token_str.length; i_u32++) {
      const ch_str = token_str[i_u32];
      const code_u32 = token_str.charCodeAt(i_u32);

      const is_alpha_bool =
        (code_u32 >= 0x41 && code_u32 <= 0x5a) ||
        (code_u32 >= 0x61 && code_u32 <= 0x7a);
      const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;

      if (is_alpha_bool || is_digit_bool || allowed_str.includes(ch_str)) {
        continue;
      }

      return false;
    }

    return true;
  }

  private isQuotedString(params: { input_str: string }): boolean {
    const input_str = params.input_str;
    if (input_str.length < 2) {
      return false;
    }
    if (!(input_str.startsWith('"') && input_str.endsWith('"'))) {
      return false;
    }

    // Validate simple quoted-string with backslash escaping
    let escape_next_bool = false;
    for (let i_u32 = 1; i_u32 < input_str.length - 1; i_u32++) {
      const ch_str = input_str[i_u32];
      const code_u32 = input_str.charCodeAt(i_u32);

      if (escape_next_bool) {
        // allow any VCHAR or WSP after backslash (conservative)
        escape_next_bool = false;
        continue;
      }

      if (ch_str === '\\') {
        escape_next_bool = true;
        continue;
      }

      // reject controls
      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return false;
      }
    }

    return !escape_next_bool;
  }

  private stripOptionalQuotes(params: { input_str: string }): string {
    const input_str = params.input_str;
    if (
      input_str.length >= 2 &&
      input_str.startsWith('"') &&
      input_str.endsWith('"')
    ) {
      return input_str.slice(1, input_str.length - 1);
    }
    return input_str;
  }

  // -----------------------------
  // Base64 validation
  // -----------------------------

  private validateBase64Data(params: {
    data_str: string;
  }): data_url_validation_result_t {
    const data_str = params.data_str;

    if (!this.allow_ascii_whitespace_in_data_bool) {
      if (this.containsAsciiWhitespace({ input_str: data_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'base64 data contains ASCII whitespace'
        };
      }
    }

    // Strict base64: chars [A-Za-z0-9+/] plus '=' padding; length mod 4 == 0
    // Some parsers accept urlsafe base64, but RFC 2397 uses regular base64.
    if (this.strict_base64_bool) {
      if (data_str.length === 0) {
        // Empty payload is ok
        return { is_valid_bool: true };
      }

      if (data_str.length % 4 !== 0) {
        return {
          is_valid_bool: false,
          reason_str: 'base64 length must be a multiple of 4'
        };
      }

      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(data_str)) {
        return {
          is_valid_bool: false,
          reason_str: 'base64 contains invalid characters'
        };
      }

      // '=' padding must be at end; regex above enforces only at end
      // Additional padding rules:
      const pad_count_u32 = this.countTrailingEquals({ input_str: data_str });
      if (pad_count_u32 > 2) {
        return {
          is_valid_bool: false,
          reason_str: 'base64 has too much padding'
        };
      }
    } else {
      // Permissive: still reject controls
      if (this.containsAsciiControls({ input_str: data_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'base64 data contains control characters'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private countTrailingEquals(params: { input_str: string }): number {
    const input_str = params.input_str;
    let count_u32 = 0;
    for (let i_u32 = input_str.length - 1; i_u32 >= 0; i_u32--) {
      if (input_str[i_u32] === '=') {
        count_u32++;
        continue;
      }
      break;
    }
    return count_u32;
  }

  // -----------------------------
  // Prechecks and helpers
  // -----------------------------

  private precheckInput(params: {
    input_str: string;
  }): data_url_validation_result_t {
    const input_str = params.input_str;

    if (input_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty input' };
    }

    if (input_str.length > this.max_total_length_u32) {
      return { is_valid_bool: false, reason_str: 'exceeds max_total_length' };
    }

    const invalid_reason_str = this.findControlOrInvalidUnicode({ input_str });
    if (invalid_reason_str !== null) {
      return { is_valid_bool: false, reason_str: invalid_reason_str };
    }

    return { is_valid_bool: true };
  }

  private startsWithDataScheme(params: { input_str: string }): boolean {
    const input_str = params.input_str;
    return (
      input_str.length >= 5 && input_str.slice(0, 5).toLowerCase() === 'data:'
    );
  }

  private containsAsciiWhitespace(params: { input_str: string }): boolean {
    const input_str = params.input_str;
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);
      if (
        code_u32 === 0x20 ||
        code_u32 === 0x09 ||
        code_u32 === 0x0a ||
        code_u32 === 0x0d
      ) {
        return true;
      }
    }
    return false;
  }

  private containsAsciiControls(params: { input_str: string }): boolean {
    const input_str = params.input_str;
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);
      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return true;
      }
    }
    return false;
  }

  private containsAsciiControlsOrSpaces(params: {
    input_str: string;
  }): boolean {
    const input_str = params.input_str;
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);
      if (code_u32 === 0x20 || code_u32 <= 0x1f || code_u32 === 0x7f) {
        return true;
      }
    }
    return false;
  }

  private isPctEncodingWellFormed(params: { input_str: string }): boolean {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      if (input_str[i_u32] !== '%') {
        continue;
      }

      if (i_u32 + 2 >= input_str.length) {
        return false;
      }

      const h1_str = input_str[i_u32 + 1];
      const h2_str = input_str[i_u32 + 2];

      if (!this.isHex({ ch_str: h1_str }) || !this.isHex({ ch_str: h2_str })) {
        return false;
      }

      i_u32 += 2;
    }

    return true;
  }

  private isHex(params: { ch_str: string }): boolean {
    const ch_str = params.ch_str;
    if (ch_str.length !== 1) {
      return false;
    }

    const code_u32 = ch_str.charCodeAt(0);
    const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;
    const is_upper_hex_bool = code_u32 >= 0x41 && code_u32 <= 0x46;
    const is_lower_hex_bool = code_u32 >= 0x61 && code_u32 <= 0x66;

    return is_digit_bool || is_upper_hex_bool || is_lower_hex_bool;
  }

  private findControlOrInvalidUnicode(params: {
    input_str: string;
  }): string | null {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);

      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return 'contains ASCII control characters';
      }

      // Unpaired surrogate check
      if (code_u32 >= 0xd800 && code_u32 <= 0xdbff) {
        if (i_u32 + 1 >= input_str.length) {
          return 'contains unpaired high surrogate';
        }
        const next_u32 = input_str.charCodeAt(i_u32 + 1);
        if (next_u32 < 0xdc00 || next_u32 > 0xdfff) {
          return 'contains unpaired high surrogate';
        }
        i_u32 += 1;
        continue;
      }

      if (code_u32 >= 0xdc00 && code_u32 <= 0xdfff) {
        return 'contains unpaired low surrogate';
      }
    }

    return null;
  }

  private normalizeDataUrl(params: {
    media_type_str: string;
    charset_str: string;
    is_base64_bool: boolean;
    meta_params_arr: Array<[string, string]>;
    data_raw_str: string;
  }): string {
    // Normalize to: data:<media_type>[;charset=...][;...][;base64],<data>
    // Emit charset explicitly only if non-default or explicitly present.
    let out_str = `data:${params.media_type_str}`;

    // Gather params into a stable order: charset first (if present), then others, then base64.
    const other_params_arr: Array<[string, string]> = [];
    let saw_charset_bool = false;

    for (const [k_str, v_str] of params.meta_params_arr) {
      if (k_str === 'charset') {
        saw_charset_bool = true;
        out_str += `;charset=${v_str}`;
        continue;
      }
      other_params_arr.push([k_str, v_str]);
    }

    // If charset never explicitly present but differs from default, emit it (rare)
    if (!saw_charset_bool && params.charset_str !== 'us-ascii') {
      out_str += `;charset=${params.charset_str}`;
    }

    for (const [k_str, v_str] of other_params_arr) {
      out_str += `;${k_str}=${v_str}`;
    }

    if (params.is_base64_bool) {
      out_str += `;base64`;
    }

    out_str += `,${params.data_raw_str}`;
    return out_str;
  }
}
