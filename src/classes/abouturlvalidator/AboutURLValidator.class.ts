type about_url_validator_result_t = {
  is_valid_bool: boolean;
  reason_str?: string;
};

interface about_url_validator_options_i {
  max_total_length_u32?: number;
  max_identity_length_u32?: number;
  max_path_length_u32?: number;
  max_query_length_u32?: number;
  max_fragment_length_u32?: number;

  // If provided, identity must case-insensitively match one of these (after percent-decoding).
  allowed_identities_arr?: string[];

  // If true, allow any syntactically valid identity token (still subject to length/char rules).
  allow_any_identity_bool?: boolean;

  // If true, accept about://<identity> in addition to about:<identity>.
  allow_about_slash_slash_bool?: boolean;
}

export class AboutURLValidator {
  private max_total_length_u32: number;
  private max_identity_length_u32: number;
  private max_path_length_u32: number;
  private max_query_length_u32: number;
  private max_fragment_length_u32: number;

  private allowed_identities_arr: string[] | null;
  private allow_any_identity_bool: boolean;
  private allow_about_slash_slash_bool: boolean;

  public constructor(params: about_url_validator_options_i = {}) {
    this.max_total_length_u32 = params.max_total_length_u32 ?? 2048;
    this.max_identity_length_u32 = params.max_identity_length_u32 ?? 64;
    this.max_path_length_u32 = params.max_path_length_u32 ?? 1024;
    this.max_query_length_u32 = params.max_query_length_u32 ?? 1024;
    this.max_fragment_length_u32 = params.max_fragment_length_u32 ?? 1024;

    this.allow_any_identity_bool = params.allow_any_identity_bool ?? false;
    this.allowed_identities_arr = this.allow_any_identity_bool
      ? null
      : (params.allowed_identities_arr ?? ['blank', 'srcdoc']);

    this.allow_about_slash_slash_bool =
      params.allow_about_slash_slash_bool ?? true;
  }

  public validate(params: {
    about_url_str: string;
  }): about_url_validator_result_t {
    const about_url_str = params.about_url_str;

    if (about_url_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty input' };
    }

    if (about_url_str.length > this.max_total_length_u32) {
      return { is_valid_bool: false, reason_str: 'exceeds max_total_length' };
    }

    const control_reason_str = this.find_control_or_invalid_unicode({
      input_str: about_url_str
    });
    if (control_reason_str !== null) {
      return { is_valid_bool: false, reason_str: control_reason_str };
    }

    const prefix_result = this.parse_about_prefix({ input_str: about_url_str });
    if (!prefix_result.is_valid_bool) {
      return prefix_result;
    }

    if (prefix_result.after_prefix_str === undefined) {
      return {
        is_valid_bool: false,
        reason_str: 'internal error: missing after_prefix_str'
      };
    }

    const after_prefix_str = prefix_result.after_prefix_str;
    if (after_prefix_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'missing identity' };
    }

    const split_idx_u32 = this.first_of_any({
      input_str: after_prefix_str,
      needles_arr: ['/', '?', '#']
    });
    const identity_raw_str =
      split_idx_u32 === null
        ? after_prefix_str
        : after_prefix_str.slice(0, split_idx_u32);
    const remainder_str =
      split_idx_u32 === null ? '' : after_prefix_str.slice(split_idx_u32);

    const identity_result = this.validate_identity({ identity_raw_str });
    if (!identity_result.is_valid_bool) {
      return identity_result;
    }

    const remainder_result = this.validate_remainder({ remainder_str });
    if (!remainder_result.is_valid_bool) {
      return remainder_result;
    }

    return { is_valid_bool: true };
  }

  private parse_about_prefix(params: {
    input_str: string;
  }): about_url_validator_result_t & { after_prefix_str?: string } {
    const input_str = params.input_str;

    // Accept:
    // - about:<rest>
    // - about://<rest> (optional)
    //
    // Scheme is case-insensitive, but we do not tolerate whitespace or other characters in the scheme delimiter region.
    const lower_str = input_str.toLowerCase();

    if (!lower_str.startsWith('about:')) {
      return {
        is_valid_bool: false,
        reason_str: 'must start with about: (case-insensitive)'
      };
    }

    const after_colon_str = input_str.slice(6); // "about:".length === 6

    if (after_colon_str.startsWith('//')) {
      if (!this.allow_about_slash_slash_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'about:// form is not allowed by configuration'
        };
      }
      return {
        is_valid_bool: true,
        after_prefix_str: after_colon_str.slice(2)
      };
    }

    return { is_valid_bool: true, after_prefix_str: after_colon_str };
  }

  // -----------------------------
  // Identity validation
  // -----------------------------

  private validate_identity(params: {
    identity_raw_str: string;
  }): about_url_validator_result_t {
    const identity_raw_str = params.identity_raw_str;

    if (identity_raw_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty identity' };
    }

    if (identity_raw_str.length > this.max_identity_length_u32) {
      return {
        is_valid_bool: false,
        reason_str: 'identity exceeds max_identity_length'
      };
    }

    // Reject authority-ish features (userinfo / port / ip-literals) and backslash ambiguity.
    if (identity_raw_str.includes('@')) {
      return {
        is_valid_bool: false,
        reason_str: 'userinfo (@) not allowed in identity'
      };
    }
    if (identity_raw_str.includes(':')) {
      return {
        is_valid_bool: false,
        reason_str: 'port separator (:) not allowed in identity'
      };
    }
    if (identity_raw_str.includes('\\')) {
      return {
        is_valid_bool: false,
        reason_str: 'backslash not allowed in identity'
      };
    }
    if (identity_raw_str.includes('[') || identity_raw_str.includes(']')) {
      return {
        is_valid_bool: false,
        reason_str: 'ip-literal brackets not allowed in identity'
      };
    }

    // Identity token: unreserved + pct-encoded only.
    if (!this.is_identity_token({ token_str: identity_raw_str })) {
      return {
        is_valid_bool: false,
        reason_str:
          'identity contains invalid characters or malformed percent-encoding'
      };
    }

    const decoded_identity_str = this.percent_decode_ascii({
      input_str: identity_raw_str
    });
    const canonical_identity_str = decoded_identity_str.toLowerCase();

    if (this.allowed_identities_arr !== null) {
      const match_bool = this.allowed_identities_arr.some(
        (x_str) => x_str.toLowerCase() === canonical_identity_str
      );
      if (!match_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'identity not in allowed_identities_arr'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private is_identity_token(params: { token_str: string }): boolean {
    const token_str = params.token_str;

    for (let i_u32 = 0; i_u32 < token_str.length; i_u32++) {
      const ch_str = token_str[i_u32];

      if (ch_str === '%') {
        if (!this.is_pct_encoded_at({ input_str: token_str, idx_u32: i_u32 })) {
          return false;
        }
        i_u32 += 2;
        continue;
      }

      if (this.is_unreserved({ ch_str })) {
        continue;
      }

      return false;
    }

    return true;
  }

  // -----------------------------
  // Remainder validation (path/query/fragment)
  // -----------------------------

  private validate_remainder(params: {
    remainder_str: string;
  }): about_url_validator_result_t {
    const remainder_str = params.remainder_str;

    if (remainder_str.length === 0) {
      return { is_valid_bool: true };
    }

    if (remainder_str.includes('\\')) {
      return { is_valid_bool: false, reason_str: 'backslash not allowed' };
    }

    const hash_idx_u32 = remainder_str.indexOf('#');
    const before_hash_str =
      hash_idx_u32 >= 0 ? remainder_str.slice(0, hash_idx_u32) : remainder_str;
    const fragment_str =
      hash_idx_u32 >= 0 ? remainder_str.slice(hash_idx_u32 + 1) : '';

    const qmark_idx_u32 = before_hash_str.indexOf('?');
    const path_str =
      qmark_idx_u32 >= 0
        ? before_hash_str.slice(0, qmark_idx_u32)
        : before_hash_str;
    const query_str =
      qmark_idx_u32 >= 0 ? before_hash_str.slice(qmark_idx_u32 + 1) : '';

    if (path_str.length > 0) {
      if (!path_str.startsWith('/')) {
        return {
          is_valid_bool: false,
          reason_str: 'path must start with / if present'
        };
      }
      if (path_str.length > this.max_path_length_u32) {
        return {
          is_valid_bool: false,
          reason_str: 'path exceeds max_path_length'
        };
      }
      if (
        !this.is_uri_component_lenient({
          component_str: path_str,
          allow_slash_bool: true
        })
      ) {
        return {
          is_valid_bool: false,
          reason_str:
            'path contains invalid characters or malformed percent-encoding'
        };
      }
    }

    if (query_str.length > 0) {
      if (query_str.length > this.max_query_length_u32) {
        return {
          is_valid_bool: false,
          reason_str: 'query exceeds max_query_length'
        };
      }
      if (
        !this.is_uri_component_lenient({
          component_str: query_str,
          allow_slash_bool: true
        })
      ) {
        return {
          is_valid_bool: false,
          reason_str:
            'query contains invalid characters or malformed percent-encoding'
        };
      }
    }

    if (fragment_str.length > 0) {
      if (fragment_str.length > this.max_fragment_length_u32) {
        return {
          is_valid_bool: false,
          reason_str: 'fragment exceeds max_fragment_length'
        };
      }
      if (
        !this.is_uri_component_lenient({
          component_str: fragment_str,
          allow_slash_bool: true
        })
      ) {
        return {
          is_valid_bool: false,
          reason_str:
            'fragment contains invalid characters or malformed percent-encoding'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private is_uri_component_lenient(params: {
    component_str: string;
    allow_slash_bool: boolean;
  }): boolean {
    const component_str = params.component_str;

    for (let i_u32 = 0; i_u32 < component_str.length; i_u32++) {
      const ch_str = component_str[i_u32];

      if (ch_str === '%') {
        if (
          !this.is_pct_encoded_at({ input_str: component_str, idx_u32: i_u32 })
        ) {
          return false;
        }
        i_u32 += 2;
        continue;
      }

      if (this.is_unreserved({ ch_str })) {
        continue;
      }

      if (params.allow_slash_bool && ch_str === '/') {
        continue;
      }

      if ("-._~!$&'()*+,;=:@".includes(ch_str)) {
        continue;
      }

      return false;
    }

    return true;
  }

  // -----------------------------
  // Low-level helpers
  // -----------------------------

  private first_of_any(params: {
    input_str: string;
    needles_arr: string[];
  }): number | null {
    let best_idx_u32: number | null = null;

    for (const needle_str of params.needles_arr) {
      const idx_u32 = params.input_str.indexOf(needle_str);
      if (idx_u32 < 0) {
        continue;
      }
      if (best_idx_u32 === null || idx_u32 < best_idx_u32) {
        best_idx_u32 = idx_u32;
      }
    }

    return best_idx_u32;
  }

  private is_unreserved(params: { ch_str: string }): boolean {
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

  private is_pct_encoded_at(params: {
    input_str: string;
    idx_u32: number;
  }): boolean {
    const input_str = params.input_str;
    const idx_u32 = params.idx_u32;

    if (idx_u32 + 2 >= input_str.length) {
      return false;
    }

    const h1_str = input_str[idx_u32 + 1];
    const h2_str = input_str[idx_u32 + 2];

    return this.is_hex({ ch_str: h1_str }) && this.is_hex({ ch_str: h2_str });
  }

  private is_hex(params: { ch_str: string }): boolean {
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

  private percent_decode_ascii(params: { input_str: string }): string {
    const input_str = params.input_str;

    let out_str = '';
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const ch_str = input_str[i_u32];
      if (ch_str !== '%') {
        out_str += ch_str;
        continue;
      }

      const hex_str = input_str.slice(i_u32 + 1, i_u32 + 3);
      const byte_u32 = parseInt(hex_str, 16);
      out_str += String.fromCharCode(byte_u32);
      i_u32 += 2;
    }

    return out_str;
  }

  private find_control_or_invalid_unicode(params: {
    input_str: string;
  }): string | null {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);

      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return 'contains ASCII control characters';
      }

      if (code_u32 === 0x20) {
        return 'contains space characters';
      }

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
}
