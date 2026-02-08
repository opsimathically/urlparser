type urn_url_validation_result_t = {
  is_valid_bool: boolean;
  reason_str?: string;

  // Populated on success
  nid_str?: string; // lowercased
  nss_str?: string; // as provided (no pct-decode by default)
  r_component_str?: string; // without leading "?+"
  q_component_str?: string; // without leading "?"
  f_component_str?: string; // without leading "#"

  normalized_urn_str?: string;
};

type urn_url_validator_options_t = {
  max_total_length_u32?: number;

  // Component acceptance: URN syntax is "urn:<NID>:<NSS>[?+r][?=q][#f]" per RFC 8141.
  allow_r_component_bool?: boolean;
  allow_q_component_bool?: boolean;
  allow_f_component_bool?: boolean;

  // NSS percent-encoding policy:
  // - strict: require any '%' sequences to be well-formed, but do not require pct-encoding for reserved chars
  // - optionally require that prohibited characters are percent-encoded
  require_well_formed_pct_encoding_in_nss_bool?: boolean;

  // If true, enforce RFC 8141 "pchar" constraints on NSS and components more strictly.
  // If false, apply a conservative-but-practical check that blocks spaces/controls and invalid '%' escapes.
  strict_rfc8141_charset_bool?: boolean;

  // If true, allow NID "urn-" prefix (RFC 8141 allows NID beginning with alnum; "urn-" is not special but appears).
  // Included for flexibility; default true (no extra restriction).
  allow_any_valid_nid_bool?: boolean;
};

export class URNURLValidator {
  private max_total_length_u32: number;

  private allow_r_component_bool: boolean;
  private allow_q_component_bool: boolean;
  private allow_f_component_bool: boolean;

  private require_well_formed_pct_encoding_in_nss_bool: boolean;
  private strict_rfc8141_charset_bool: boolean;
  private allow_any_valid_nid_bool: boolean;

  public constructor(params: urn_url_validator_options_t = {}) {
    this.max_total_length_u32 = params.max_total_length_u32 ?? 4096;

    this.allow_r_component_bool = params.allow_r_component_bool ?? true;
    this.allow_q_component_bool = params.allow_q_component_bool ?? true;
    this.allow_f_component_bool = params.allow_f_component_bool ?? true;

    this.require_well_formed_pct_encoding_in_nss_bool =
      params.require_well_formed_pct_encoding_in_nss_bool ?? true;
    this.strict_rfc8141_charset_bool =
      params.strict_rfc8141_charset_bool ?? true;

    this.allow_any_valid_nid_bool = params.allow_any_valid_nid_bool ?? true;
  }

  public validate(params: {
    urn_url_str: string;
  }): urn_url_validation_result_t {
    const urn_url_str = params.urn_url_str;

    const precheck_result = this.precheckInput({ input_str: urn_url_str });
    if (!precheck_result.is_valid_bool) {
      return precheck_result;
    }

    if (!this.startsWithUrnScheme({ input_str: urn_url_str })) {
      // debugger;
      return {
        is_valid_bool: false,
        reason_str: 'must start with urn: (case-insensitive)'
      };
    }

    const after_scheme_str = urn_url_str.slice(4);
    if (after_scheme_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'missing NID:NSS after urn:' };
    }

    // Split components: "urn:<nid>:<nss>[?+r][?=q][#f]"
    const split_result = this.splitUrnComponents({ after_scheme_str });
    if (!split_result.is_valid_bool) {
      return { is_valid_bool: false, reason_str: split_result.reason_str };
    }

    const nid_str = split_result.nid_str as string;
    const nss_str = split_result.nss_str as string;

    const r_component_str = split_result.r_component_str;
    const q_component_str = split_result.q_component_str;
    const f_component_str = split_result.f_component_str;

    const nid_result = this.validateNid({ nid_str });
    if (!nid_result.is_valid_bool) {
      return nid_result;
    }

    const nss_result = this.validateNss({ nss_str });
    if (!nss_result.is_valid_bool) {
      return nss_result;
    }

    if (r_component_str !== undefined) {
      if (!this.allow_r_component_bool) {
        return { is_valid_bool: false, reason_str: 'r-component not allowed' };
      }
      const r_ok_bool = this.validateComponent({
        component_str: r_component_str,
        component_name_str: 'r-component'
      });
      if (!r_ok_bool.is_valid_bool) {
        return r_ok_bool;
      }
    }

    if (q_component_str !== undefined) {
      if (!this.allow_q_component_bool) {
        return { is_valid_bool: false, reason_str: 'q-component not allowed' };
      }
      const q_ok_bool = this.validateComponent({
        component_str: q_component_str,
        component_name_str: 'q-component'
      });
      if (!q_ok_bool.is_valid_bool) {
        return q_ok_bool;
      }
    }

    if (f_component_str !== undefined) {
      if (!this.allow_f_component_bool) {
        return { is_valid_bool: false, reason_str: 'f-component not allowed' };
      }
      const f_ok_bool = this.validateComponent({
        component_str: f_component_str,
        component_name_str: 'f-component'
      });
      if (!f_ok_bool.is_valid_bool) {
        return f_ok_bool;
      }
    }

    const normalized_nid_str = nid_str.toLowerCase();
    const normalized_urn_str = this.normalizeUrn({
      nid_str: normalized_nid_str,
      nss_str,
      r_component_str,
      q_component_str,
      f_component_str
    });

    return {
      is_valid_bool: true,
      nid_str: normalized_nid_str,
      nss_str,
      r_component_str,
      q_component_str,
      f_component_str,
      normalized_urn_str
    };
  }

  // -----------------------------
  // Split "NID:NSS[?+r][?=q][#f]"
  // -----------------------------

  private splitUrnComponents(params: { after_scheme_str: string }): {
    is_valid_bool: boolean;
    reason_str?: string;
    nid_str?: string;
    nss_str?: string;
    r_component_str?: string;
    q_component_str?: string;
    f_component_str?: string;
  } {
    const after_scheme_str = params.after_scheme_str;

    // Find first ':' which separates NID and NSS
    const first_colon_idx_i32 = after_scheme_str.indexOf(':');
    if (first_colon_idx_i32 < 0) {
      return {
        is_valid_bool: false,
        reason_str: "missing ':' separator between NID and NSS"
      };
    }

    const nid_str = after_scheme_str.slice(0, first_colon_idx_i32);
    let rest_str = after_scheme_str.slice(first_colon_idx_i32 + 1);

    if (nid_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty NID' };
    }
    if (rest_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty NSS' };
    }

    // Extract f-component (fragment) first (after #)
    let f_component_str: string | undefined = undefined;
    const hash_idx_i32 = rest_str.indexOf('#');
    if (hash_idx_i32 >= 0) {
      f_component_str = rest_str.slice(hash_idx_i32 + 1);
      rest_str = rest_str.slice(0, hash_idx_i32);
    }

    // Now rest is "<nss>[?+r][?=q]" in some order.
    // RFC 8141 ordering: r-component first (?+), then q-component (?=), but accept either order conservatively.
    let r_component_str: string | undefined = undefined;
    let q_component_str: string | undefined = undefined;

    // Find occurrences of ?+ and ?=
    const r_idx_i32 = rest_str.indexOf('?+');
    const q_idx_i32 = rest_str.indexOf('?=');

    // Determine NSS end
    let nss_end_i32 = rest_str.length;

    if (r_idx_i32 >= 0) {
      nss_end_i32 = Math.min(nss_end_i32, r_idx_i32);
    }
    if (q_idx_i32 >= 0) {
      nss_end_i32 = Math.min(nss_end_i32, q_idx_i32);
    }

    const nss_str = rest_str.slice(0, nss_end_i32);
    const tail_str = rest_str.slice(nss_end_i32);

    if (nss_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty NSS' };
    }

    // Parse tail: zero or more of (?+...)(?=...)
    // We implement a strict structure parse:
    let i_u32 = 0;
    while (i_u32 < tail_str.length) {
      if (tail_str.startsWith('?+', i_u32)) {
        i_u32 += 2;
        const next_marker_idx_i32 = this.findNextMarker({
          input_str: tail_str,
          start_idx_u32: i_u32
        });
        const comp_str = tail_str.slice(i_u32, next_marker_idx_i32);
        if (r_component_str !== undefined) {
          return { is_valid_bool: false, reason_str: 'duplicate r-component' };
        }
        r_component_str = comp_str;
        i_u32 = next_marker_idx_i32;
        continue;
      }

      if (tail_str.startsWith('?=', i_u32)) {
        i_u32 += 2;
        const next_marker_idx_i32 = this.findNextMarker({
          input_str: tail_str,
          start_idx_u32: i_u32
        });
        const comp_str = tail_str.slice(i_u32, next_marker_idx_i32);
        if (q_component_str !== undefined) {
          return { is_valid_bool: false, reason_str: 'duplicate q-component' };
        }
        q_component_str = comp_str;
        i_u32 = next_marker_idx_i32;
        continue;
      }

      return {
        is_valid_bool: false,
        reason_str: 'invalid component marker (expected ?+ or ?=)'
      };
    }

    return {
      is_valid_bool: true,
      nid_str,
      nss_str,
      r_component_str,
      q_component_str,
      f_component_str
    };
  }

  private findNextMarker(params: {
    input_str: string;
    start_idx_u32: number;
  }): number {
    const input_str = params.input_str;
    const start_idx_u32 = params.start_idx_u32;

    for (let i_u32 = start_idx_u32; i_u32 < input_str.length; i_u32++) {
      if (
        input_str.startsWith('?+', i_u32) ||
        input_str.startsWith('?=', i_u32)
      ) {
        return i_u32;
      }
    }
    return input_str.length;
  }

  // -----------------------------
  // NID validation (RFC 8141)
  // -----------------------------

  private validateNid(params: {
    nid_str: string;
  }): urn_url_validation_result_t {
    const nid_str = params.nid_str;

    // RFC 8141: NID = (alnum) 0*30 (alnum / "-") ; length 1..31
    if (nid_str.length < 1 || nid_str.length > 31) {
      return { is_valid_bool: false, reason_str: 'NID length must be 1..31' };
    }

    const first_ch_str = nid_str[0];
    if (!this.isAlnum({ ch_str: first_ch_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'NID must start with an alphanumeric character'
      };
    }

    for (let i_u32 = 0; i_u32 < nid_str.length; i_u32++) {
      const ch_str = nid_str[i_u32];

      if (this.isAlnum({ ch_str })) {
        continue;
      }

      if (ch_str === '-') {
        continue;
      }

      return {
        is_valid_bool: false,
        reason_str: 'NID contains invalid character'
      };
    }

    // If you want to forbid certain NIDs or enforce registration, that’s external to syntax.
    if (!this.allow_any_valid_nid_bool) {
      // Placeholder for policy controls (kept permissive).
    }

    return { is_valid_bool: true };
  }

  private isAlnum(params: { ch_str: string }): boolean {
    const ch_str = params.ch_str;
    if (ch_str.length !== 1) {
      return false;
    }
    const code_u32 = ch_str.charCodeAt(0);
    const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;
    const is_upper_bool = code_u32 >= 0x41 && code_u32 <= 0x5a;
    const is_lower_bool = code_u32 >= 0x61 && code_u32 <= 0x7a;
    return is_digit_bool || is_upper_bool || is_lower_bool;
  }

  // -----------------------------
  // NSS and component validation
  // -----------------------------

  private validateNss(params: {
    nss_str: string;
  }): urn_url_validation_result_t {
    const nss_str = params.nss_str;

    if (nss_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty NSS' };
    }

    if (this.containsAsciiControlsOrSpaces({ input_str: nss_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'NSS contains spaces or control characters'
      };
    }

    if (this.require_well_formed_pct_encoding_in_nss_bool) {
      if (!this.isPctEncodingWellFormed({ input_str: nss_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'malformed percent-encoding in NSS'
        };
      }
    }

    if (this.strict_rfc8141_charset_bool) {
      // RFC 8141 (URN syntax) references RFC 3986 'pchar' and allows '/' as well as some delimiters in NSS.
      // We validate a conservative pchar-ish set plus '%' for pct-encoding.
      for (let i_u32 = 0; i_u32 < nss_str.length; i_u32++) {
        const ch_str = nss_str[i_u32];

        if (this.isPcharOrUrnExtra({ ch_str })) {
          continue;
        }

        if (ch_str === '%') {
          // well-formedness handled above if enabled
          continue;
        }

        return {
          is_valid_bool: false,
          reason_str: 'NSS contains invalid character'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private validateComponent(params: {
    component_str: string;
    component_name_str: string;
  }): urn_url_validation_result_t {
    const component_str = params.component_str;

    if (this.containsAsciiControlsOrSpaces({ input_str: component_str })) {
      return {
        is_valid_bool: false,
        reason_str: `${params.component_name_str} contains spaces or control characters`
      };
    }

    if (!this.isPctEncodingWellFormed({ input_str: component_str })) {
      return {
        is_valid_bool: false,
        reason_str: `malformed percent-encoding in ${params.component_name_str}`
      };
    }

    if (this.strict_rfc8141_charset_bool) {
      for (let i_u32 = 0; i_u32 < component_str.length; i_u32++) {
        const ch_str = component_str[i_u32];

        if (this.isPcharOrUrnExtra({ ch_str })) {
          continue;
        }
        if (ch_str === '%') {
          continue;
        }
        return {
          is_valid_bool: false,
          reason_str: `${params.component_name_str} contains invalid character`
        };
      }
    }

    return { is_valid_bool: true };
  }

  private isPcharOrUrnExtra(params: { ch_str: string }): boolean {
    const ch_str = params.ch_str;

    // RFC 3986 pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
    // URN NSS also commonly allows "/" and some additional delimiters; RFC 8141 allows a broad set in NSS.
    // We accept: unreserved + sub-delims + ":" + "@" + "/" + "."
    const unreserved_str =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    const subdelims_str = "!$&'()*+,;=";

    if (unreserved_str.includes(ch_str)) {
      return true;
    }
    if (subdelims_str.includes(ch_str)) {
      return true;
    }
    if (ch_str === ':' || ch_str === '@' || ch_str === '/') {
      return true;
    }

    return false;
  }

  // -----------------------------
  // Prechecks and helpers
  // -----------------------------

  private precheckInput(params: {
    input_str: string;
  }): urn_url_validation_result_t {
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

  private startsWithUrnScheme(params: { input_str: string }): boolean {
    const input_str = params.input_str;
    return (
      input_str.length >= 4 && input_str.slice(0, 4).toLowerCase() === 'urn:'
    );
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

  private containsAsciiControlsOrSpaces(params: {
    input_str: string;
  }): boolean {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);

      if (code_u32 === 0x20) {
        return true;
      }
      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return true;
      }
    }

    return false;
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

  private normalizeUrn(params: {
    nid_str: string;
    nss_str: string;
    r_component_str?: string;
    q_component_str?: string;
    f_component_str?: string;
  }): string {
    let out_str = `urn:${params.nid_str}:${params.nss_str}`;

    if (params.r_component_str !== undefined) {
      out_str += `?+${params.r_component_str}`;
    }
    if (params.q_component_str !== undefined) {
      out_str += `?=${params.q_component_str}`;
    }
    if (params.f_component_str !== undefined) {
      out_str += `#${params.f_component_str}`;
    }

    return out_str;
  }
}
