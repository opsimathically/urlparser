type blob_url_validation_result_t = {
  is_valid_bool: boolean;
  reason_str?: string;

  // Populated on success
  origin_str?: string; // e.g. "https://example.com:8443" or "null"
  uuid_str?: string; // canonical uuid (lowercased)
};

type blob_url_validator_options_t = {
  max_total_length_u32?: number;

  // If true, allow "blob:null/<uuid>" (opaque origin serialization).
  allow_null_origin_bool?: boolean;

  // Allowed origin schemes for "blob:<origin>/<uuid>"
  // (Most modern blob URLs you see are http/https; keep conservative by default.)
  allow_http_bool?: boolean;
  allow_https_bool?: boolean;

  // If true, allow query and fragment on the blob URL (many implementations ignore; default false = strict).
  allow_query_bool?: boolean;
  allow_fragment_bool?: boolean;

  // If true, allow non-RFC4122 UUIDs (still enforces a basic hex+dash pattern).
  allow_non_rfc4122_uuid_bool?: boolean;
};

export class BlobURLValidator {
  private max_total_length_u32: number;

  private allow_null_origin_bool: boolean;
  private allow_http_bool: boolean;
  private allow_https_bool: boolean;

  private allow_query_bool: boolean;
  private allow_fragment_bool: boolean;

  private allow_non_rfc4122_uuid_bool: boolean;

  public constructor(params: blob_url_validator_options_t = {}) {
    this.max_total_length_u32 = params.max_total_length_u32 ?? 2048;

    this.allow_null_origin_bool = params.allow_null_origin_bool ?? true;
    this.allow_http_bool = params.allow_http_bool ?? true;
    this.allow_https_bool = params.allow_https_bool ?? true;

    this.allow_query_bool = params.allow_query_bool ?? false;
    this.allow_fragment_bool = params.allow_fragment_bool ?? false;

    this.allow_non_rfc4122_uuid_bool =
      params.allow_non_rfc4122_uuid_bool ?? false;
  }

  public validate(params: {
    blob_url_str: string;
  }): blob_url_validation_result_t {
    const blob_url_str = params.blob_url_str;

    const precheck_result = this.precheckInput({ input_str: blob_url_str });
    if (!precheck_result.is_valid_bool) {
      return precheck_result;
    }

    // Scheme must be "blob:" (case-insensitive)
    if (!this.startsWithBlobScheme({ input_str: blob_url_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'must start with blob: (case-insensitive)'
      };
    }

    const after_scheme_str = blob_url_str.slice(5); // "blob:".length

    if (after_scheme_str.length === 0) {
      return {
        is_valid_bool: false,
        reason_str: 'missing blob body after scheme'
      };
    }

    // Enforce query/fragment policy (strict by default)
    const qmark_idx_i32 = after_scheme_str.indexOf('?');
    const hash_idx_i32 = after_scheme_str.indexOf('#');

    if (!this.allow_query_bool && qmark_idx_i32 >= 0) {
      return {
        is_valid_bool: false,
        reason_str: 'query not allowed in blob URL'
      };
    }

    if (!this.allow_fragment_bool && hash_idx_i32 >= 0) {
      return {
        is_valid_bool: false,
        reason_str: 'fragment not allowed in blob URL'
      };
    }

    // Split off any ?/# if allowed (so the origin/uuid portion is validated cleanly)
    const cut_idx_i32 = this.minNonnegI32({
      a_i32: qmark_idx_i32,
      b_i32: hash_idx_i32
    });
    const main_str =
      cut_idx_i32 < 0
        ? after_scheme_str
        : after_scheme_str.slice(0, cut_idx_i32);

    // Expected shape (common modern form):
    //   blob:<origin>/<uuid>
    //
    // where <origin> is "null" OR "http(s)://host[:port]"
    // and <uuid> is RFC4122-like.
    const last_slash_idx_i32 = main_str.lastIndexOf('/');
    if (last_slash_idx_i32 < 0) {
      return {
        is_valid_bool: false,
        reason_str: "missing '/' separator between origin and uuid"
      };
    }

    const origin_str = main_str.slice(0, last_slash_idx_i32);
    const uuid_str = main_str.slice(last_slash_idx_i32 + 1);

    if (origin_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty origin component' };
    }

    if (uuid_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty uuid component' };
    }

    const origin_result = this.validateOrigin({ origin_str });
    if (!origin_result.is_valid_bool) {
      return origin_result;
    }

    const uuid_result = this.validateUUID({ uuid_str });
    if (!uuid_result.is_valid_bool) {
      return uuid_result;
    }

    return {
      is_valid_bool: true,
      origin_str: origin_str,
      uuid_str: uuid_result.uuid_str
    };
  }

  // -----------------------------
  // Origin validation
  // -----------------------------

  private validateOrigin(params: {
    origin_str: string;
  }): blob_url_validation_result_t {
    const origin_str = params.origin_str;

    if (origin_str.toLowerCase() === 'null') {
      if (!this.allow_null_origin_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'null origin not allowed by configuration'
        };
      }
      return { is_valid_bool: true };
    }

    // Conservative origin parser for: http(s)://host[:port]
    // Notes:
    // - No username/password.
    // - Host may be reg-name, IPv4, or [IPv6].
    // - Optional port 0..65535.
    const scheme_sep_idx_i32 = origin_str.indexOf('://');
    if (scheme_sep_idx_i32 < 0) {
      return {
        is_valid_bool: false,
        reason_str: "origin must be 'null' or a URL like http(s)://host[:port]"
      };
    }

    const scheme_str = origin_str.slice(0, scheme_sep_idx_i32).toLowerCase();
    const rest_str = origin_str.slice(scheme_sep_idx_i32 + 3);

    const scheme_ok_bool =
      (scheme_str === 'http' && this.allow_http_bool) ||
      (scheme_str === 'https' && this.allow_https_bool);

    if (!scheme_ok_bool) {
      return { is_valid_bool: false, reason_str: 'origin scheme not allowed' };
    }

    if (rest_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'origin missing host' };
    }

    // Reject path/query/fragment in origin serialization (we want origin, not full URL)
    if (
      rest_str.includes('/') ||
      rest_str.includes('?') ||
      rest_str.includes('#')
    ) {
      return {
        is_valid_bool: false,
        reason_str: 'origin must not include path/query/fragment'
      };
    }

    // Reject userinfo
    if (rest_str.includes('@')) {
      return {
        is_valid_bool: false,
        reason_str: 'origin must not include userinfo'
      };
    }

    const host_port_result = this.parseHostPort({ host_port_str: rest_str });
    if (!host_port_result.is_valid_bool) {
      return {
        is_valid_bool: false,
        reason_str: host_port_result.reason_str ?? 'invalid host/port'
      };
    }

    return { is_valid_bool: true };
  }

  private parseHostPort(params: { host_port_str: string }): {
    is_valid_bool: boolean;
    reason_str?: string;
  } {
    const host_port_str = params.host_port_str;

    // IPv6 literal: [....]:port?
    if (host_port_str.startsWith('[')) {
      const close_idx_i32 = host_port_str.indexOf(']');
      if (close_idx_i32 < 0) {
        return {
          is_valid_bool: false,
          reason_str: 'unterminated IPv6 literal'
        };
      }

      const host_inside_str = host_port_str.slice(1, close_idx_i32);
      if (!this.isIPv6Address({ ipv6_str: host_inside_str })) {
        return { is_valid_bool: false, reason_str: 'invalid IPv6 address' };
      }

      const after_bracket_str = host_port_str.slice(close_idx_i32 + 1);
      if (after_bracket_str.length === 0) {
        return { is_valid_bool: true };
      }

      if (!after_bracket_str.startsWith(':')) {
        return {
          is_valid_bool: false,
          reason_str: 'unexpected characters after IPv6 literal'
        };
      }

      const port_str = after_bracket_str.slice(1);
      if (!this.isPort({ port_str })) {
        return { is_valid_bool: false, reason_str: 'invalid port' };
      }

      return { is_valid_bool: true };
    }

    // reg-name or IPv4 with optional :port
    const last_colon_idx_i32 = host_port_str.lastIndexOf(':');
    if (last_colon_idx_i32 >= 0) {
      const host_str = host_port_str.slice(0, last_colon_idx_i32);
      const port_str = host_port_str.slice(last_colon_idx_i32 + 1);

      if (host_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty host' };
      }

      if (!this.isPort({ port_str })) {
        return { is_valid_bool: false, reason_str: 'invalid port' };
      }

      if (
        !this.isIPv4Address({ ipv4_str: host_str }) &&
        !this.isRegName({ host_str })
      ) {
        return { is_valid_bool: false, reason_str: 'invalid host' };
      }

      return { is_valid_bool: true };
    }

    // no port
    if (
      !this.isIPv4Address({ ipv4_str: host_port_str }) &&
      !this.isRegName({ host_str: host_port_str })
    ) {
      return { is_valid_bool: false, reason_str: 'invalid host' };
    }

    return { is_valid_bool: true };
  }

  private isRegName(params: { host_str: string }): boolean {
    // Practical hostname validation (LDH labels + dots).
    const host_str = params.host_str;

    if (host_str.length === 0 || host_str.length > 253) {
      return false;
    }
    if (host_str.startsWith('.') || host_str.endsWith('.')) {
      return false;
    }
    if (host_str.includes('..')) {
      return false;
    }

    const labels_arr = host_str.split('.');
    for (const label_str of labels_arr) {
      if (!this.isDNSLabel({ label_str })) {
        return false;
      }
    }
    return true;
  }

  private isDNSLabel(params: { label_str: string }): boolean {
    const label_str = params.label_str;

    if (label_str.length === 0 || label_str.length > 63) {
      return false;
    }
    if (label_str.startsWith('-') || label_str.endsWith('-')) {
      return false;
    }

    for (let i_u32 = 0; i_u32 < label_str.length; i_u32++) {
      const ch_str = label_str[i_u32];
      const code_u32 = label_str.charCodeAt(i_u32);

      const is_alpha_bool =
        (code_u32 >= 0x41 && code_u32 <= 0x5a) ||
        (code_u32 >= 0x61 && code_u32 <= 0x7a);
      const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;
      const is_hyphen_bool = ch_str === '-';

      if (!(is_alpha_bool || is_digit_bool || is_hyphen_bool)) {
        return false;
      }
    }

    return true;
  }

  // -----------------------------
  // UUID validation
  // -----------------------------

  private validateUUID(params: { uuid_str: string }): {
    is_valid_bool: boolean;
    reason_str?: string;
    uuid_str?: string;
  } {
    const uuid_str = params.uuid_str;
    const canonical_uuid_str = uuid_str.toLowerCase();

    // Basic UUID pattern: 8-4-4-4-12 hex
    const basic_ok_bool =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
        canonical_uuid_str
      );
    if (!basic_ok_bool) {
      return {
        is_valid_bool: false,
        reason_str: 'uuid must match 8-4-4-4-12 hex pattern'
      };
    }

    if (this.allow_non_rfc4122_uuid_bool) {
      return { is_valid_bool: true, uuid_str: canonical_uuid_str };
    }

    // RFC 4122 constraints (practical):
    // - version is the first nibble of the 3rd group: [1-5]
    // - variant is the first nibble of the 4th group: [8,9,a,b]
    const version_ch_str = canonical_uuid_str[14];
    const variant_ch_str = canonical_uuid_str[19];

    if (!'12345'.includes(version_ch_str)) {
      return {
        is_valid_bool: false,
        reason_str: 'uuid version must be 1-5 (RFC 4122)'
      };
    }

    if (!'89ab'.includes(variant_ch_str)) {
      return {
        is_valid_bool: false,
        reason_str: 'uuid variant must be 8,9,a,b (RFC 4122)'
      };
    }

    return { is_valid_bool: true, uuid_str: canonical_uuid_str };
  }

  // -----------------------------
  // Prechecks and helpers
  // -----------------------------

  private precheckInput(params: {
    input_str: string;
  }): blob_url_validation_result_t {
    const input_str = params.input_str;

    if (input_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty input' };
    }

    if (input_str.length > this.max_total_length_u32) {
      return { is_valid_bool: false, reason_str: 'exceeds max_total_length' };
    }

    const invalid_reason_str = this.findControlOrInvalidUnicode({
      input_str
    });
    if (invalid_reason_str !== null) {
      return { is_valid_bool: false, reason_str: invalid_reason_str };
    }

    return { is_valid_bool: true };
  }

  private startsWithBlobScheme(params: { input_str: string }): boolean {
    const input_str = params.input_str;
    if (input_str.length < 5) {
      return false;
    }
    return input_str.slice(0, 5).toLowerCase() === 'blob:';
  }

  private minNonnegI32(params: { a_i32: number; b_i32: number }): number {
    const a_i32 = params.a_i32;
    const b_i32 = params.b_i32;

    if (a_i32 < 0) {
      return b_i32;
    }
    if (b_i32 < 0) {
      return a_i32;
    }
    return Math.min(a_i32, b_i32);
  }

  private findControlOrInvalidUnicode(params: {
    input_str: string;
  }): string | null {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);

      // ASCII controls + DEL
      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return 'contains ASCII control characters';
      }

      // Disallow spaces in a strict pre-parse validator
      if (code_u32 === 0x20) {
        return 'contains space characters';
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

  private isPort(params: { port_str: string }): boolean {
    const port_str = params.port_str;

    if (port_str.length === 0 || port_str.length > 5) {
      return false;
    }

    if (!/^\d+$/.test(port_str)) {
      return false;
    }

    const val_u32 = Number(port_str);
    if (!Number.isFinite(val_u32) || val_u32 < 0 || val_u32 > 65535) {
      return false;
    }

    return true;
  }

  private isIPv4Address(params: { ipv4_str: string }): boolean {
    const ipv4_str = params.ipv4_str;

    const parts_arr = ipv4_str.split('.');
    if (parts_arr.length !== 4) {
      return false;
    }

    for (const part_str of parts_arr) {
      if (part_str.length === 0 || part_str.length > 3) {
        return false;
      }
      if (!/^\d+$/.test(part_str)) {
        return false;
      }
      const val_u32 = Number(part_str);
      if (!Number.isFinite(val_u32) || val_u32 < 0 || val_u32 > 255) {
        return false;
      }
    }

    return true;
  }

  private isIPv6Address(params: { ipv6_str: string }): boolean {
    // Practical IPv6 validation:
    // - allow one '::' compression
    // - groups are 1..4 hex
    // - allow embedded IPv4 in last position
    const ipv6_str = params.ipv6_str;

    if (ipv6_str.length === 0) {
      return false;
    }

    for (let i_u32 = 0; i_u32 < ipv6_str.length; i_u32++) {
      const ch_str = ipv6_str[i_u32];
      const code_u32 = ipv6_str.charCodeAt(i_u32);

      const is_colon_bool = ch_str === ':';
      const is_dot_bool = ch_str === '.';
      const is_hex_bool =
        (code_u32 >= 0x30 && code_u32 <= 0x39) ||
        (code_u32 >= 0x41 && code_u32 <= 0x46) ||
        (code_u32 >= 0x61 && code_u32 <= 0x66);

      if (!(is_colon_bool || is_dot_bool || is_hex_bool)) {
        return false;
      }
    }

    const has_double_colon_bool = ipv6_str.includes('::');
    if (
      has_double_colon_bool &&
      ipv6_str.indexOf('::') !== ipv6_str.lastIndexOf('::')
    ) {
      return false;
    }

    const parts_arr = ipv6_str.split(':');

    let group_count_u32 = 0;
    for (let i_u32 = 0; i_u32 < parts_arr.length; i_u32++) {
      const group_str = parts_arr[i_u32];

      if (group_str.length === 0) {
        continue; // compression slot
      }

      if (group_str.includes('.')) {
        if (i_u32 !== parts_arr.length - 1) {
          return false;
        }
        if (!this.isIPv4Address({ ipv4_str: group_str })) {
          return false;
        }
        group_count_u32 += 2;
        continue;
      }

      if (group_str.length < 1 || group_str.length > 4) {
        return false;
      }

      if (!/^[0-9A-Fa-f]{1,4}$/.test(group_str)) {
        return false;
      }

      group_count_u32++;
    }

    if (!has_double_colon_bool) {
      return group_count_u32 === 8;
    }

    return group_count_u32 < 8;
  }
}
