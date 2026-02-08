type tel_url_validation_result_t = {
  is_valid_bool: boolean;
  reason_str?: string;

  normalized_tel_str?: string;

  is_global_bool?: boolean;
  global_number_str?: string; // digits only, no leading '+'
  local_number_str?: string; // raw local part (without params)

  ext_str?: string; // decoded extension value
  isub_str?: string; // decoded isub
  phone_context_str?: string; // decoded phone-context
  tsp_str?: string; // decoded tsp
};

type tel_url_validator_options_t = {
  max_total_length_u32?: number;

  allow_local_number_bool?: boolean;
  require_phone_context_for_local_bool?: boolean;

  allow_visual_separators_bool?: boolean;

  allow_query_bool?: boolean;
  allow_fragment_bool?: boolean;

  allow_unknown_params_bool?: boolean;
  allow_pct_encoded_in_params_bool?: boolean;

  // Extended RFC 3966 behaviors you requested
  allow_dtmf_in_ext_bool?: boolean; // allow '*' and '#' (and optionally A-D) in ext
  allow_dtmf_abcd_bool?: boolean; // allow A-D/a-d in ext and tsp
  allow_tsp_param_bool?: boolean; // allow ;tsp=
  // If true, phone-context domainname validation is more permissive than LDH-only
  allow_general_domainname_in_phone_context_bool?: boolean;
};

export class TelURLValidator {
  private max_total_length_u32: number;

  private allow_local_number_bool: boolean;
  private require_phone_context_for_local_bool: boolean;

  private allow_visual_separators_bool: boolean;

  private allow_query_bool: boolean;
  private allow_fragment_bool: boolean;

  private allow_unknown_params_bool: boolean;
  private allow_pct_encoded_in_params_bool: boolean;

  private allow_dtmf_in_ext_bool: boolean;
  private allow_dtmf_abcd_bool: boolean;
  private allow_tsp_param_bool: boolean;
  private allow_general_domainname_in_phone_context_bool: boolean;

  public constructor(params: tel_url_validator_options_t = {}) {
    this.max_total_length_u32 = params.max_total_length_u32 ?? 2048;

    this.allow_local_number_bool = params.allow_local_number_bool ?? true;
    this.require_phone_context_for_local_bool =
      params.require_phone_context_for_local_bool ?? true;

    this.allow_visual_separators_bool =
      params.allow_visual_separators_bool ?? true;

    this.allow_query_bool = params.allow_query_bool ?? false;
    this.allow_fragment_bool = params.allow_fragment_bool ?? false;

    this.allow_unknown_params_bool = params.allow_unknown_params_bool ?? false;
    this.allow_pct_encoded_in_params_bool =
      params.allow_pct_encoded_in_params_bool ?? true;

    this.allow_dtmf_in_ext_bool = params.allow_dtmf_in_ext_bool ?? true;
    this.allow_dtmf_abcd_bool = params.allow_dtmf_abcd_bool ?? true;
    this.allow_tsp_param_bool = params.allow_tsp_param_bool ?? true;

    this.allow_general_domainname_in_phone_context_bool =
      params.allow_general_domainname_in_phone_context_bool ?? true;
  }

  public validate(params: {
    tel_url_str: string;
  }): tel_url_validation_result_t {
    const tel_url_str = params.tel_url_str;

    const precheck_result = this.precheckInput({ input_str: tel_url_str });
    if (!precheck_result.is_valid_bool) {
      return precheck_result;
    }

    if (!this.startsWithTelScheme({ input_str: tel_url_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'must start with tel: (case-insensitive)'
      };
    }

    const after_scheme_str = tel_url_str.slice(4);
    if (after_scheme_str.length === 0) {
      return {
        is_valid_bool: false,
        reason_str: 'missing telephone-subscriber after tel:'
      };
    }

    const qmark_idx_i32 = after_scheme_str.indexOf('?');
    const hash_idx_i32 = after_scheme_str.indexOf('#');

    if (!this.allow_query_bool && qmark_idx_i32 >= 0) {
      return {
        is_valid_bool: false,
        reason_str: 'query not allowed in tel URL'
      };
    }
    if (!this.allow_fragment_bool && hash_idx_i32 >= 0) {
      return {
        is_valid_bool: false,
        reason_str: 'fragment not allowed in tel URL'
      };
    }

    const cut_idx_i32 = this.minNonnegI32({
      a_i32: qmark_idx_i32,
      b_i32: hash_idx_i32
    });
    const main_str =
      cut_idx_i32 < 0
        ? after_scheme_str
        : after_scheme_str.slice(0, cut_idx_i32);

    const semi_idx_i32 = main_str.indexOf(';');
    const number_str =
      semi_idx_i32 < 0 ? main_str : main_str.slice(0, semi_idx_i32);
    const params_str = semi_idx_i32 < 0 ? '' : main_str.slice(semi_idx_i32 + 1);

    if (number_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty telephone-subscriber' };
    }

    const number_result = this.validateNumber({ number_str });
    if (!number_result.is_valid_bool) {
      return number_result;
    }

    const parsed_params = new Map<string, string | null>();

    let ext_str: string | undefined = undefined;
    let isub_str: string | undefined = undefined;
    let phone_context_str: string | undefined = undefined;
    let tsp_str: string | undefined = undefined;

    if (params_str.length > 0) {
      const params_result = this.validateAndParseParams({
        params_str,
        parsed_params,
        is_global_bool: number_result.is_global_bool as boolean
      });
      if (!params_result.is_valid_bool) {
        return params_result;
      }

      const ext_val = parsed_params.get('ext');
      if (ext_val !== undefined && ext_val !== null) {
        ext_str = ext_val;
      }

      const isub_val = parsed_params.get('isub');
      if (isub_val !== undefined && isub_val !== null) {
        isub_str = isub_val;
      }

      const pc_val = parsed_params.get('phone-context');
      if (pc_val !== undefined && pc_val !== null) {
        phone_context_str = pc_val;
      }

      const tsp_val = parsed_params.get('tsp');
      if (tsp_val !== undefined && tsp_val !== null) {
        tsp_str = tsp_val;
      }
    }

    if (!(number_result.is_global_bool as boolean)) {
      const has_pc_bool = parsed_params.has('phone-context');
      if (this.require_phone_context_for_local_bool && !has_pc_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'local number requires phone-context parameter'
        };
      }
    }

    const normalized_tel_str = this.normalizeTel({
      is_global_bool: number_result.is_global_bool as boolean,
      digits_only_str: number_result.digits_only_str as string,
      local_number_str: number_result.local_number_str as string | null,
      parsed_params
    });

    return {
      is_valid_bool: true,
      normalized_tel_str,

      is_global_bool: number_result.is_global_bool as boolean,
      global_number_str: (number_result.is_global_bool as boolean)
        ? (number_result.digits_only_str as string)
        : undefined,
      local_number_str: (number_result.is_global_bool as boolean)
        ? undefined
        : (number_result.local_number_str as string),

      ext_str,
      isub_str,
      phone_context_str,
      tsp_str
    };
  }

  // -----------------------------
  // Number validation
  // -----------------------------
  private validateNumber(params: {
    number_str: string;
  }): tel_url_validation_result_t & {
    digits_only_str?: string;
    local_number_str?: string | null;
    is_global_bool?: boolean;
  } {
    const number_str = params.number_str;

    const is_global_bool = number_str.startsWith('+');
    if (!is_global_bool && !this.allow_local_number_bool) {
      return {
        is_valid_bool: false,
        reason_str: 'local numbers not allowed by configuration'
      };
    }

    const raw_body_str = is_global_bool ? number_str.slice(1) : number_str;
    if (raw_body_str.length === 0) {
      return {
        is_valid_bool: false,
        reason_str: "missing digits after leading '+'"
      };
    }

    // Allow percent-encoding in the number portion (common for spaces: %20)
    if (!this.isPctEncodingWellFormed({ input_str: raw_body_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'malformed percent-encoding in phone-number'
      };
    }

    const body_str = raw_body_str.includes('%')
      ? this.percentDecodeAscii({ input_str: raw_body_str })
      : raw_body_str;

    if (this.containsAsciiControls({ input_str: body_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'phone-number contains control characters'
      };
    }

    let digits_only_str = '';
    let saw_digit_bool = false;

    let in_parens_bool = false;
    let saw_digit_in_parens_bool = false;

    // let last_was_digit_bool = false;
    let last_was_sep_bool = false;
    let last_sep_char_str: string | null = null;

    for (let i_u32 = 0; i_u32 < body_str.length; i_u32++) {
      const ch_str = body_str[i_u32];
      const code_u32 = body_str.charCodeAt(i_u32);

      const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;
      if (is_digit_bool) {
        digits_only_str += ch_str;
        saw_digit_bool = true;

        // last_was_digit_bool = true;
        last_was_sep_bool = false;
        last_sep_char_str = null;

        if (in_parens_bool) {
          saw_digit_in_parens_bool = true;
        }
        continue;
      }

      if (!this.allow_visual_separators_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'visual separators not allowed in number'
        };
      }

      // Parentheses rules
      if (ch_str === '(') {
        // Allow '(' after digits as well (e.g. "+1(555)123-4567")
        if (in_parens_bool) {
          return {
            is_valid_bool: false,
            reason_str: "nested '(' not allowed in phone-number"
          };
        }

        // Disallow ")(" adjacency (weird formatting)
        if (last_sep_char_str === ')') {
          return {
            is_valid_bool: false,
            reason_str: "invalid '(' placement in phone-number"
          };
        }

        in_parens_bool = true;
        saw_digit_in_parens_bool = false;

        // last_was_digit_bool = false;
        last_was_sep_bool = true;
        last_sep_char_str = '(';
        continue;
      }

      if (ch_str === ')') {
        // Allow ')' only if currently in parens and we saw a digit inside
        if (!in_parens_bool || !saw_digit_in_parens_bool) {
          return {
            is_valid_bool: false,
            reason_str: "invalid ')' placement in phone-number"
          };
        }

        in_parens_bool = false;

        // last_was_digit_bool = false;
        last_was_sep_bool = true;
        last_sep_char_str = ')';
        continue;
      }

      // Other visual separators
      const is_sep_bool =
        ch_str === '-' || ch_str === '.' || ch_str === ' ' || ch_str === '\t';
      if (is_sep_bool) {
        // Allow adjacency around parentheses (common: "+1 (555) 123-4567" or "(555) 123-4567")
        const prev_is_paren_bool =
          last_sep_char_str === '(' || last_sep_char_str === ')';
        if (last_was_sep_bool && !prev_is_paren_bool) {
          // Conservative: reject repeated separators like "--", "..", or "  "
          return {
            is_valid_bool: false,
            reason_str: 'repeated separators in phone-number'
          };
        }

        // last_was_digit_bool = false;
        last_was_sep_bool = true;
        last_sep_char_str = ch_str;
        continue;
      }

      return {
        is_valid_bool: false,
        reason_str: 'invalid character in phone-number'
      };
    }

    if (in_parens_bool) {
      return {
        is_valid_bool: false,
        reason_str: "unterminated '(' in phone-number"
      };
    }

    if (!saw_digit_bool) {
      return {
        is_valid_bool: false,
        reason_str: 'phone-number must contain digits'
      };
    }

    if (is_global_bool && digits_only_str.length > 15) {
      return {
        is_valid_bool: false,
        reason_str: 'global number exceeds 15 digits (E.164)'
      };
    }

    if (!is_global_bool && digits_only_str.length > 64) {
      return { is_valid_bool: false, reason_str: 'local number too long' };
    }

    return {
      is_valid_bool: true,
      is_global_bool,
      digits_only_str,
      local_number_str: is_global_bool ? undefined : body_str
    };
  }

  // -----------------------------
  // Parameter validation/parsing
  // -----------------------------

  private validateAndParseParams(params: {
    params_str: string;
    parsed_params: Map<string, string | null>;
    is_global_bool: boolean;
  }): tel_url_validation_result_t {
    const parts_arr = params.params_str.split(';');

    for (const raw_part_str of parts_arr) {
      // Permit optional whitespace around param segments (permissive)
      const part_str = raw_part_str.trim();

      if (part_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty parameter segment' };
      }

      const eq_idx_i32 = part_str.indexOf('=');
      const name_raw_str =
        eq_idx_i32 < 0 ? part_str : part_str.slice(0, eq_idx_i32);
      const value_raw_str =
        eq_idx_i32 < 0 ? null : part_str.slice(eq_idx_i32 + 1);

      // Permit optional whitespace around name/value (permissive)
      const name_trimmed_str = name_raw_str.trim();
      const value_trimmed_str =
        value_raw_str === null ? null : value_raw_str.trim();

      if (name_trimmed_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty parameter name' };
      }

      const name_str = name_trimmed_str.toLowerCase();
      if (!this.isParamName({ name_str })) {
        return { is_valid_bool: false, reason_str: 'invalid parameter name' };
      }

      const is_known_bool =
        name_str === 'ext' ||
        name_str === 'isub' ||
        name_str === 'phone-context' ||
        (name_str === 'tsp' && this.allow_tsp_param_bool);

      if (!is_known_bool && !this.allow_unknown_params_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'unknown parameter not allowed'
        };
      }

      if (params.parsed_params.has(name_str)) {
        return { is_valid_bool: false, reason_str: 'duplicate parameter name' };
      }

      if (value_trimmed_str === null) {
        if (is_known_bool) {
          return {
            is_valid_bool: false,
            reason_str: 'known parameter missing value'
          };
        }
        params.parsed_params.set(name_str, null);
        continue;
      }

      if (value_trimmed_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty parameter value' };
      }

      if (
        !this.allow_pct_encoded_in_params_bool &&
        value_trimmed_str.includes('%')
      ) {
        return {
          is_valid_bool: false,
          reason_str: 'percent-encoding not allowed in params'
        };
      }

      if (!this.isPctEncodingWellFormed({ input_str: value_trimmed_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'malformed percent-encoding in params'
        };
      }

      const value_decoded_str = this.percentDecodeAscii({
        input_str: value_trimmed_str
      });
      if (this.containsAsciiControls({ input_str: value_decoded_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'parameter value contains control characters'
        };
      }

      // Known parameters
      if (name_str === 'ext') {
        const ext_ok_bool = this.isDtmfDigitString({
          value_str: value_decoded_str,
          min_len_u32: 1,
          max_len_u32: 32,
          allow_star_hash_bool: this.allow_dtmf_in_ext_bool,
          allow_abcd_bool: this.allow_dtmf_abcd_bool,
          allow_visual_separators_bool: false
        });
        if (!ext_ok_bool) {
          return {
            is_valid_bool: false,
            reason_str: 'ext contains invalid characters'
          };
        }
      } else if (name_str === 'isub') {
        if (!/^[A-Za-z0-9\-._~]+$/.test(value_decoded_str)) {
          return {
            is_valid_bool: false,
            reason_str: 'isub contains invalid characters'
          };
        }
      } else if (name_str === 'phone-context') {
        const pc_ok_bool = this.isPhoneContext({
          phone_context_str: value_decoded_str
        });
        if (!pc_ok_bool) {
          return { is_valid_bool: false, reason_str: 'phone-context invalid' };
        }
      } else if (name_str === 'tsp') {
        if (!this.allow_tsp_param_bool) {
          return {
            is_valid_bool: false,
            reason_str: 'tsp parameter not allowed'
          };
        }

        const tsp_ok_bool = this.isDtmfDigitString({
          value_str: value_decoded_str,
          min_len_u32: 1,
          max_len_u32: 64,
          allow_star_hash_bool: true,
          allow_abcd_bool: this.allow_dtmf_abcd_bool,
          allow_visual_separators_bool: true
        });
        if (!tsp_ok_bool) {
          return {
            is_valid_bool: false,
            reason_str: 'tsp contains invalid characters'
          };
        }
      }

      params.parsed_params.set(name_str, value_decoded_str);
    }

    return { is_valid_bool: true };
  }

  private isPhoneContext(params: { phone_context_str: string }): boolean {
    const phone_context_str = params.phone_context_str;

    // phone-context can be global-number starting with '+'
    if (phone_context_str.startsWith('+')) {
      const digits_str = phone_context_str.slice(1);
      return /^\d{1,15}$/.test(digits_str);
    }

    // Or a domainname. Your parser supports "more general" rules, so we provide two modes:
    // - strict LDH labels (classic hostnames)
    // - general "reg-name-like" labels (unreserved/sub-delims) without forbidden delimiters
    if (this.allow_general_domainname_in_phone_context_bool) {
      return this.isGeneralDomainname({ domain_str: phone_context_str });
    }

    return this.isLdhDomainname({ domain_str: phone_context_str });
  }

  private isLdhDomainname(params: { domain_str: string }): boolean {
    const domain_str = params.domain_str;

    if (domain_str.length === 0 || domain_str.length > 253) {
      return false;
    }
    if (domain_str.startsWith('.') || domain_str.endsWith('.')) {
      return false;
    }
    if (domain_str.includes('..')) {
      return false;
    }

    const labels_arr = domain_str.split('.');
    for (const label_str of labels_arr) {
      if (!this.isDnsLabel({ label_str })) {
        return false;
      }
    }
    return true;
  }

  private isGeneralDomainname(params: { domain_str: string }): boolean {
    // Accepts a practical superset:
    // - dot-separated labels
    // - labels may contain alnum, hyphen, underscore, and other RFC3986 reg-name chars:
    //   unreserved / pct-encoded / sub-delims
    // - reject whitespace and URI delimiters that would be ambiguous
    const domain_str = params.domain_str;

    if (domain_str.length === 0 || domain_str.length > 253) {
      return false;
    }
    if (domain_str.startsWith('.') || domain_str.endsWith('.')) {
      return false;
    }
    if (domain_str.includes('..')) {
      return false;
    }

    if (
      domain_str.includes('/') ||
      domain_str.includes('?') ||
      domain_str.includes('#') ||
      domain_str.includes('@')
    ) {
      return false;
    }

    // Allow labels with: unreserved + sub-delims + "_" + "-"
    // (We already percent-decoded param values, so '%' should not appear here unless you want to allow raw.)
    const allowed_extra_str = "!$&'()*+,;=";

    const labels_arr = domain_str.split('.');
    for (const label_str of labels_arr) {
      if (label_str.length === 0 || label_str.length > 63) {
        return false;
      }

      // Disallow leading/trailing hyphen conservatively
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

        const is_unreserved_mark_bool =
          ch_str === '-' || ch_str === '.' || ch_str === '_' || ch_str === '~';
        const is_extra_bool = allowed_extra_str.includes(ch_str);

        if (
          is_alpha_bool ||
          is_digit_bool ||
          is_unreserved_mark_bool ||
          is_extra_bool
        ) {
          continue;
        }

        // Permit non-ASCII (IDN / U-label) if it isn't a control or whitespace
        if (code_u32 > 0x7f) {
          continue;
        }

        return false;
      }
    }

    return true;
  }

  private isDtmfDigitString(params: {
    value_str: string;
    min_len_u32: number;
    max_len_u32: number;
    allow_star_hash_bool: boolean;
    allow_abcd_bool: boolean;
    allow_visual_separators_bool: boolean;
  }): boolean {
    const value_str = params.value_str;

    if (
      value_str.length < params.min_len_u32 ||
      value_str.length > params.max_len_u32
    ) {
      return false;
    }

    let saw_digit_bool = false;
    let last_was_digit_bool = false;

    for (let i_u32 = 0; i_u32 < value_str.length; i_u32++) {
      const ch_str = value_str[i_u32];
      const code_u32 = value_str.charCodeAt(i_u32);

      const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;
      if (is_digit_bool) {
        saw_digit_bool = true;
        last_was_digit_bool = true;
        continue;
      }

      if (params.allow_star_hash_bool && (ch_str === '*' || ch_str === '#')) {
        saw_digit_bool = true;
        last_was_digit_bool = true;
        continue;
      }

      if (params.allow_abcd_bool) {
        const is_abcd_bool =
          ch_str === 'A' ||
          ch_str === 'B' ||
          ch_str === 'C' ||
          ch_str === 'D' ||
          ch_str === 'a' ||
          ch_str === 'b' ||
          ch_str === 'c' ||
          ch_str === 'd';
        if (is_abcd_bool) {
          saw_digit_bool = true;
          last_was_digit_bool = true;
          continue;
        }
      }

      if (params.allow_visual_separators_bool) {
        const is_sep_bool =
          ch_str === '-' ||
          ch_str === '.' ||
          ch_str === '(' ||
          ch_str === ')' ||
          ch_str === ' ' ||
          ch_str === '\t';
        if (is_sep_bool) {
          if (!last_was_digit_bool) {
            return false;
          }
          last_was_digit_bool = false;
          continue;
        }
      }

      return false;
    }

    return saw_digit_bool;
  }

  private isParamName(params: { name_str: string }): boolean {
    return /^[a-z0-9-]+$/.test(params.name_str);
  }

  private isDnsLabel(params: { label_str: string }): boolean {
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
  // Prechecks and helpers
  // -----------------------------

  private precheckInput(params: {
    input_str: string;
  }): tel_url_validation_result_t {
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

  private startsWithTelScheme(params: { input_str: string }): boolean {
    return (
      params.input_str.length >= 4 &&
      params.input_str.slice(0, 4).toLowerCase() === 'tel:'
    );
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

  private percentDecodeAscii(params: { input_str: string }): string {
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

  private isHex(params: { ch_str: string }): boolean {
    const code_u32 = params.ch_str.charCodeAt(0);
    const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;
    const is_upper_hex_bool = code_u32 >= 0x41 && code_u32 <= 0x46;
    const is_lower_hex_bool = code_u32 >= 0x61 && code_u32 <= 0x66;
    return is_digit_bool || is_upper_hex_bool || is_lower_hex_bool;
  }

  private containsAsciiControls(params: { input_str: string }): boolean {
    for (let i_u32 = 0; i_u32 < params.input_str.length; i_u32++) {
      const code_u32 = params.input_str.charCodeAt(i_u32);
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

  private normalizeTel(params: {
    is_global_bool: boolean;
    digits_only_str: string;
    local_number_str: string | null;
    parsed_params: Map<string, string | null>;
  }): string {
    const is_global_bool = params.is_global_bool;

    let out_str = is_global_bool
      ? `tel:+${params.digits_only_str}`
      : `tel:${params.local_number_str ?? ''}`;

    const pc_str = params.parsed_params.get('phone-context');
    if (pc_str !== undefined && pc_str !== null) {
      out_str += `;phone-context=${this.percentEncodeParamValue({ value_str: pc_str })}`;
    }

    const ext_str = params.parsed_params.get('ext');
    if (ext_str !== undefined && ext_str !== null) {
      out_str += `;ext=${this.percentEncodeParamValue({ value_str: ext_str })}`;
    }

    const isub_str = params.parsed_params.get('isub');
    if (isub_str !== undefined && isub_str !== null) {
      out_str += `;isub=${this.percentEncodeParamValue({ value_str: isub_str })}`;
    }

    const tsp_str = params.parsed_params.get('tsp');
    if (
      tsp_str !== undefined &&
      tsp_str !== null &&
      this.allow_tsp_param_bool
    ) {
      out_str += `;tsp=${this.percentEncodeParamValue({ value_str: tsp_str })}`;
    }

    if (this.allow_unknown_params_bool) {
      for (const [k_str, v_str] of params.parsed_params.entries()) {
        if (
          k_str === 'phone-context' ||
          k_str === 'ext' ||
          k_str === 'isub' ||
          k_str === 'tsp'
        ) {
          continue;
        }
        if (v_str === null) {
          out_str += `;${k_str}`;
        } else {
          out_str += `;${k_str}=${this.percentEncodeParamValue({ value_str: v_str })}`;
        }
      }
    }

    return out_str;
  }

  private percentEncodeParamValue(params: { value_str: string }): string {
    const value_str = params.value_str;

    let out_str = '';
    for (let i_u32 = 0; i_u32 < value_str.length; i_u32++) {
      const ch_str = value_str[i_u32];
      const code_u32 = value_str.charCodeAt(i_u32);

      const is_unreserved_bool =
        (code_u32 >= 0x41 && code_u32 <= 0x5a) ||
        (code_u32 >= 0x61 && code_u32 <= 0x7a) ||
        (code_u32 >= 0x30 && code_u32 <= 0x39) ||
        ch_str === '-' ||
        ch_str === '.' ||
        ch_str === '_' ||
        ch_str === '~';

      if (is_unreserved_bool) {
        out_str += ch_str;
        continue;
      }

      if (code_u32 <= 0xff) {
        out_str += `%${code_u32.toString(16).toUpperCase().padStart(2, '0')}`;
      } else {
        out_str += `%${((code_u32 >>> 8) & 0xff).toString(16).toUpperCase().padStart(2, '0')}`;
        out_str += `%${(code_u32 & 0xff).toString(16).toUpperCase().padStart(2, '0')}`;
      }
    }

    return out_str;
  }
}
