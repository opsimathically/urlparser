import { TelURLValidator } from './TelURLValidator.class';

type tel_url_fuzzer_options_t = {
  seed_u32?: number;

  max_total_length_u32?: number;

  // Valid generation knobs
  include_local_numbers_bool?: boolean;
  require_phone_context_for_local_bool?: boolean;

  allow_visual_separators_in_number_bool?: boolean;
  allow_pct_encoded_separators_in_number_bool?: boolean;

  include_ext_param_bool?: boolean;
  include_isub_param_bool?: boolean;
  include_phone_context_param_bool?: boolean;
  include_tsp_param_bool?: boolean;

  // Extended features you mentioned earlier
  allow_dtmf_in_ext_bool?: boolean; // allow '*' and '#'
  allow_dtmf_abcd_bool?: boolean; // allow A-D/a-d

  // If true, include some "known good" realistic examples
  include_known_examples_bool?: boolean;
};

export class TelURLFuzzer {
  private rng_state_u32: number;

  private max_total_length_u32: number;

  private include_local_numbers_bool: boolean;
  private require_phone_context_for_local_bool: boolean;

  private allow_visual_separators_in_number_bool: boolean;
  private allow_pct_encoded_separators_in_number_bool: boolean;

  private include_ext_param_bool: boolean;
  private include_isub_param_bool: boolean;
  private include_phone_context_param_bool: boolean;
  private include_tsp_param_bool: boolean;

  private allow_dtmf_in_ext_bool: boolean;
  private allow_dtmf_abcd_bool: boolean;

  private include_known_examples_bool: boolean;

  public constructor(params: tel_url_fuzzer_options_t = {}) {
    this.rng_state_u32 = params.seed_u32 ?? 0x1234abcd;

    this.max_total_length_u32 = params.max_total_length_u32 ?? 16_384;

    this.include_local_numbers_bool = params.include_local_numbers_bool ?? true;
    this.require_phone_context_for_local_bool =
      params.require_phone_context_for_local_bool ?? true;

    this.allow_visual_separators_in_number_bool =
      params.allow_visual_separators_in_number_bool ?? true;
    this.allow_pct_encoded_separators_in_number_bool =
      params.allow_pct_encoded_separators_in_number_bool ?? true;

    this.include_ext_param_bool = params.include_ext_param_bool ?? true;
    this.include_isub_param_bool = params.include_isub_param_bool ?? true;
    this.include_phone_context_param_bool =
      params.include_phone_context_param_bool ?? true;
    this.include_tsp_param_bool = params.include_tsp_param_bool ?? true;

    this.allow_dtmf_in_ext_bool = params.allow_dtmf_in_ext_bool ?? true;
    this.allow_dtmf_abcd_bool = params.allow_dtmf_abcd_bool ?? true;

    this.include_known_examples_bool =
      params.include_known_examples_bool ?? true;
  }

  // -----------------------------
  // Public API
  // -----------------------------

  public generateValidTelUrls(params: { count_u32: number }): string[] {
    const count_u32 = params.count_u32 >>> 0;
    const out_arr: string[] = [];

    const tel_validator = new TelURLValidator({
      allow_dtmf_abcd_bool: true,
      allow_dtmf_in_ext_bool: true,
      allow_fragment_bool: true,
      allow_general_domainname_in_phone_context_bool: true,
      allow_local_number_bool: true,
      allow_pct_encoded_in_params_bool: true,
      allow_query_bool: true,
      allow_tsp_param_bool: true,
      allow_unknown_params_bool: true
    });

    for (let i_u32 = 0; i_u32 < count_u32; ) {
      const tel_url = this.generateOneValidTelUrl();
      const validated = tel_validator.validate({ tel_url_str: tel_url });
      if (!validated?.is_valid_bool) continue;
      out_arr.push(tel_url);
      i_u32++;
    }

    return out_arr;
  }

  public generateInvalidTelUrls(params: { count_u32: number }): string[] {
    const count_u32 = params.count_u32 >>> 0;
    const out_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
      out_arr.push(this.generateOneInvalidTelUrl());
    }

    return out_arr;
  }

  // -----------------------------
  // Valid generation (RFC 3966-ish + extensions)
  // -----------------------------

  private generateOneValidTelUrl(): string {
    if (
      this.include_known_examples_bool &&
      this.nextBool({ chance_f64: 0.12 })
    ) {
      const examples_arr = [
        'tel:+15551234567',
        'TEL:+1 (555) 123-4567',
        'tel:+1(555)123-4567',
        'tel:+1%20555%20123%204567',
        'tel:5551234567;phone-context=+1',
        'tel:(555)123-4567;phone-context=example.com',
        'tel:+15551234567;ext=123',
        'tel:+15551234567;ext=12*34#56',
        'tel:+15551234567;tsp=9-123-4567'
      ];
      return examples_arr[this.nextU32({ max_u32: examples_arr.length })];
    }

    const scheme_str = this.nextBool({ chance_f64: 0.25 })
      ? 'TEL'
      : this.nextBool({ chance_f64: 0.25 })
        ? 'tEl'
        : 'tel';

    const is_global_bool =
      this.nextBool({ chance_f64: 0.7 }) || !this.include_local_numbers_bool;

    const number_str = is_global_bool
      ? this.generateGlobalNumber({
          allow_visual_bool: this.allow_visual_separators_in_number_bool,
          allow_pct_sep_bool: this.allow_pct_encoded_separators_in_number_bool
        })
      : this.generateLocalNumber({
          allow_visual_bool: this.allow_visual_separators_in_number_bool,
          allow_pct_sep_bool: this.allow_pct_encoded_separators_in_number_bool
        });

    const params_arr: string[] = [];

    // phone-context for local numbers (required by strict RFC mode)
    const should_add_phone_context_bool =
      this.include_phone_context_param_bool &&
      (!is_global_bool
        ? this.require_phone_context_for_local_bool ||
          this.nextBool({ chance_f64: 0.35 })
        : this.nextBool({ chance_f64: 0.1 }));

    if (should_add_phone_context_bool) {
      params_arr.push(this.generatePhoneContextParam());
    }

    if (this.include_ext_param_bool && this.nextBool({ chance_f64: 0.35 })) {
      params_arr.push(this.generateExtParam());
    }

    if (this.include_isub_param_bool && this.nextBool({ chance_f64: 0.2 })) {
      params_arr.push(this.generateIsubParam());
    }

    if (this.include_tsp_param_bool && this.nextBool({ chance_f64: 0.2 })) {
      params_arr.push(this.generateTspParam());
    }

    // Shuffle params to exercise ordering
    this.shuffleInPlace({ arr: params_arr });

    const param_str = params_arr.length === 0 ? '' : ';' + params_arr.join(';');

    let url_str = `${scheme_str}:${number_str}${param_str}`;
    if (url_str.length > this.max_total_length_u32) {
      url_str = url_str.slice(0, this.max_total_length_u32);
    }
    return url_str;
  }

  private generateGlobalNumber(params: {
    allow_visual_bool: boolean;
    allow_pct_sep_bool: boolean;
  }): string {
    // E.164 max 15 digits; generate 1..15 digits.
    const digit_count_u32 = 1 + this.nextU32({ max_u32: 15 });

    const raw_digits_str = this.randomDigits({ count_u32: digit_count_u32 });

    if (!params.allow_visual_bool && !params.allow_pct_sep_bool) {
      return `+${raw_digits_str}`;
    }

    // Sometimes return straight digits
    if (this.nextBool({ chance_f64: 0.35 })) {
      return `+${raw_digits_str}`;
    }

    // Insert visual separators / parentheses in a plausible way
    let formatted_str = '';
    for (let i_u32 = 0; i_u32 < raw_digits_str.length; i_u32++) {
      const d_str = raw_digits_str[i_u32];

      if (i_u32 === 1 && this.nextBool({ chance_f64: 0.2 })) {
        formatted_str += ' ';
      }

      // Optional parentheses around a small group after country code
      if (i_u32 === 1 && this.nextBool({ chance_f64: 0.25 })) {
        formatted_str += '(';
      }
      formatted_str += d_str;

      if (
        i_u32 === 3 &&
        formatted_str.includes('(') &&
        !formatted_str.includes(')')
      ) {
        formatted_str += ')';
      }

      if (
        i_u32 + 1 < raw_digits_str.length &&
        this.nextBool({ chance_f64: 0.18 })
      ) {
        const sep_arr = [' ', '-', '.', '\t'];
        formatted_str += sep_arr[this.nextU32({ max_u32: sep_arr.length })];
      }
    }

    if (params.allow_pct_sep_bool && this.nextBool({ chance_f64: 0.35 })) {
      // Percent-encode some spaces/tabs to test %20 etc.
      formatted_str = formatted_str.replace(/ /g, '%20').replace(/\t/g, '%09');
    }

    return `+${formatted_str}`;
  }

  private generateLocalNumber(params: {
    allow_visual_bool: boolean;
    allow_pct_sep_bool: boolean;
  }): string {
    // Local numbers are namespace-specific; generate 1..20 digits-ish with optional formatting.
    const digit_count_u32 = 1 + this.nextU32({ max_u32: 20 });
    const raw_digits_str = this.randomDigits({ count_u32: digit_count_u32 });

    if (!params.allow_visual_bool && !params.allow_pct_sep_bool) {
      return raw_digits_str;
    }

    if (this.nextBool({ chance_f64: 0.4 })) {
      return raw_digits_str;
    }

    // Common local formatting: (AAA)BBB-CCCC etc if enough digits
    let out_str = '';
    if (raw_digits_str.length >= 7 && this.nextBool({ chance_f64: 0.45 })) {
      const a_str = raw_digits_str.slice(0, 3);
      const b_str = raw_digits_str.slice(3, 6);
      const c_str = raw_digits_str.slice(6);

      out_str = `(${a_str})${b_str}-${c_str}`;
    } else {
      out_str = raw_digits_str;
      for (let i_u32 = 1; i_u32 < out_str.length; i_u32 += 3) {
        if (this.nextBool({ chance_f64: 0.3 })) {
          out_str = out_str.slice(0, i_u32) + ' ' + out_str.slice(i_u32);
        }
      }
    }

    if (params.allow_pct_sep_bool && this.nextBool({ chance_f64: 0.35 })) {
      out_str = out_str.replace(/ /g, '%20').replace(/\t/g, '%09');
    }

    return out_str;
  }

  private generatePhoneContextParam(): string {
    // phone-context can be +global-number or domainname
    const use_global_context_bool = this.nextBool({ chance_f64: 0.5 });

    let value_str = '';
    if (use_global_context_bool) {
      const digit_count_u32 = 1 + this.nextU32({ max_u32: 15 });
      value_str = `+${this.randomDigits({ count_u32: digit_count_u32 })}`;
    } else {
      value_str = this.generateDomainName();
    }

    return `phone-context=${this.pctEncodeIfNeeded({ value_str })}`;
  }

  private generateExtParam(): string {
    // ext: 1*phonedigit; include DTMF extras optionally
    const len_u32 = 1 + this.nextU32({ max_u32: 12 });

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const roll_u32 = this.nextU32({ max_u32: 100 });

      if (roll_u32 < 70) {
        out_str += this.randomDigits({ count_u32: 1 });
        continue;
      }

      if (this.allow_dtmf_in_ext_bool && roll_u32 < 90) {
        out_str += this.nextBool({ chance_f64: 0.5 }) ? '*' : '#';
        continue;
      }

      if (this.allow_dtmf_abcd_bool) {
        const abcd_arr = ['A', 'B', 'C', 'D', 'a', 'b', 'c', 'd'];
        out_str += abcd_arr[this.nextU32({ max_u32: abcd_arr.length })];
        continue;
      }

      out_str += this.randomDigits({ count_u32: 1 });
    }

    return `ext=${this.pctEncodeIfNeeded({ value_str: out_str })}`;
  }

  private generateIsubParam(): string {
    const val_str = this.randomToken({
      min_len_u32: 1,
      max_len_u32: 18,
      allow_dot_bool: true,
      allow_underscore_bool: true
    });
    return `isub=${this.pctEncodeIfNeeded({ value_str: val_str })}`;
  }

  private generateTspParam(): string {
    // TSP: allow digits + optional visual separators + optional DTMF
    const len_u32 = 1 + this.nextU32({ max_u32: 24 });
    const sep_arr = ['-', '.', ' ', '\t'];

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      const roll_u32 = this.nextU32({ max_u32: 100 });

      if (roll_u32 < 70) {
        out_str += this.randomDigits({ count_u32: 1 });
        continue;
      }

      if (this.allow_dtmf_in_ext_bool && roll_u32 < 80) {
        out_str += this.nextBool({ chance_f64: 0.5 }) ? '*' : '#';
        continue;
      }

      if (this.allow_dtmf_abcd_bool && roll_u32 < 85) {
        const abcd_arr = ['A', 'B', 'C', 'D'];
        out_str += abcd_arr[this.nextU32({ max_u32: abcd_arr.length })];
        continue;
      }

      out_str += sep_arr[this.nextU32({ max_u32: sep_arr.length })];
    }

    // Avoid raw spaces/tabs by encoding (many validators disallow them in params)
    out_str = out_str.replace(/ /g, '%20').replace(/\t/g, '%09');

    return `tsp=${out_str}`;
  }

  // -----------------------------
  // Invalid generation
  // -----------------------------

  private generateOneInvalidTelUrl(): string {
    // Includes:
    // - bad scheme, missing parts
    // - invalid chars in number, malformed percent encodings
    // - unterminated parens, nested parens, weird ordering
    // - duplicate params, empty param segments, missing values
    // - local without phone-context (if strict)
    // - params containing forbidden chars, whitespace around '=' or leading space after ';'
    // - huge parameter chains (stress)
    const mode_u32 = this.nextU32({ max_u32: 22 });

    if (mode_u32 === 0) {
      return 'tel'; // missing ':'
    }
    if (mode_u32 === 1) {
      return 'tel:'; // missing number
    }
    if (mode_u32 === 2) {
      return 'tel:+'; // missing digits
    }
    if (mode_u32 === 3) {
      return 'tel:+12%3'; // malformed percent in number
    }
    if (mode_u32 === 4) {
      return 'tel:+12%GG34'; // malformed percent hex
    }
    if (mode_u32 === 5) {
      return 'tel:+1(555123-4567'; // unterminated '('
    }
    if (mode_u32 === 6) {
      return 'tel:+1((555))123-4567'; // nested parens
    }
    if (mode_u32 === 7) {
      return 'tel:+1)555(123-4567'; // misplaced parens
    }
    if (mode_u32 === 8) {
      return 'tel:+15551234567;'; // empty param segment
    }
    if (mode_u32 === 9) {
      return 'tel:+15551234567;;ext=123'; // empty param between ;;
    }
    if (mode_u32 === 10) {
      return 'tel:+15551234567;ext='; // empty value
    }
    if (mode_u32 === 11) {
      return 'tel:+15551234567;ext'; // missing value for known param
    }
    if (mode_u32 === 12) {
      return 'tel:+15551234567; ext=123'; // leading space in param name
    }
    if (mode_u32 === 13) {
      return 'tel:+15551234567;ex t=123'; // space in param name
    }
    if (mode_u32 === 14) {
      return 'tel:+15551234567;ext=12%2'; // malformed percent in param value
    }
    if (mode_u32 === 15) {
      return 'tel:5551234567'; // local without phone-context (strict RFC mode)
    }
    if (mode_u32 === 16) {
      return 'tel:5551234567;phone-context='; // missing phone-context value
    }
    if (mode_u32 === 17) {
      return 'tel:5551234567;phone-context=exa mple.com'; // space in domain
    }
    if (mode_u32 === 18) {
      return 'tel:+15551234567;ext=12**34'; // repeated dtmf separators (some parsers hate)
    }
    if (mode_u32 === 19) {
      return 'tel:+15551234567;ext=12\x01'; // control char
    }
    if (mode_u32 === 20) {
      // Duplicate param name
      return 'tel:+15551234567;ext=123;ext=456';
    }

    // mode 21: stress: huge chain of params with tricky separators
    const chain_len_u32 = 50 + this.nextU32({ max_u32: 200 });
    let out_str = 'tel:+15551234567';
    for (let i_u32 = 0; i_u32 < chain_len_u32; i_u32++) {
      const bad_piece_u32 = this.nextU32({ max_u32: 6 });
      if (bad_piece_u32 === 0) {
        out_str +=
          ';x-' +
          this.randomToken({
            min_len_u32: 1,
            max_len_u32: 8,
            allow_dot_bool: false,
            allow_underscore_bool: false
          }) +
          '=A%';
      } else if (bad_piece_u32 === 1) {
        out_str += ';;';
      } else if (bad_piece_u32 === 2) {
        out_str += ';=nope';
      } else if (bad_piece_u32 === 3) {
        out_str += ';x= \t';
      } else if (bad_piece_u32 === 4) {
        out_str += ';phone-context=+';
      } else {
        out_str += ';ext=' + '9'.repeat(40);
      }

      if (out_str.length > this.max_total_length_u32) {
        break;
      }
    }

    return out_str.slice(0, this.max_total_length_u32);
  }

  // -----------------------------
  // Helpers
  // -----------------------------

  private generateDomainName(): string {
    // Simple LDH labels; keep it parser-friendly.
    const label_count_u32 = 2 + this.nextU32({ max_u32: 3 }); // 2..4
    const labels_arr: string[] = [];

    for (let i_u32 = 0; i_u32 < label_count_u32; i_u32++) {
      const len_u32 = 1 + this.nextU32({ max_u32: 12 });
      let label_str = '';

      for (let j_u32 = 0; j_u32 < len_u32; j_u32++) {
        const roll_u32 = this.nextU32({ max_u32: 100 });
        if (roll_u32 < 75) {
          label_str += this.randomAlnumChar();
        } else {
          label_str += '-';
        }
      }

      label_str = label_str.replace(/^-+/, 'a').replace(/-+$/, 'a');
      labels_arr.push(label_str.toLowerCase());
    }

    return labels_arr.join('.');
  }

  private pctEncodeIfNeeded(params: { value_str: string }): string {
    // For params, we keep mostly unreserved/sub-delims; if others appear, percent-encode as UTF-8 bytes.
    // Here we conservatively percent-encode any byte outside [A-Za-z0-9-._~!$&'()*+,;=:@/]
    const value_str = params.value_str;

    const allowed_str =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/";
    let out_str = '';

    for (let i_u32 = 0; i_u32 < value_str.length; i_u32++) {
      const ch_str = value_str[i_u32];
      if (allowed_str.includes(ch_str)) {
        out_str += ch_str;
        continue;
      }

      // Percent-encode as a single byte (ASCII) for fuzzing simplicity.
      const code_u32 = value_str.charCodeAt(i_u32);
      const byte_u32 = code_u32 & 0xff;
      out_str += '%' + byte_u32.toString(16).toUpperCase().padStart(2, '0');
    }

    return out_str;
  }

  private randomDigits(params: { count_u32: number }): string {
    const count_u32 = params.count_u32 >>> 0;
    let out_str = '';
    for (let i_u32 = 0; i_u32 < count_u32; i_u32++) {
      out_str += String.fromCharCode(0x30 + this.nextU32({ max_u32: 10 }));
    }
    return out_str;
  }

  private randomToken(params: {
    min_len_u32: number;
    max_len_u32: number;
    allow_dot_bool: boolean;
    allow_underscore_bool: boolean;
  }): string {
    const min_len_u32 = params.min_len_u32 >>> 0;
    const max_len_u32 = params.max_len_u32 >>> 0;

    const len_u32 =
      min_len_u32 +
      this.nextU32({ max_u32: Math.max(1, max_len_u32 - min_len_u32 + 1) });

    let alphabet_str =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-';
    if (params.allow_dot_bool) {
      alphabet_str += '.';
    }
    if (params.allow_underscore_bool) {
      alphabet_str += '_';
    }

    let out_str = '';
    for (let i_u32 = 0; i_u32 < len_u32; i_u32++) {
      out_str += alphabet_str[this.nextU32({ max_u32: alphabet_str.length })];
    }

    return out_str;
  }

  private shuffleInPlace(params: { arr: string[] }): void {
    const arr = params.arr;
    for (let i_i32 = arr.length - 1; i_i32 > 0; i_i32--) {
      const j_i32 = this.nextU32({ max_u32: i_i32 + 1 });
      const tmp_str = arr[i_i32];
      arr[i_i32] = arr[j_i32];
      arr[j_i32] = tmp_str;
    }
  }

  // -----------------------------
  // RNG (xorshift32)
  // -----------------------------

  private nextU32(params: { max_u32: number }): number {
    const max_u32 = params.max_u32 >>> 0;
    if (max_u32 === 0) {
      return 0;
    }

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
