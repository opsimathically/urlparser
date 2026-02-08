type mailto_validation_result_t = {
  is_valid_bool: boolean;
  reason_str?: string;

  // Parsed (only populated when is_valid_bool === true, unless you choose to ignore)
  scheme_str?: string; // "mailto"
  to_raw_str?: string; // raw (percent-encoded) to-part (without leading "mailto:")
  to_decoded_str?: string; // decoded to-part
  recipients_arr?: string[]; // decoded addr-specs (or local-only, if allowed)
  headers_map?: Map<string, string[]>; // lowercased header-name -> decoded values (may repeat)
};

type mailto_url_validator_options_t = {
  max_total_length_u32?: number;
  max_to_length_u32?: number;
  max_recipient_count_u32?: number;
  max_header_count_u32?: number;
  max_header_name_length_u32?: number;
  max_header_value_length_u32?: number;

  // RFC 6068 permits empty to-part (e.g. "mailto:?subject=x").
  allow_empty_to_bool?: boolean;

  // RFC 6068 allows "to" header in the query (in addition to the to-part). Many parsers accept it.
  allow_to_header_bool?: boolean;

  // Accept local-only recipients (no "@domain"). RFC 6068 discusses this; some parsers allow, some reject.
  allow_local_only_recipient_bool?: boolean;

  // If false, reject unknown header fields (only allow common ones below).
  allow_unknown_headers_bool?: boolean;

  // If provided, overrides default allowed headers list.
  allowed_headers_arr?: string[];
};

/*

// Optional convenience wrapper (PascalCase per your convention)
function ValidateMailtoUrl(params: { mailto_url_str: string; options_obj?: mailto_url_validator_options_t }): mailto_validation_result_t {
    const validator_obj = new MailtoUrlValidator(params.options_obj ?? {});
    return validator_obj.validate({ mailto_url_str: params.mailto_url_str });
}
    */

export class MailtoURLValidator {
  private max_total_length_u32: number;
  private max_to_length_u32: number;
  private max_recipient_count_u32: number;
  private max_header_count_u32: number;
  private max_header_name_length_u32: number;
  private max_header_value_length_u32: number;

  private allow_empty_to_bool: boolean;
  private allow_to_header_bool: boolean;
  private allow_local_only_recipient_bool: boolean;
  private allow_unknown_headers_bool: boolean;
  private allowed_headers_set: Set<string>;

  public constructor(params: mailto_url_validator_options_t = {}) {
    this.max_total_length_u32 = params.max_total_length_u32 ?? 2048;
    this.max_to_length_u32 = params.max_to_length_u32 ?? 1024;
    this.max_recipient_count_u32 = params.max_recipient_count_u32 ?? 32;
    this.max_header_count_u32 = params.max_header_count_u32 ?? 64;
    this.max_header_name_length_u32 = params.max_header_name_length_u32 ?? 64;
    this.max_header_value_length_u32 =
      params.max_header_value_length_u32 ?? 4096;

    this.allow_empty_to_bool = params.allow_empty_to_bool ?? true;
    this.allow_to_header_bool = params.allow_to_header_bool ?? true;
    this.allow_local_only_recipient_bool =
      params.allow_local_only_recipient_bool ?? false;

    this.allow_unknown_headers_bool = params.allow_unknown_headers_bool ?? true;

    const default_allowed_headers_arr = [
      'to',
      'cc',
      'bcc',
      'subject',
      'body',
      'in-reply-to',
      // common de-facto extras
      'reply-to',
      'from'
    ];

    const allowed_headers_arr =
      params.allowed_headers_arr ?? default_allowed_headers_arr;
    this.allowed_headers_set = new Set<string>(
      allowed_headers_arr.map((h_str) => h_str.toLowerCase())
    );
  }

  public validate(params: {
    mailto_url_str: string;
  }): mailto_validation_result_t {
    const mailto_url_str = params.mailto_url_str;

    const precheck_result = this.precheckInput({ mailto_url_str });
    if (!precheck_result.is_valid_bool) {
      return precheck_result;
    }

    const prefix_result = this.parseSchemePrefix({ mailto_url_str });
    if (!prefix_result.is_valid_bool) {
      return prefix_result;
    }

    const after_scheme_str = prefix_result.after_scheme_str as string;

    // Split [to-part][?query]
    const qmark_idx_i32 = after_scheme_str.indexOf('?');
    const to_raw_str =
      qmark_idx_i32 >= 0
        ? after_scheme_str.slice(0, qmark_idx_i32)
        : after_scheme_str;
    const query_raw_str =
      qmark_idx_i32 >= 0 ? after_scheme_str.slice(qmark_idx_i32 + 1) : '';

    if (to_raw_str.length > this.max_to_length_u32) {
      return {
        is_valid_bool: false,
        reason_str: 'to-part exceeds max_to_length'
      };
    }

    if (!this.isPctEncodingWellFormed({ input_str: to_raw_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'to-part contains malformed percent-encoding'
      };
    }

    const to_decoded_str = this.percentDecodeASCII({ input_str: to_raw_str });

    // RFC 6068: to-part is a list of addr-spec separated by commas (no CFWS); many parsers are strict here.
    const recipients_arr: string[] = [];
    if (to_decoded_str.length === 0) {
      if (!this.allow_empty_to_bool && query_raw_str.length === 0) {
        return {
          is_valid_bool: false,
          reason_str: 'empty to-part not allowed'
        };
      }
    } else {
      if (this.containsASCIIControls({ input_str: to_decoded_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'decoded to-part contains control characters'
        };
      }

      const parts_arr = this.splitRecipients({ to_decoded_str });
      if (parts_arr === null) {
        return {
          is_valid_bool: false,
          reason_str: 'malformed recipient list (quotes/escapes)'
        };
      }

      for (const part_str of parts_arr) {
        if (part_str.length === 0) {
          return {
            is_valid_bool: false,
            reason_str: 'empty recipient in to-part'
          };
        }
        const addr_result = this.validateRecipient({
          recipient_str: part_str
        });
        if (!addr_result.is_valid_bool) {
          return addr_result;
        }
        recipients_arr.push(part_str);
      }
    }

    const headers_map = new Map<string, string[]>();
    if (query_raw_str.length > 0) {
      const query_result = this.validateAndParseQuery({
        query_raw_str,
        headers_map
      });
      if (!query_result.is_valid_bool) {
        return query_result;
      }
    }

    // Optional: enforce that "to" header is absent if you want canonical form only.
    if (!this.allow_to_header_bool && headers_map.has('to')) {
      return {
        is_valid_bool: false,
        reason_str: '"to" header is not allowed by configuration'
      };
    }

    return {
      is_valid_bool: true,
      scheme_str: 'mailto',
      to_raw_str,
      to_decoded_str,
      recipients_arr,
      headers_map
    };
  }

  // -----------------------------
  // Scheme and prechecks
  // -----------------------------

  private precheckInput(params: {
    mailto_url_str: string;
  }): mailto_validation_result_t {
    const mailto_url_str = params.mailto_url_str;

    if (mailto_url_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty input' };
    }

    if (mailto_url_str.length > this.max_total_length_u32) {
      return { is_valid_bool: false, reason_str: 'exceeds max_total_length' };
    }

    const invalid_reason_str = this.findControlOrInvalidUnicode({
      input_str: mailto_url_str
    });
    if (invalid_reason_str !== null) {
      return { is_valid_bool: false, reason_str: invalid_reason_str };
    }

    return { is_valid_bool: true };
  }

  private parseSchemePrefix(params: {
    mailto_url_str: string;
  }): mailto_validation_result_t & { after_scheme_str?: string } {
    const mailto_url_str = params.mailto_url_str;

    if (mailto_url_str.length < 7) {
      return { is_valid_bool: false, reason_str: 'too short to be mailto:' };
    }

    const prefix_str = mailto_url_str.slice(0, 7).toLowerCase();
    if (prefix_str !== 'mailto:') {
      return {
        is_valid_bool: false,
        reason_str: 'must start with mailto: (case-insensitive)'
      };
    }

    // Reject hierarchical confusion: mailto://...
    if (mailto_url_str.slice(7, 9) === '//') {
      return {
        is_valid_bool: false,
        reason_str: 'mailto must not use hierarchical form (mailto://...)'
      };
    }

    return { is_valid_bool: true, after_scheme_str: mailto_url_str.slice(7) };
  }

  // -----------------------------
  // Recipient (addr-spec) validation (practical RFC 5322 subset)
  // -----------------------------

  private validateRecipient(params: {
    recipient_str: string;
  }): mailto_validation_result_t {
    const recipient_str = params.recipient_str;

    const split_result = this.splitAddrSpec({ recipient_str });
    if (!split_result.is_valid_bool) {
      return { is_valid_bool: false, reason_str: split_result.reason_str };
    }

    const local_part_str = split_result.local_part_str as string;
    const domain_str = split_result.domain_str as string;

    const local_result = this.validateLocalPart({ local_part_str });
    if (!local_result.is_valid_bool) {
      return local_result;
    }

    if (domain_str.length === 0) {
      if (!this.allow_local_only_recipient_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'recipient missing @domain'
        };
      }
      return { is_valid_bool: true };
    }

    const domain_result = this.validateDomain({ domain_str });
    if (!domain_result.is_valid_bool) {
      return domain_result;
    }

    return { is_valid_bool: true };
  }

  private splitAddrSpec(params: { recipient_str: string }): {
    is_valid_bool: boolean;
    reason_str?: string;
    local_part_str?: string;
    domain_str?: string;
  } {
    const recipient_str = params.recipient_str;

    if (recipient_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty recipient' };
    }

    // Quoted local-part: "<qcontent>"@domain
    if (recipient_str.startsWith('"')) {
      const end_quote_idx_i32 = this.findClosingQuote({
        input_str: recipient_str,
        start_idx_u32: 0
      });
      if (end_quote_idx_i32 < 0) {
        return {
          is_valid_bool: false,
          reason_str: 'quoted local-part must start and end with double-quote'
        };
      }

      const at_idx_i32 = end_quote_idx_i32 + 1;
      if (
        at_idx_i32 >= recipient_str.length ||
        recipient_str[at_idx_i32] !== '@'
      ) {
        // Allow local-only quoted local-part if configured (no @domain)
        const local_only_bool = at_idx_i32 >= recipient_str.length;
        if (local_only_bool) {
          return {
            is_valid_bool: true,
            local_part_str: recipient_str,
            domain_str: ''
          };
        }
        return {
          is_valid_bool: false,
          reason_str: 'missing @ after quoted local-part'
        };
      }

      const local_part_str = recipient_str.slice(0, at_idx_i32);
      const domain_str = recipient_str.slice(at_idx_i32 + 1);

      if (domain_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty domain' };
      }

      return { is_valid_bool: true, local_part_str, domain_str };
    }

    // Dot-atom local-part: should not contain '@', so first '@' is the separator if present.
    const at_idx_i32 = recipient_str.indexOf('@');
    if (at_idx_i32 < 0) {
      return {
        is_valid_bool: true,
        local_part_str: recipient_str,
        domain_str: ''
      };
    }

    // Ensure only one separator '@' (extra '@' would be in domain, which we reject)
    if (recipient_str.indexOf('@', at_idx_i32 + 1) >= 0) {
      return {
        is_valid_bool: false,
        reason_str: 'recipient must contain exactly one @ separator'
      };
    }

    const local_part_str = recipient_str.slice(0, at_idx_i32);
    const domain_str = recipient_str.slice(at_idx_i32 + 1);

    if (local_part_str.length === 0 || domain_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty local-part or domain' };
    }

    return { is_valid_bool: true, local_part_str, domain_str };
  }

  private splitRecipients(params: { to_decoded_str: string }): string[] | null {
    const to_decoded_str = params.to_decoded_str;

    const out_arr: string[] = [];
    let cur_str = '';

    let in_quotes_bool = false;
    let escape_next_bool = false;

    for (let i_u32 = 0; i_u32 < to_decoded_str.length; i_u32++) {
      const ch_str = to_decoded_str[i_u32];

      if (escape_next_bool) {
        cur_str += ch_str;
        escape_next_bool = false;
        continue;
      }

      if (in_quotes_bool && ch_str === '\\') {
        cur_str += ch_str;
        escape_next_bool = true;
        continue;
      }

      if (ch_str === '"') {
        cur_str += ch_str;
        in_quotes_bool = !in_quotes_bool;
        continue;
      }

      if (!in_quotes_bool && ch_str === ',') {
        if (cur_str.length === 0) {
          return null; // empty recipient
        }
        out_arr.push(cur_str);
        cur_str = '';
        continue;
      }

      cur_str += ch_str;
    }

    if (in_quotes_bool || escape_next_bool) {
      return null; // unterminated quote or dangling escape
    }

    if (cur_str.length > 0) {
      out_arr.push(cur_str);
    }

    return out_arr;
  }

  private findClosingQuote(params: {
    input_str: string;
    start_idx_u32: number;
  }): number {
    const input_str = params.input_str;
    let i_u32 = params.start_idx_u32;

    if (i_u32 >= input_str.length || input_str[i_u32] !== '"') {
      return -1;
    }

    i_u32++; // skip opening quote
    for (; i_u32 < input_str.length; i_u32++) {
      const ch_str = input_str[i_u32];

      if (ch_str === '\\') {
        // quoted-pair: skip escaped char if present
        if (i_u32 + 1 >= input_str.length) {
          return -1;
        }
        i_u32++;
        continue;
      }

      if (ch_str === '"') {
        return i_u32; // closing quote position
      }
    }

    return -1;
  }

  private validateLocalPart(params: {
    local_part_str: string;
  }): mailto_validation_result_t {
    const local_part_str = params.local_part_str;

    if (local_part_str.length > 64) {
      return {
        is_valid_bool: false,
        reason_str: 'local-part exceeds 64 chars'
      };
    }

    if (local_part_str.startsWith('"')) {
      return this.validateQuotedLocalPart({ local_part_str });
    }

    return this.validateDotAtomLocalPart({ local_part_str });
  }

  private validateDotAtomLocalPart(params: {
    local_part_str: string;
  }): mailto_validation_result_t {
    const local_part_str = params.local_part_str;

    if (local_part_str.startsWith('.') || local_part_str.endsWith('.')) {
      return {
        is_valid_bool: false,
        reason_str: 'dot-atom local-part must not start/end with dot'
      };
    }

    if (local_part_str.includes('..')) {
      return {
        is_valid_bool: false,
        reason_str: 'dot-atom local-part must not contain consecutive dots'
      };
    }

    const atoms_arr = local_part_str.split('.');
    for (const atom_str of atoms_arr) {
      if (atom_str.length === 0) {
        return {
          is_valid_bool: false,
          reason_str: 'empty atom in dot-atom local-part'
        };
      }
      if (!this.isAtext_Token({ token_str: atom_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'dot-atom local-part contains invalid characters'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private validateQuotedLocalPart(params: {
    local_part_str: string;
  }): mailto_validation_result_t {
    const local_part_str = params.local_part_str;

    if (local_part_str.length < 2 || !local_part_str.endsWith('"')) {
      return {
        is_valid_bool: false,
        reason_str: 'quoted local-part must start and end with double-quote'
      };
    }

    // Content between quotes: allow qtext (printable excluding \ and ") plus quoted-pair escapes.
    const inner_str = local_part_str.slice(1, local_part_str.length - 1);

    for (let i_u32 = 0; i_u32 < inner_str.length; i_u32++) {
      const ch_str = inner_str[i_u32];

      // disallow raw CR/LF and controls
      const code_u32 = inner_str.charCodeAt(i_u32);
      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return {
          is_valid_bool: false,
          reason_str: 'quoted local-part contains control characters'
        };
      }

      if (ch_str === '\\') {
        // quoted-pair must have following char
        if (i_u32 + 1 >= inner_str.length) {
          return {
            is_valid_bool: false,
            reason_str: 'dangling escape in quoted local-part'
          };
        }
        const next_code_u32 = inner_str.charCodeAt(i_u32 + 1);
        if (next_code_u32 <= 0x1f || next_code_u32 === 0x7f) {
          return {
            is_valid_bool: false,
            reason_str: 'escaped char in quoted local-part is a control'
          };
        }
        i_u32 += 1;
        continue;
      }

      if (ch_str === '"') {
        return {
          is_valid_bool: false,
          reason_str: 'unescaped quote in quoted local-part'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private validateDomain(params: {
    domain_str: string;
  }): mailto_validation_result_t {
    const domain_str = params.domain_str;

    if (domain_str.length > 253) {
      return { is_valid_bool: false, reason_str: 'domain exceeds 253 chars' };
    }

    // Domain-literal: [ ... ]
    if (domain_str.startsWith('[') || domain_str.endsWith(']')) {
      return this.validateDomainLiteral({ domain_str });
    }

    // DNS name: labels separated by dots, LDH rule.
    if (domain_str.startsWith('.') || domain_str.endsWith('.')) {
      return {
        is_valid_bool: false,
        reason_str: 'domain must not start/end with dot'
      };
    }
    if (domain_str.includes('..')) {
      return {
        is_valid_bool: false,
        reason_str: 'domain must not contain empty labels'
      };
    }

    const labels_arr = domain_str.split('.');
    if (labels_arr.length < 1) {
      return { is_valid_bool: false, reason_str: 'domain missing labels' };
    }

    for (const label_str of labels_arr) {
      const label_result = this.validateDNSLabel({ label_str });
      if (!label_result.is_valid_bool) {
        return label_result;
      }
    }

    return { is_valid_bool: true };
  }

  private validateDNSLabel(params: {
    label_str: string;
  }): mailto_validation_result_t {
    const label_str = params.label_str;

    if (label_str.length === 0) {
      return { is_valid_bool: false, reason_str: 'empty domain label' };
    }
    if (label_str.length > 63) {
      return {
        is_valid_bool: false,
        reason_str: 'domain label exceeds 63 chars'
      };
    }
    if (label_str.startsWith('-') || label_str.endsWith('-')) {
      return {
        is_valid_bool: false,
        reason_str: 'domain label must not start/end with hyphen'
      };
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
        return {
          is_valid_bool: false,
          reason_str: 'domain label contains invalid characters'
        };
      }
    }

    return { is_valid_bool: true };
  }

  private validateDomainLiteral(params: {
    domain_str: string;
  }): mailto_validation_result_t {
    const domain_str = params.domain_str;

    if (!domain_str.startsWith('[') || !domain_str.endsWith(']')) {
      return {
        is_valid_bool: false,
        reason_str: 'domain-literal must be bracketed'
      };
    }

    const inner_str = domain_str.slice(1, domain_str.length - 1);

    // Accept:
    // - IPv4 address literal: d.d.d.d
    // - IPv6 literal: IPv6:....
    if (inner_str.toLowerCase().startsWith('ipv6:')) {
      const ipv6_str = inner_str.slice(5);
      const ipv6_ok_bool = this.isIPv6Address({ ipv6_str });
      if (!ipv6_ok_bool) {
        return {
          is_valid_bool: false,
          reason_str: 'invalid IPv6 address in domain-literal'
        };
      }
      return { is_valid_bool: true };
    }

    // IPv4
    const ipv4_ok_bool = this.isIPv4Address({ ipv4_str: inner_str });
    if (!ipv4_ok_bool) {
      return {
        is_valid_bool: false,
        reason_str: 'invalid IPv4 address in domain-literal'
      };
    }

    return { is_valid_bool: true };
  }

  // -----------------------------
  // Query parsing/validation (RFC 6068-ish)
  // -----------------------------

  private validateAndParseQuery(params: {
    query_raw_str: string;
    headers_map: Map<string, string[]>;
  }): mailto_validation_result_t {
    const query_raw_str = params.query_raw_str;
    const headers_map = params.headers_map;

    if (!this.isPctEncodingWellFormed({ input_str: query_raw_str })) {
      return {
        is_valid_bool: false,
        reason_str: 'query contains malformed percent-encoding'
      };
    }

    // Split on '&' (RFC 6068: hfields separated by '&')
    const fields_arr = query_raw_str.split('&');
    if (fields_arr.length > this.max_header_count_u32) {
      return {
        is_valid_bool: false,
        reason_str: 'header field count exceeds max_header_count'
      };
    }

    for (const field_str of fields_arr) {
      if (field_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty header field' };
      }

      const eq_idx_i32 = field_str.indexOf('=');
      if (eq_idx_i32 < 0) {
        return {
          is_valid_bool: false,
          reason_str: "header field missing '=' separator"
        };
      }

      const name_raw_str = field_str.slice(0, eq_idx_i32);
      const value_raw_str = field_str.slice(eq_idx_i32 + 1);

      if (name_raw_str.length === 0) {
        return { is_valid_bool: false, reason_str: 'empty header name' };
      }

      if (name_raw_str.length > this.max_header_name_length_u32) {
        return {
          is_valid_bool: false,
          reason_str: 'header name exceeds max_header_name_length'
        };
      }

      if (value_raw_str.length > this.max_header_value_length_u32) {
        return {
          is_valid_bool: false,
          reason_str: 'header value exceeds max_header_value_length'
        };
      }

      const name_decoded_str = this.percentDecodeASCII({
        input_str: name_raw_str
      }).toLowerCase();
      const value_decoded_str = this.percentDecodeASCII({
        input_str: value_raw_str
      });

      // Disallow CR/LF and other controls in decoded values (header injection mitigation).
      if (
        this.containsASCIIControls({ input_str: name_decoded_str }) ||
        this.containsASCIIControls({ input_str: value_decoded_str })
      ) {
        return {
          is_valid_bool: false,
          reason_str: 'decoded header contains control characters'
        };
      }

      // Header name: practical token-ish validation (letters/digits/hyphen) plus optional "x-" style.
      if (!this.isHeaderNameToken({ header_name_str: name_decoded_str })) {
        return {
          is_valid_bool: false,
          reason_str: 'invalid header name syntax'
        };
      }

      if (
        !this.allow_unknown_headers_bool &&
        !this.allowed_headers_set.has(name_decoded_str)
      ) {
        return {
          is_valid_bool: false,
          reason_str: 'unknown header name not allowed'
        };
      }

      // Store
      const existing_arr = headers_map.get(name_decoded_str) ?? [];
      existing_arr.push(value_decoded_str);
      headers_map.set(name_decoded_str, existing_arr);
    }

    return { is_valid_bool: true };
  }

  private isHeaderNameToken(params: { header_name_str: string }): boolean {
    const header_name_str = params.header_name_str;

    // Very practical policy: 1+ of [A-Za-z0-9-]
    // (RFC 6068 refers to "hname" from RFC 5322; this is a conservative subset.)
    for (let i_u32 = 0; i_u32 < header_name_str.length; i_u32++) {
      const ch_str = header_name_str[i_u32];
      const code_u32 = header_name_str.charCodeAt(i_u32);

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
  // Low-level utilities
  // -----------------------------

  private isAtext_Token(params: { token_str: string }): boolean {
    // RFC 5322 atext: ALPHA / DIGIT / and these specials:
    // ! # $ % & ' * + - / = ? ^ _ ` { | } ~
    const token_str = params.token_str;
    const allowed_specials_str = "!#$%&'*+-/=?^_`{|}~";

    for (let i_u32 = 0; i_u32 < token_str.length; i_u32++) {
      const ch_str = token_str[i_u32];
      const code_u32 = token_str.charCodeAt(i_u32);

      const is_alpha_bool =
        (code_u32 >= 0x41 && code_u32 <= 0x5a) ||
        (code_u32 >= 0x61 && code_u32 <= 0x7a);
      const is_digit_bool = code_u32 >= 0x30 && code_u32 <= 0x39;

      if (
        is_alpha_bool ||
        is_digit_bool ||
        allowed_specials_str.includes(ch_str)
      ) {
        continue;
      }

      return false;
    }

    return true;
  }

  private isPctEncodingWellFormed(params: { input_str: string }): boolean {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const ch_str = input_str[i_u32];
      if (ch_str !== '%') {
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

  private percentDecodeASCII(params: { input_str: string }): string {
    // Decodes %XX into bytes mapped to codepoints 0..255.
    // Assumes percent triplets are already validated.
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

  private containsASCIIControls(params: { input_str: string }): boolean {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);
      if (code_u32 <= 0x1f || code_u32 === 0x7f) {
        return true;
      }
    }

    return false;
  }

  private containsASCIISpaceOrControls(params: { input_str: string }): boolean {
    const input_str = params.input_str;

    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      const code_u32 = input_str.charCodeAt(i_u32);
      if (code_u32 === 0x20 || code_u32 <= 0x1f || code_u32 === 0x7f) {
        return true;
      }
    }

    return false;
  }

  private countChar(params: { input_str: string; ch_str: string }): number {
    const input_str = params.input_str;
    const ch_str = params.ch_str;

    let count_u32 = 0;
    for (let i_u32 = 0; i_u32 < input_str.length; i_u32++) {
      if (input_str[i_u32] === ch_str) {
        count_u32++;
      }
    }
    return count_u32;
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
      // Disallow leading '+' or whitespace is already prevented; allow leading zeros (common).
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

    // Reject invalid characters early (only hex, ':', '.', and optionally one IPv4 tail)
    for (let i_u32 = 0; i_u32 < ipv6_str.length; i_u32++) {
      const ch_str = ipv6_str[i_u32];
      const code_u32 = ipv6_str.charCodeAt(i_u32);

      const is_colon_bool = ch_str === ':';
      const is_dot_bool = ch_str === '.';
      const isHex_bool =
        (code_u32 >= 0x30 && code_u32 <= 0x39) ||
        (code_u32 >= 0x41 && code_u32 <= 0x46) ||
        (code_u32 >= 0x61 && code_u32 <= 0x66);

      if (!(is_colon_bool || is_dot_bool || isHex_bool)) {
        return false;
      }
    }

    const has_double_colon_bool = ipv6_str.includes('::');
    if (has_double_colon_bool) {
      // Only one '::' allowed
      if (ipv6_str.indexOf('::') !== ipv6_str.lastIndexOf('::')) {
        return false;
      }
    }

    const parts_arr = ipv6_str.split(':');

    // Handle leading/trailing empty due to :: or leading/trailing colon
    // Basic sanity: no empty part unless it's from compression.
    let empty_count_u32 = 0;
    for (const p_str of parts_arr) {
      if (p_str.length === 0) {
        empty_count_u32++;
      }
    }

    if (!has_double_colon_bool) {
      // No compression => must have exactly 8 groups or 7 + IPv4 tail.
      if (parts_arr.length !== 8) {
        // allow IPv4 tail form: 6 groups + ipv4 => total 7 parts (since ipv4 contains dots)
        if (parts_arr.length !== 7) {
          return false;
        }
      }
      // also forbid any empty groups without ::
      if (empty_count_u32 !== 0) {
        return false;
      }
    } else {
      // With ::, empties are expected. But must not be just single ':' cases.
      // Eg ":" or ":::"
      if (ipv6_str === '::') {
        return true;
      }
      if (ipv6_str.startsWith(':') && !ipv6_str.startsWith('::')) {
        return false;
      }
      if (ipv6_str.endsWith(':') && !ipv6_str.endsWith('::')) {
        return false;
      }
    }

    // Validate each group
    let group_count_u32 = 0;
    for (let i_u32 = 0; i_u32 < parts_arr.length; i_u32++) {
      const group_str = parts_arr[i_u32];

      if (group_str.length === 0) {
        continue; // compression slot
      }

      // IPv4 tail?
      if (group_str.includes('.')) {
        if (i_u32 !== parts_arr.length - 1) {
          return false;
        }
        if (!this.isIPv4Address({ ipv4_str: group_str })) {
          return false;
        }
        group_count_u32 += 2; // IPv4 tail counts as 2 groups
        continue;
      }

      if (group_str.length < 1 || group_str.length > 4) {
        return false;
      }

      for (let j_u32 = 0; j_u32 < group_str.length; j_u32++) {
        if (!this.isHex({ ch_str: group_str[j_u32] })) {
          return false;
        }
      }

      group_count_u32++;
    }

    if (!has_double_colon_bool) {
      return group_count_u32 === 8;
    }

    // With compression, group_count_u32 must be < 8 (compression fills the rest)
    return group_count_u32 < 8;
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
}
