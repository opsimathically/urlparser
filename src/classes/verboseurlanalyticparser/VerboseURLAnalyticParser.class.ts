export type Url_diagnostic_issue = {
  code: string;
  message: string;
  offset: number;
  length: number;
  found?: string;
  expected?: string;
  context?: string;
  severity: 'fatal' | 'warning';
};

type Node_url_error = {
  name: string;
  message: string;
  code?: string;
};

export type Url_diagnostic_result =
  | {
      ok: true;
      url: URL;
      normalized: string;
      issues: Url_diagnostic_issue[];
    }
  | {
      ok: false;
      issues: Url_diagnostic_issue[];
      node_error?: Node_url_error;
    };

type Parser_context = {
  input: string;
  base?: string;
  issues: Url_diagnostic_issue[];
};

type Parsed_components = {
  scheme: string;
  has_authority: boolean;
  username: string;
  password: string;
  host: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
};

export class VerboseURLAnalyticParser {
  public analyzeUrl(input: string, base?: string): Url_diagnostic_result {
    let parser_context: Parser_context = { input, base, issues: [] };

    // WHATWG: strip leading/trailing C0 controls and space from input.
    // Node follows this behavior; we also report it (warning) because it matters for diagnostics.
    parser_context = this.stripC0AndSpace(parser_context);

    // Fast fatal: empty after stripping.
    if (parser_context.input.length === 0) {
      this.pushIssue(parser_context, {
        code: 'empty_input',
        message:
          'Input is empty after stripping leading/trailing C0 controls and spaces.',
        offset: 0,
        length: 0,
        severity: 'fatal'
      });
      return this.fail(parser_context, input, base);
    }

    // Detect illegal internal ASCII whitespace early (common root cause).
    // WHATWG sometimes percent-encodes in path/query; BUT in host it is forbidden and often fatal.
    // We do not immediately fail on whitespace in general; we locate it and validate by component later.
    const whitespace_offset: number = this.findAsciiWhitespace(
      parser_context.input
    );
    if (whitespace_offset !== -1) {
      this.pushIssue(parser_context, {
        code: 'ascii_whitespace_present',
        message:
          'ASCII whitespace is present in the input. This is typically not allowed in hosts and often causes parsing failure.',
        offset: whitespace_offset,
        length: 1,
        found: parser_context.input[whitespace_offset],
        severity: 'warning'
      });
    }

    // Parse with a simplified WHATWG-inspired flow:
    // 1) Determine if input is absolute (has a valid scheme), else it is relative and requires base.
    const scheme_parse = this.parseScheme(parser_context.input);

    if (!scheme_parse.has_scheme) {
      // Relative URL without a base is a primary reason Node's new URL() throws.
      if (!base) {
        this.pushIssue(parser_context, {
          code: 'relative_url_without_base',
          message: 'Relative URL provided without a base URL.',
          offset: 0,
          length: parser_context.input.length,
          severity: 'fatal',
          expected: 'An absolute URL (with scheme) or a valid base URL.'
        });
        return this.fail(parser_context, input, base);
      }

      // We still run Node oracle below; diagnostics for base validity as well.
      return this.oracleWithBase(parser_context, input, base);
    }

    // Scheme exists; validate it precisely.
    if (!scheme_parse.is_valid) {
      this.pushIssue(parser_context, {
        code: 'invalid_scheme',
        message:
          "Scheme is invalid. A scheme must start with an ASCII letter and contain only ASCII alphanumerics, '+', '-', '.'.",
        offset: scheme_parse.error_offset ?? 0,
        length: 1,
        found: scheme_parse.found,
        severity: 'fatal'
      });
      return this.fail(parser_context, input, base);
    }

    // Parse main components from the post-scheme remainder.
    const parsed_components = this.parseAfterScheme(
      parser_context,
      scheme_parse.scheme,
      scheme_parse.after_scheme_offset
    );

    // Validate according to special-scheme authority expectations (WHATWG “special schemes”).
    const is_special_scheme: boolean = this.isSpecialScheme(
      parsed_components.scheme
    );

    if (is_special_scheme) {
      // For special schemes, `//` indicates authority; absence can be allowed but commonly fails if host is required by consumer.
      // Node generally accepts e.g. "http:example.com" as path-like, but many expect "//".
      // We do not fail here, but we do validate host strongly when authority is present.
      if (parsed_components.has_authority) {
        // Host must be non-empty for http/https/ws/wss/ftp.
        if (parsed_components.host.length === 0) {
          this.pushIssue(parser_context, {
            code: 'missing_host',
            message: `Host is missing after authority marker ('//') for special scheme '${parsed_components.scheme}'.`,
            offset: scheme_parse.after_scheme_offset + 2, // approx: after "://"
            length: 0,
            severity: 'fatal'
          });
          return this.fail(parser_context, input, base);
        }

        // Forbidden host code points (WHATWG concept).
        const forbidden = this.findForbiddenHostCodePoint(
          parsed_components.host
        );
        if (forbidden) {
          this.pushIssue(parser_context, {
            code: 'forbidden_host_code_point',
            message:
              'Host contains a forbidden code point for a special-scheme URL.',
            offset: forbidden.offset,
            length: 1,
            found: forbidden.found,
            severity: 'fatal',
            context: forbidden.context
          });
          return this.fail(parser_context, input, base);
        }

        // IPv6 bracket semantics and basic validation.
        const ipv6_issue = this.validateIpv6Literal(parsed_components.host);
        if (ipv6_issue) {
          this.pushIssue(parser_context, ipv6_issue);
          return this.fail(parser_context, input, base);
        }

        // Port semantics.
        const port_issue = this.validatePort(
          parsed_components.port,
          parsed_components.scheme,
          scheme_parse.after_scheme_offset,
          parser_context.input
        );
        if (port_issue) {
          this.pushIssue(parser_context, port_issue);
          return this.fail(parser_context, input, base);
        }
      }
    } else {
      // Non-special schemes may use opaque paths; host parsing is not always required.
      // However, "scheme://" still implies authority parsing.
      if (parsed_components.has_authority) {
        const forbidden = this.findForbiddenHostCodePoint(
          parsed_components.host
        );
        if (forbidden) {
          this.pushIssue(parser_context, {
            code: 'forbidden_host_code_point',
            message: 'Host contains a forbidden code point.',
            offset: forbidden.offset,
            length: 1,
            found: forbidden.found,
            severity: 'fatal',
            context: forbidden.context
          });
          return this.fail(parser_context, input, base);
        }

        const port_issue = this.validatePort(
          parsed_components.port,
          parsed_components.scheme,
          scheme_parse.after_scheme_offset,
          parser_context.input
        );
        if (port_issue) {
          this.pushIssue(parser_context, port_issue);
          return this.fail(parser_context, input, base);
        }
      }
    }

    // Final: use Node’s URL as oracle to confirm behavior.
    return this.oracle(parser_context, input, base);
  }

  // -------------------------
  // Core WHATWG-ish steps
  // -------------------------

  private stripC0AndSpace(parser_context: Parser_context): Parser_context {
    const original_input: string = parser_context.input;

    const leading = this.countLeadingC0AndSpace(original_input);
    const trailing = this.countTrailingC0AndSpace(original_input);

    if (leading > 0 || trailing > 0) {
      this.pushIssue(parser_context, {
        code: 'stripped_c0_or_space',
        message:
          'Leading/trailing C0 control codes and/or spaces were stripped per WHATWG parsing behavior.',
        offset: 0,
        length: original_input.length,
        severity: 'warning',
        context: `leading_stripped=${leading}, trailing_stripped=${trailing}`
      });

      parser_context.input = original_input.slice(
        leading,
        original_input.length - trailing
      );
    }

    return parser_context;
  }

  private parseScheme(input: string): {
    has_scheme: boolean;
    scheme: string;
    is_valid: boolean;
    after_scheme_offset: number;
    error_offset?: number;
    found?: string;
  } {
    // Scheme ends at first ':' if present.
    const colon_index: number = input.indexOf(':');
    if (colon_index === -1) {
      return {
        has_scheme: false,
        scheme: '',
        is_valid: false,
        after_scheme_offset: 0
      };
    }

    const scheme_candidate: string = input.slice(0, colon_index);
    if (scheme_candidate.length === 0) {
      return {
        has_scheme: true,
        scheme: '',
        is_valid: false,
        after_scheme_offset: colon_index + 1,
        error_offset: 0,
        found: ':'
      };
    }

    // Must start with ASCII letter.
    const first_char: string = scheme_candidate[0];
    if (!this.isAsciiAlpha(first_char)) {
      return {
        has_scheme: true,
        scheme: scheme_candidate,
        is_valid: false,
        after_scheme_offset: colon_index + 1,
        error_offset: 0,
        found: first_char
      };
    }

    for (let i = 1; i < scheme_candidate.length; i++) {
      const ch: string = scheme_candidate[i];
      const ok: boolean =
        this.isAsciiAlpha(ch) ||
        this.isAsciiDigit(ch) ||
        ch === '+' ||
        ch === '-' ||
        ch === '.';
      if (!ok) {
        return {
          has_scheme: true,
          scheme: scheme_candidate,
          is_valid: false,
          after_scheme_offset: colon_index + 1,
          error_offset: i,
          found: ch
        };
      }
    }

    return {
      has_scheme: true,
      scheme: scheme_candidate.toLowerCase(),
      is_valid: true,
      after_scheme_offset: colon_index + 1
    };
  }

  private parseAfterScheme(
    parser_context: Parser_context,
    scheme: string,
    after_scheme_offset: number
  ): Parsed_components {
    const input: string = parser_context.input;

    // After scheme ":" we may have "//" (authority), or opaque/path.
    let cursor: number = after_scheme_offset;

    let has_authority: boolean = false;
    if (input.slice(cursor, cursor + 2) === '//') {
      has_authority = true;
      cursor += 2;
    }

    let username: string = '';
    let password: string = '';
    let host: string = '';
    let port: string = '';
    let pathname: string = '';
    let search: string = '';
    let hash: string = '';

    if (has_authority) {
      const authority_end: number = this.findFirstOf(input, cursor, [
        '/',
        '?',
        '#'
      ]);
      const authority: string =
        authority_end === -1
          ? input.slice(cursor)
          : input.slice(cursor, authority_end);

      // Split userinfo and hostport by last '@' (WHATWG userinfo handling).
      const at_index: number = authority.lastIndexOf('@');
      const hostport: string =
        at_index === -1 ? authority : authority.slice(at_index + 1);
      const userinfo: string =
        at_index === -1 ? '' : authority.slice(0, at_index);

      if (userinfo.length > 0) {
        const colon_index: number = userinfo.indexOf(':');
        if (colon_index === -1) {
          username = userinfo;
        } else {
          username = userinfo.slice(0, colon_index);
          password = userinfo.slice(colon_index + 1);
        }
      }

      // Host/port split: IPv6 literal in brackets takes precedence.
      if (hostport.startsWith('[')) {
        const rb_index: number = hostport.indexOf(']');
        host = rb_index === -1 ? hostport : hostport.slice(0, rb_index + 1);
        const rest: string =
          rb_index === -1 ? '' : hostport.slice(rb_index + 1);

        if (rest.startsWith(':')) {
          port = rest.slice(1);
        }
      } else {
        const last_colon: number = hostport.lastIndexOf(':');
        if (
          last_colon !== -1 &&
          /^[0-9]*$/.test(hostport.slice(last_colon + 1))
        ) {
          host = hostport.slice(0, last_colon);
          port = hostport.slice(last_colon + 1);
        } else {
          host = hostport;
        }
      }

      cursor = authority_end === -1 ? input.length : authority_end;
    }

    // Pathname from cursor until ? or #
    const query_index: number = input.indexOf('?', cursor);
    const hash_index: number = input.indexOf('#', cursor);

    const path_end: number = this.minPositive(
      [query_index, hash_index],
      input.length
    );
    pathname = input.slice(cursor, path_end);

    if (query_index !== -1 && (hash_index === -1 || query_index < hash_index)) {
      const query_end: number = hash_index === -1 ? input.length : hash_index;
      search = input.slice(query_index, query_end); // includes "?"
    }

    if (hash_index !== -1) {
      hash = input.slice(hash_index); // includes "#"
    }

    return {
      scheme,
      has_authority,
      username,
      password,
      host,
      port,
      pathname,
      search,
      hash
    };
  }

  // -------------------------
  // Validation helpers (WHATWG-aligned intent)
  // -------------------------

  private isSpecialScheme(scheme: string): boolean {
    // WHATWG special schemes include: ftp, file, http, https, ws, wss
    // (Others exist in implementations, but these are core.)
    const special_schemes: Set<string> = new Set([
      'ftp',
      'file',
      'http',
      'https',
      'ws',
      'wss'
    ]);
    return special_schemes.has(scheme);
  }

  private validateIpv6Literal(host: string): Url_diagnostic_issue | null {
    if (!host.startsWith('[')) return null;

    const rb_index: number = host.indexOf(']');
    if (rb_index === -1) {
      return {
        code: 'ipv6_missing_closing_bracket',
        message: "IPv6 host literal is missing a closing ']'.",
        offset: 0,
        length: host.length,
        found: host,
        severity: 'fatal'
      };
    }

    const inner: string = host.slice(1, rb_index);
    if (inner.length === 0) {
      return {
        code: 'ipv6_empty',
        message: 'IPv6 host literal is empty inside brackets.',
        offset: 0,
        length: host.length,
        found: host,
        severity: 'fatal'
      };
    }

    // Minimal IPv6 sanity: allow hex, colon, dot. Full RFC validation is more complex.
    if (!/^[0-9A-Fa-f:.]+$/.test(inner) || !inner.includes(':')) {
      return {
        code: 'ipv6_invalid_characters',
        message:
          "IPv6 host literal contains invalid characters or lacks ':' separators.",
        offset: 0,
        length: host.length,
        found: host,
        severity: 'fatal',
        context: inner
      };
    }

    return null;
  }

  private validatePort(
    port: string,
    scheme: string,
    after_scheme_offset: number,
    full_input: string
  ): Url_diagnostic_issue | null {
    if (port.length === 0) return null;

    if (!/^[0-9]+$/.test(port)) {
      // Attempt to locate in full_input for better diagnostics.
      const port_offset: number = full_input.indexOf(
        ':' + port,
        after_scheme_offset
      );
      return {
        code: 'port_non_numeric',
        message: 'Port contains non-numeric characters.',
        offset: port_offset !== -1 ? port_offset + 1 : 0,
        length: port.length,
        found: port,
        severity: 'fatal',
        expected: 'Digits only (0-9).'
      };
    }

    // Leading + is not allowed; above already disallows, but keep semantic note.
    const port_value: number = Number(port);
    if (!Number.isFinite(port_value)) {
      return {
        code: 'port_not_finite',
        message: 'Port could not be interpreted as a finite number.',
        offset: 0,
        length: port.length,
        found: port,
        severity: 'fatal'
      };
    }

    if (port_value < 0 || port_value > 65535) {
      const port_offset: number = full_input.indexOf(
        ':' + port,
        after_scheme_offset
      );
      return {
        code: 'port_out_of_range',
        message: 'Port is out of range. Valid ports are 0 through 65535.',
        offset: port_offset !== -1 ? port_offset + 1 : 0,
        length: port.length,
        found: port,
        severity: 'fatal',
        context: `scheme=${scheme}`
      };
    }

    return null;
  }

  private findForbiddenHostCodePoint(
    host: string
  ): { offset: number; found: string; context: string } | null {
    // If this is an IPv6 literal host, brackets are allowed and required.
    // We validate bracket structure elsewhere (validateIpv6Literal).
    const is_ipv6_literal: boolean = host.startsWith('[') && host.endsWith(']');

    // WHATWG “forbidden host code points” (pragmatic diagnostics):
    // - ASCII whitespace
    // - C0 controls
    // - U+0000
    // - delimiters that cannot appear in host
    //
    // IMPORTANT: '[' and ']' are allowed ONLY for bracketed IPv6 literals.
    const forbidden_set: Set<string> = new Set([
      '#',
      '/',
      ':',
      '?',
      '@',
      '\\',
      '^',
      '|'
    ]);

    for (let i = 0; i < host.length; i++) {
      const ch: string = host[i];

      if (this.isAsciiWhitespace(ch)) {
        return { offset: i, found: ch, context: 'ASCII whitespace in host' };
      }

      const code: number = ch.codePointAt(0) ?? 0;
      if (code === 0x00) {
        return { offset: i, found: ch, context: 'NUL in host' };
      }

      if (code >= 0x00 && code <= 0x1f) {
        return { offset: i, found: ch, context: 'C0 control in host' };
      }

      // Disallow brackets in non-IPv6-literal hosts.
      if (!is_ipv6_literal && (ch === '[' || ch === ']')) {
        return { offset: i, found: ch, context: 'Bracket in non-IPv6 host' };
      }

      // For an IPv6 literal host, we allow ':' and brackets and validate separately.
      if (is_ipv6_literal) {
        continue;
      }

      if (forbidden_set.has(ch)) {
        return { offset: i, found: ch, context: 'Forbidden delimiter in host' };
      }
    }

    return null;
  }

  // -------------------------
  // Node oracle (confirmation)
  // -------------------------

  private oracle(
    parser_context: Parser_context,
    original_input: string,
    base?: string
  ): Url_diagnostic_result {
    try {
      const url = base
        ? new URL(original_input, base)
        : new URL(original_input);
      return {
        ok: true,
        url,
        normalized: url.toString(),
        issues: parser_context.issues
      };
    } catch (err) {
      return this.fail(parser_context, original_input, base, err);
    }
  }

  private oracleWithBase(
    parser_context: Parser_context,
    original_input: string,
    base: string
  ): Url_diagnostic_result {
    // Validate base separately because Node can throw due to invalid base.
    try {
      // If base is invalid, this will throw.
      // We do not store it; we only want to detect and report a focused diagnostic.
      new URL(base);
    } catch (err) {
      this.pushIssue(parser_context, {
        code: 'invalid_base_url',
        message:
          'Base URL is invalid; cannot resolve a relative URL against it.',
        offset: 0,
        length: base.length,
        found: base,
        severity: 'fatal'
      });
      return this.fail(parser_context, original_input, base, err);
    }

    return this.oracle(parser_context, original_input, base);
  }

  private fail(
    parser_context: Parser_context,
    original_input: string,
    base?: string,
    err?: unknown
  ): Url_diagnostic_result {
    // Always include Node error details when available; Node typically throws TypeError with code ERR_INVALID_URL.
    let node_error: Node_url_error | undefined = undefined;
    // let node_error: Url_diagnostic_result['node_error'] | undefined = undefined;

    if (err && err instanceof Error) {
      const any_err = err as unknown as { code?: string };
      node_error = {
        name: err.name,
        message: err.message,
        code: any_err.code
      };
    } else {
      // If we did not call Node oracle (early fail), try once to capture Node behavior for alignment.
      try {
        if (base) {
          new URL(original_input, base);
        } else {
          new URL(original_input);
        }
      } catch (oracle_err) {
        if (oracle_err instanceof Error) {
          const any_err = oracle_err as unknown as { code?: string };
          node_error = {
            name: oracle_err.name,
            message: oracle_err.message,
            code: any_err.code
          };
        }
      }
    }

    // Ensure we have at least one fatal issue, even if parser_context only contains warnings.
    const has_fatal: boolean = parser_context.issues.some(
      (i) => i.severity === 'fatal'
    );
    if (!has_fatal) {
      this.pushIssue(parser_context, {
        code: 'invalid_url',
        message:
          'URL is invalid under WHATWG parsing rules as implemented by Node.',
        offset: 0,
        length: original_input.length,
        severity: 'fatal'
      });
    }

    return {
      ok: false,
      issues: parser_context.issues,
      node_error
    };
  }

  // -------------------------
  // Utility methods
  // -------------------------

  private pushIssue(
    parser_context: Parser_context,
    issue: Url_diagnostic_issue
  ): void {
    parser_context.issues.push(issue);
  }

  private countLeadingC0AndSpace(input: string): number {
    let count: number = 0;
    while (count < input.length) {
      const code: number = input.charCodeAt(count);
      if (code === 0x20 || (code >= 0x00 && code <= 0x1f)) {
        count++;
        continue;
      }
      break;
    }
    return count;
  }

  private countTrailingC0AndSpace(input: string): number {
    let count: number = 0;
    let i: number = input.length - 1;
    while (i >= 0) {
      const code: number = input.charCodeAt(i);
      if (code === 0x20 || (code >= 0x00 && code <= 0x1f)) {
        count++;
        i--;
        continue;
      }
      break;
    }
    return count;
  }

  private findAsciiWhitespace(input: string): number {
    for (let i = 0; i < input.length; i++) {
      if (this.isAsciiWhitespace(input[i])) return i;
    }
    return -1;
  }

  private isAsciiWhitespace(ch: string): boolean {
    // WHATWG defines ASCII whitespace as: TAB, LF, FF, CR, SPACE
    const code: number = ch.charCodeAt(0);
    return (
      code === 0x09 ||
      code === 0x0a ||
      code === 0x0c ||
      code === 0x0d ||
      code === 0x20
    );
  }

  private isAsciiAlpha(ch: string): boolean {
    const code: number = ch.charCodeAt(0);
    return (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
  }

  private isAsciiDigit(ch: string): boolean {
    const code: number = ch.charCodeAt(0);
    return code >= 0x30 && code <= 0x39;
  }

  private findFirstOf(input: string, start: number, chars: string[]): number {
    for (let i = start; i < input.length; i++) {
      if (chars.includes(input[i])) return i;
    }
    return -1;
  }

  private minPositive(values: number[], fallback: number): number {
    const positives: number[] = values.filter((v) => v !== -1);
    return positives.length > 0 ? Math.min(...positives) : fallback;
  }
}
