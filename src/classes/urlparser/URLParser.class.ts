import type {
  urlparse_user_and_password_info_t,
  urlparse_port_and_protocol_info_t,
  urlparse_host_info_t,
  urlparse_base_info_t,
  urlparsed_domain_result_t,
  urlparsed_resource_details_t,
  urlparsed_path_component_t,
  urlparsed_path_element_details_t,
  urlparsed_path_and_resource_info_t,
  urlparsed_indicators_t,
  urlparsed_path_t,
  urlparsed_queryparam_t,
  urlparsed_param_info_t,
  url_hash_data_t,
  unusual_url_type_t,
  data_url_info_t,
  blob_url_info_t,
  about_url_info_t,
  mailto_url_info_t,
  tel_url_info_t,
  urn_url_info_t,
  urlparsed_t
} from '@src/index';

import { isEmpty } from '../../functions/emptyvals/emptyvals';
import { VerboseURLAnalyticParser } from '../verboseurlanalyticparser/VerboseURLAnalyticParser.class';
import { parseDomain } from 'parse-domain';

import {
  extractNumericStrings,
  extractNonNumericStrings,
  extractAlphabeticStrings,
  // extractAlphabeticStringsLowercase,
  extractNonAlphanumericStrings,
  extractUniqueCharacters
} from '../../functions/extractors/extractors';

export const urlparser_tcp_ports_by_scheme: Record<string, number> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21,
  ftps: 990,
  ssh: 22,
  sftp: 22,
  telnet: 23,
  telnets: 992,
  smtp: 25,
  submission: 587,
  submissions: 465,
  imap: 143,
  imaps: 993,
  pop3: 110,
  pop3s: 995,
  ldap: 389,
  ldaps: 636,
  mqtt: 1883,
  amqp: 5672,
  amqps: 5671,
  sip: 5060,
  sips: 5061,
  rtsp: 554,
  irc: 194,
  ircs: 6697,
  xmpp: 5222,
  'xmpp-server': 5269
};

function detectUnusualUrlType(input_url: string): unusual_url_type_t {
  if (typeof input_url !== 'string') {
    return 'unknown_type';
  }

  const normalized_url = input_url.trim().toLowerCase();

  if (normalized_url.startsWith('data:')) {
    return 'data_url_type';
  }

  if (normalized_url.startsWith('blob:')) {
    return 'blob_url_type';
  }

  if (normalized_url.startsWith('about:')) {
    return 'about_url_type';
  }

  if (normalized_url.startsWith('mailto:')) {
    return 'mailto_url_type';
  }

  if (normalized_url.startsWith('tel:')) {
    return 'telephone_url_type';
  }

  if (normalized_url.startsWith('urn:')) {
    return 'urn_url_type';
  }

  return 'unknown_type';
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% URL Parser %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export class URLParser {
  private verbose_analytic_parser: VerboseURLAnalyticParser =
    new VerboseURLAnalyticParser();
  constructor() {}

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Main Parse URL %%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  public parse(url_to_parse: string): urlparsed_t | null {
    // set self ref
    const urlparser_ref = this;

    const final_urlparse_data: urlparsed_t = {
      type: 'unset',
      indicators: {}
    };

    // 1) Use built in URL parser to parse.
    let parsed_url: URL | null = null;
    try {
      // Note:
      // The url class will fail to parse for erroneous urls.  Things with bad ports, etc, will fail naturally.
      parsed_url = new URL(url_to_parse, url_to_parse);
    } catch (err: any) {
      if (err) {
        // create diagnostics
        final_urlparse_data.failed_parse_diagnostics =
          urlparser_ref.verbose_analytic_parser.analyzeUrl(
            url_to_parse,
            url_to_parse
          );

        return final_urlparse_data;
      }
    }

    if (!parsed_url || parsed_url?.hostname === '') {
      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%% Attempt To Parse Unusual Types %%%%%
      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

      const detected_unusual_type = detectUnusualUrlType(
        url_to_parse.toLowerCase()
      );
      switch (detected_unusual_type) {
        // parse as a data url
        case 'data_url_type':
          final_urlparse_data.type = 'data';
          final_urlparse_data.data_url_info =
            urlparser_ref.parseDataURL(url_to_parse);
          if (!final_urlparse_data.data_url_info) return null;
          return final_urlparse_data;

        // parse as a blob url
        case 'blob_url_type':
          final_urlparse_data.type = 'blob';
          final_urlparse_data.blob_url_info =
            urlparser_ref.parseBlobURL(url_to_parse);
          if (!final_urlparse_data.blob_url_info) return null;
          return final_urlparse_data;

        case 'about_url_type':
          final_urlparse_data.type = 'about';
          final_urlparse_data.about_url_info =
            urlparser_ref.parseAboutURL(url_to_parse);
          if (!final_urlparse_data.about_url_info) return null;
          return final_urlparse_data;

        case 'mailto_url_type':
          final_urlparse_data.type = 'mailto';
          final_urlparse_data.mailto_url_info =
            urlparser_ref.parseMailtoURL(url_to_parse);
          if (!final_urlparse_data.mailto_url_info) return null;
          return final_urlparse_data;

        case 'telephone_url_type':
          final_urlparse_data.type = 'telephone';
          final_urlparse_data.tel_url_info =
            urlparser_ref.parseTelephoneURL(url_to_parse);
          if (!final_urlparse_data.tel_url_info) return null;
          return final_urlparse_data;

        case 'urn_url_type':
          final_urlparse_data.type = 'urn';
          final_urlparse_data.urn_url_info =
            urlparser_ref.parseURNURL(url_to_parse);
          if (!final_urlparse_data.urn_url_info) return null;
          return final_urlparse_data;

        // unknown types return null
        case 'unknown_type':
        default:
          break;
      }

      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%% Fail If Wasn't Unusual Type %%%%%%%%
      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

      final_urlparse_data.indicators.has_failures = true;
      return final_urlparse_data;
    }

    // things like mailto: will give a parsed_url, but won't have a hostname
    // if we got this far we know we got problems
    if (parsed_url.hostname === '') return null;

    if (url_to_parse.toLowerCase().indexOf('mailto') === 0) debugger;
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Parse Typical URLs %%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    //
    final_urlparse_data.scheme_and_port_info =
      urlparser_ref.parseSchemeAndPortInfo({
        url: parsed_url,
        parse_data: final_urlparse_data
      });

    final_urlparse_data.user_and_password_info =
      urlparser_ref.parseUserAndPasswordInfo({
        url: parsed_url,
        parse_data: final_urlparse_data
      });

    final_urlparse_data.host_info = urlparser_ref.parseHostInfo({
      url: parsed_url,
      parse_data: final_urlparse_data
    });

    final_urlparse_data.base_info = urlparser_ref.parseBaseInfo({
      original_url_string: url_to_parse,
      url: parsed_url,
      parse_data: final_urlparse_data
    });

    final_urlparse_data.path_and_resource_info =
      urlparser_ref.parsePathAndResourceInfo({
        url: parsed_url,
        parse_data: final_urlparse_data
      });

    final_urlparse_data.parameter_info = urlparser_ref.parseParams({
      url: parsed_url,
      parse_data: final_urlparse_data
    });

    final_urlparse_data.hash_info = urlparser_ref.parseURLHashData({
      url: parsed_url,
      parse_data: final_urlparse_data
    });

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Process and Set Indicators %%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // Indicators are used to provide simple flags which can be searched for
    // in database queries.  The point is to reduce query complexity, reduce
    // pipeline requirements, and simply do some work in advance so that later
    // data lookups are more natural and less investigatory.
    final_urlparse_data.indicators =
      urlparser_ref.processParseDataAndSetIndicators({
        parse_data: final_urlparse_data
      });

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Process and Calculate Hashes %%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // Hash Sets are used for quick lookups of potential data.  If you're looking
    // for a URL in the database that contains exact data in an exact position, a hash
    // lookup is often an easier/faster solution than a complex query.

    debugger;
    return final_urlparse_data;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Internal Private Methods %%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Data URL Parsing %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  parseDataURL(input_url: string): data_url_info_t | null {
    if (typeof input_url !== 'string') return null;

    const trimmed_url = input_url.trim();

    // Scheme check (case-insensitive) without attempting full URL parsing
    if (
      trimmed_url.length < 5 ||
      trimmed_url.slice(0, 5).toLowerCase() !== 'data:'
    ) {
      return null;
    }

    // RFC2397: data:[<mediatype>][;base64],<data>
    // The first comma separates metadata from data payload.
    const comma_index = trimmed_url.indexOf(',');
    if (comma_index === -1) {
      return null; // not a valid data URL (must have comma delimiter)
    }

    const metadata = trimmed_url.slice(5, comma_index); // after "data:" up to comma
    const data = trimmed_url.slice(comma_index + 1); // after comma to end

    // Defaults per RFC2397 if mediatype is omitted
    let media_type = 'text/plain';
    let charset: string | null = 'US-ASCII';
    let is_base64 = false;

    // Empty metadata means default mediatype/charset, no base64
    if (metadata.length > 0) {
      const metadata_parts = metadata.split(';');

      // If the first part contains "/" it's a mediatype; otherwise mediatype is omitted.
      const first_part = metadata_parts[0];
      let start_index = 0;

      if (first_part.includes('/')) {
        media_type = first_part.toLowerCase();
        charset = null; // charset only set if explicitly provided when mediatype is present
        start_index = 1;
      } else {
        // mediatype omitted: keep defaults (text/plain; US-ASCII) unless overridden by charset
        start_index = 0;
      }

      for (let i = start_index; i < metadata_parts.length; i++) {
        const part = metadata_parts[i].trim();
        if (!part) continue;

        if (part.toLowerCase() === 'base64') {
          is_base64 = true;
          continue;
        }

        // charset=...
        if (part.toLowerCase().startsWith('charset=')) {
          const charset_value = part.slice('charset='.length).trim();
          charset = charset_value.length > 0 ? charset_value : null;
          continue;
        }

        // Other parameters exist in the wild; ignore them but keep parser resilient.
      }

      // If mediatype was present but charset was never specified, leave as null
      // (caller can interpret null as "unspecified").
      // If mediatype was omitted, charset default remains US-ASCII unless overridden.
    }

    return {
      scheme: 'data',
      media_type: media_type,
      charset: charset,
      is_base64: is_base64,
      data: data,
      metadata: metadata
    };
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Blob URLs %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  parseBlobURL(input_url: string): blob_url_info_t | null {
    if (typeof input_url !== 'string') return null;

    const raw = input_url.trim();
    if (raw.length < 5) return null;

    // Case-insensitive scheme check
    if (raw.slice(0, 5).toLowerCase() !== 'blob:') return null;

    const remainder = raw.slice(5); // everything after "blob:"
    if (remainder.length === 0) return null;

    // Separate off fragment and query from the remainder (do not decode)
    let main_part = remainder;
    let fragment: string | null = null;
    let query: string | null = null;

    const hash_index = main_part.indexOf('#');
    if (hash_index !== -1) {
      fragment = main_part.slice(hash_index + 1);
      main_part = main_part.slice(0, hash_index);
    }

    const question_index = main_part.indexOf('?');
    if (question_index !== -1) {
      query = main_part.slice(question_index + 1);
      main_part = main_part.slice(0, question_index);
    }

    // Expected high-level shape: <origin>/<uuid>
    // Use *last* "/" to be resilient if origin ever contains "/"
    const last_slash_index = main_part.lastIndexOf('/');
    if (last_slash_index === -1) return null;

    const origin = main_part.slice(0, last_slash_index);
    const uuid = main_part.slice(last_slash_index + 1);

    if (origin.length === 0 || uuid.length === 0) return null;

    return {
      scheme: 'blob',
      origin: origin,
      uuid: uuid,
      query: query,
      fragment: fragment,
      raw: raw
    };
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% About URL Parsing %%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  parseAboutURL(input_url: string): about_url_info_t | null {
    if (typeof input_url !== 'string') return null;

    const raw = input_url.trim();
    if (raw.length < 6) return null;

    // Case-insensitive scheme check
    if (raw.slice(0, 6).toLowerCase() !== 'about:') {
      return null;
    }

    let remainder = raw.slice(6); // everything after "about:"
    let fragment: string | null = null;
    let query: string | null = null;

    // Extract fragment first
    const hash_index = remainder.indexOf('#');
    if (hash_index !== -1) {
      fragment = remainder.slice(hash_index + 1);
      remainder = remainder.slice(0, hash_index);
    }

    // Extract query
    const question_index = remainder.indexOf('?');
    if (question_index !== -1) {
      query = remainder.slice(question_index + 1);
      remainder = remainder.slice(0, question_index);
    }

    // What remains is the identifier (may be empty)
    const identifier = remainder;

    return {
      scheme: 'about',
      identifier: identifier,
      query: query,
      fragment: fragment,
      raw: raw
    };
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Mailto URLs %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  parseMailtoURL(input_url: string): mailto_url_info_t | null {
    if (typeof input_url !== 'string') return null;

    const raw = input_url.trim();
    if (raw.length < 7) return null;

    // Case-insensitive scheme check
    if (raw.slice(0, 7).toLowerCase() !== 'mailto:') return null;

    // Split off fragment first (common in copied URLs, even if not semantically meaningful for mailto)
    const hash_index = raw.indexOf('#');
    const raw_without_fragment =
      hash_index === -1 ? raw : raw.slice(0, hash_index);
    const fragment = hash_index === -1 ? null : raw.slice(hash_index + 1);

    const remainder = raw_without_fragment.slice(7); // everything after "mailto:"

    // Split once on "?" to separate recipients from query
    const question_index = remainder.indexOf('?');
    const to_part =
      question_index === -1 ? remainder : remainder.slice(0, question_index);
    const query_part =
      question_index === -1 ? '' : remainder.slice(question_index + 1);

    // Recipients in the path: RFC-style comma-separated; semicolons appear in practice.
    // Keep raw tokens; drop empties.
    const to = to_part
      .split(/[;,]/g)
      .map((token) => token.trim())
      .filter((token) => token.length > 0);

    // Parse query string into multi-map WITHOUT decoding.
    // We tolerate both "&" and ";" separators between pairs.
    const raw_query_params: Record<string, string[]> = {};

    if (query_part.length > 0) {
      const pairs = query_part.split(/[&;]/g);

      for (const pair of pairs) {
        if (!pair) continue;

        const equals_index = pair.indexOf('=');
        const raw_key = (
          equals_index === -1 ? pair : pair.slice(0, equals_index)
        ).trim();
        const raw_value =
          equals_index === -1 ? '' : pair.slice(equals_index + 1);

        // Skip empty keys like "?=value"
        if (!raw_key) continue;

        if (!raw_query_params[raw_key]) {
          raw_query_params[raw_key] = [];
        }
        raw_query_params[raw_key].push(raw_value);
      }
    }

    // Helpers: collect + split address lists from query params like cc/bcc
    const split_address_list = (values: string[]): string[] => {
      // Do not decode; just split on commas/semicolons and trim.
      // Preserve "opaque" tokens like `"Support Team" <support@example.com>` if they appear unencoded.
      const results: string[] = [];

      for (const value of values) {
        const tokens = value
          .split(/[;,]/g)
          .map((t) => t.trim())
          .filter((t) => t.length > 0);

        results.push(...tokens);
      }

      return results;
    };

    const get_values_case_insensitive = (param_name: string): string[] => {
      const matches: string[] = [];
      const target = param_name.toLowerCase();

      for (const key of Object.keys(raw_query_params)) {
        if (key.toLowerCase() === target) {
          matches.push(...raw_query_params[key]);
        }
      }

      return matches;
    };

    const cc_values = get_values_case_insensitive('cc');
    const bcc_values = get_values_case_insensitive('bcc');
    const subject_values = get_values_case_insensitive('subject');
    const body_values = get_values_case_insensitive('body');

    const cc = split_address_list(cc_values);
    const bcc = split_address_list(bcc_values);

    // Everything else goes into other_query_params (excluding cc/bcc/subject/body, case-insensitive)
    const other_query_params: Record<string, string[]> = {};
    const excluded_keys = new Set(['cc', 'bcc', 'subject', 'body']);

    for (const key of Object.keys(raw_query_params)) {
      if (excluded_keys.has(key.toLowerCase())) continue;
      other_query_params[key] = raw_query_params[key];
    }

    return {
      scheme: 'mailto',
      raw: raw,
      fragment: fragment,
      to: to,
      cc: cc,
      bcc: bcc,
      subject: subject_values,
      body: body_values,
      other_query_params: other_query_params
    };
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Telephone URLs %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  parseTelephoneURL(input_url: string): tel_url_info_t | null {
    if (typeof input_url !== 'string') return null;

    const raw = input_url.trim();
    if (raw.length < 4) return null;

    // Case-insensitive scheme check
    if (raw.slice(0, 4).toLowerCase() !== 'tel:') return null;

    let remainder = raw.slice(4); // everything after "tel:"

    // Split off query if present (rare, but tolerated)
    const question_index = remainder.indexOf('?');
    if (question_index !== -1) {
      remainder = remainder.slice(0, question_index);
    }

    // Split phone number from parameters (semicolon-delimited)
    const parts = remainder.split(';');
    const phone_number = parts[0] ?? '';

    const parameters: Record<string, string[]> = {};

    for (let i = 1; i < parts.length; i++) {
      const part = parts[i].trim();
      if (!part) continue;

      const equals_index = part.indexOf('=');
      const key = equals_index === -1 ? part : part.slice(0, equals_index);
      const value = equals_index === -1 ? '' : part.slice(equals_index + 1);

      if (!parameters[key]) {
        parameters[key] = [];
      }
      parameters[key].push(value);
    }

    return {
      scheme: 'tel',
      phone_number: phone_number,
      parameters: parameters,
      raw: raw
    };
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Parse URN URLs %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  parseURNURL(input_url: string): urn_url_info_t | null {
    if (typeof input_url !== 'string') return null;

    const raw = input_url.trim();
    if (raw.length < 4) return null;

    // Case-insensitive scheme check
    if (raw.slice(0, 4).toLowerCase() !== 'urn:') return null;

    let remainder = raw.slice(4); // everything after "urn:"
    if (remainder.length === 0) return null;

    // Extract fragment first
    let fragment: string | null = null;
    const hash_index = remainder.indexOf('#');
    if (hash_index !== -1) {
      fragment = remainder.slice(hash_index + 1);
      remainder = remainder.slice(0, hash_index);
    }

    // Extract query
    let query: string | null = null;
    const question_index = remainder.indexOf('?');
    if (question_index !== -1) {
      query = remainder.slice(question_index + 1);
      remainder = remainder.slice(0, question_index);
    }

    // Now remainder should be "<nid>:<nss>" (nss may contain additional colons)
    const first_colon_index = remainder.indexOf(':');
    if (first_colon_index === -1) {
      return null; // no nid/nss separator
    }

    const nid = remainder.slice(0, first_colon_index);
    const nss = remainder.slice(first_colon_index + 1);

    if (nid.length === 0 || nss.length === 0) return null;

    return {
      scheme: 'urn',
      nid,
      nss,
      query,
      fragment,
      raw
    };
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% URL Parsing %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  private processParseDataAndSetIndicators(params: {
    parse_data: urlparsed_t;
  }): urlparsed_indicators_t {
    const { parse_data } = params;
    const indicators: any = {} as any;

    /*
    export type urlparsed_t = {
      scheme_and_port_info?: urlparse_port_and_protocol_info_t | null;
      user_and_password_info?: urlparse_user_and_password_info_t | null;
      host_info?: urlparse_host_info_t | null;
      base_info?: urlparse_base_info_t | null;
      path_and_resource_info?: urlparsed_path_and_resource_info_t | null;
      parameter_info?: urlparsed_param_info_t | null;
      hash_info?: url_hash_data_t | null;
      failed_parse_diagnostics?: url_diagnostic_result_t | null;
      indicators: any;
    };
    */

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Scheme And Port Indicators %%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    if (parse_data.scheme_and_port_info) {
      const protocol = parse_data.scheme_and_port_info.protocol;
      const port = parse_data.scheme_and_port_info.port;
      const protocol_std_port =
        parse_data.scheme_and_port_info.protocol_std_port;

      /*
      export type urlparse_port_and_protocol_info_t = {
        scheme: string;
        protocol: string;
        port: number;
        protocol_std_port: number;
      };
      */
      if (port !== protocol_std_port)
        indicators.is_nonstandard_protocol_port = true;
      else indicators.is_standard_protocol_port = true;

      // check websocket
      if (['ws', 'wss'].includes(protocol)) {
        indicators.is_websocket = true;
      }

      // check http/https
      if (['http', 'https'].includes(protocol)) {
        indicators.is_webtarget = true;
      }

      // check if it's not a websocket, or not a http protocol
      if (!['http', 'https', 'ws', 'wss'].includes(protocol)) {
        indicators.is_atypical_web_protocol = true;
      }

      if (protocol === 'file') indicators.is_file_protocol = true;
    }

    debugger;
    return indicators;
  }

  private parseURLHashData(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): url_hash_data_t {
    const { url /*, parse_data*/ } = params;
    const url_hash_data: url_hash_data_t = {
      hash: null,
      hash_lowercase: null
    };

    if (url.hash) {
      url_hash_data.hash = url.hash;
      url_hash_data.hash_lowercase = url.hash.toLowerCase();
    }

    return url_hash_data;
  }

  private parseHostInfo(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): urlparse_host_info_t {
    const { url, parse_data } = params;
    const host_info: urlparse_host_info_t = {
      host: '',
      host_with_protocol: '',
      host_lowercase: '',
      host_with_protocol_lowercase: '',
      domain: null,
      domain_with_tld: null,
      domain_with_subdomains_and_tld: null,
      top_level_domain: null,
      subdomains: null,
      host_domain_information_parsed: null
    };

    host_info.host = url.hostname;
    host_info.host_with_protocol =
      parse_data.scheme_and_port_info?.protocol + '://' + url.hostname;

    host_info.host_lowercase = host_info.host.toLowerCase();
    host_info.host_with_protocol_lowercase =
      host_info.host_with_protocol.toLowerCase();

    // create a dummy object which will hold assignments from the
    // parse-domain library.
    const urlparsed_domain: urlparsed_domain_result_t = {
      type: 'INVALID',
      hostname: 'INVALID',
      errors: [],
      labels: [],
      subdomains: [],
      domain: 'INVALID',
      top_level_domains: [],
      icann: {
        subdomains: [],
        domain: 'INVALID',
        top_level_domains: []
      }
    };

    // Note: we type to 'any' here so we can assign to our internal type.  This is
    // done so zod validators can work as desired.  We don't just do an Object.assign
    // because we want all properties on the object to be set for later database insertion.
    const parsed_domain = parseDomain(host_info.host_lowercase) as any;
    if (parsed_domain) {
      if (parsed_domain.type) {
        urlparsed_domain.type = parsed_domain.type;
      }
      if (parsed_domain.hostname) {
        urlparsed_domain.hostname = parsed_domain.hostname;
      }
      if (parsed_domain.errors) {
        urlparsed_domain.errors = parsed_domain.errors;
      }
      if (parsed_domain.labels) {
        urlparsed_domain.labels = parsed_domain.labels;
      }
      if (parsed_domain.subDomains) {
        urlparsed_domain.subdomains = parsed_domain.subDomains;
      }
      if (parsed_domain.domain) {
        urlparsed_domain.domain = parsed_domain.domain;
      }
      if (parsed_domain.topLevelDomains) {
        urlparsed_domain.top_level_domains = parsed_domain.topLevelDomains;
      }
      if (parsed_domain.icann.subDomains) {
        urlparsed_domain.icann.subdomains = parsed_domain.icann.subDomains;
      }
      if (parsed_domain.icann.domain) {
        urlparsed_domain.icann.domain = parsed_domain.icann.domain;
      }
      if (parsed_domain.icann.topLevelDomains) {
        urlparsed_domain.icann.top_level_domains =
          parsed_domain.icann.topLevelDomains;
      }
    }

    // only set parse result if we have one
    if (parsed_domain) {
      host_info.host_domain_information_parsed = urlparsed_domain;

      if (urlparsed_domain.domain) host_info.domain = urlparsed_domain.domain;

      if (urlparsed_domain.top_level_domains) {
        if (urlparsed_domain.top_level_domains.length) {
          host_info.top_level_domain =
            urlparsed_domain.top_level_domains.join('.');
        }
      }

      if (urlparsed_domain.subdomains) {
        if (urlparsed_domain.subdomains.length) {
          host_info.subdomains = urlparsed_domain.subdomains.join('.');
        }
      }
    }

    if (host_info.domain) {
      // domain + top_level_domain
      if (host_info.top_level_domain && host_info.top_level_domain) {
        host_info.domain_with_tld =
          host_info.domain + '.' + host_info.top_level_domain;
      }

      // subdomain + domain + top_level_domain
      if (
        host_info.subdomains &&
        host_info.top_level_domain &&
        host_info.top_level_domain
      ) {
        host_info.domain_with_subdomains_and_tld =
          host_info.subdomains +
          '.' +
          host_info.domain +
          '.' +
          host_info.top_level_domain;
      }
    }

    return host_info;
  }

  private parseUserAndPasswordInfo(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): urlparse_user_and_password_info_t {
    const { url } = params;

    const user_and_password_info: urlparse_user_and_password_info_t = {
      username: null,
      username_lowercase: null,
      password: null,
      password_lowercase: null
    };

    if (!isEmpty(url.username)) {
      user_and_password_info.username = url.username;
      user_and_password_info.username_lowercase = url.username.toLowerCase();
    }
    if (!isEmpty(url.password)) {
      user_and_password_info.password = url.password;
      user_and_password_info.password_lowercase = url.password.toLowerCase();
    }

    return user_and_password_info;
  }

  private parseSchemeAndPortInfo(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): urlparse_port_and_protocol_info_t {
    const { url, parse_data } = params;

    const port_and_proto_info: urlparse_port_and_protocol_info_t = {
      port: -1,
      scheme: '',
      protocol: '',
      protocol_std_port: -1
    };

    // check port
    let port_parsed_from_string = -1;
    if (typeof url.port === 'string') {
      if (url.port !== '') port_parsed_from_string = parseInt(url.port);
    }

    // create normalized protocol string
    let protocol = url.protocol.endsWith(':')
      ? url.protocol.slice(0, -1)
      : url.protocol;
    protocol = protocol.toLowerCase();

    // check for common protocols
    if (!['http', 'https'].includes(protocol))
      parse_data.indicators.is_not_http_or_https = true;
    if (['ws', 'wss'].includes(protocol))
      parse_data.indicators.is_websocket = true;

    // set scheme
    port_and_proto_info.scheme = protocol + '://';

    // parsed_url.protocol
    const protocol_std_port = urlparser_tcp_ports_by_scheme[protocol];
    if (protocol_std_port) {
      port_and_proto_info.protocol_std_port = protocol_std_port;
    }

    // set non-standard port indicator
    if (
      port_parsed_from_string !== -1 &&
      protocol_std_port !== port_parsed_from_string
    ) {
      parse_data.indicators.has_nonstandard_protocol_port = true;
    }

    // set port resolved port
    if (protocol_std_port && port_parsed_from_string === -1)
      port_and_proto_info.port = protocol_std_port;
    else port_and_proto_info.port = port_parsed_from_string;

    // set protocol
    port_and_proto_info.protocol = protocol;

    // return port and protocol information
    return port_and_proto_info;
  }

  private parseBaseInfo(params: {
    original_url_string: string;
    url: URL;
    parse_data: urlparsed_t;
  }): urlparse_base_info_t {
    const { url, parse_data } = params;

    let url_base: string | null = null;

    const base_info: urlparse_base_info_t = {
      base: '',
      base_lowercase: '',
      base_without_port_lowercase: '',
      base_without_port: ''
    };

    // create base uri
    if (isEmpty(url.pathname) === true) {
      url_base = params.original_url_string;
    } else {
      url_base = params.original_url_string.slice(
        0,
        params.original_url_string.indexOf(url.pathname)
      );
    }

    // original_url_string
    base_info.base = url_base;
    base_info.base_lowercase = url_base.toLowerCase();

    // generate base without port
    if (parse_data.scheme_and_port_info) {
      // calculate base without port
      if (base_info.base.endsWith(`:${parse_data.scheme_and_port_info.port}`)) {
        base_info.base_without_port = base_info.base.substring(
          0,
          base_info.base.length -
            `:${parse_data.scheme_and_port_info.port}`.length
        );
        base_info.base_without_port_lowercase =
          base_info.base_without_port.toLowerCase();
      }
    }

    return base_info;
  }

  parsePathAndResourceInfo(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): urlparsed_path_and_resource_info_t | null {
    const { url } = params;

    // ensure we have a path
    if (typeof url.pathname !== 'string') return null;
    if (url.pathname.length <= 0) return null;

    // create initial empty structure
    const pathinfo: urlparsed_path_and_resource_info_t = {
      resource_str: '',
      resource_str_lowercase: '',
      resource_str_length: 0,
      pathname: '',
      pathname_lowercase: '',
      pathname_normalized: '',
      pathname_normalized_lowercase: '',
      pathname_length: 0,

      // path parts and components
      path_parsed: null,
      path_parsed_collapsed: null,
      path_parsed_collapsed_lowercase: null
    };

    const collapseEmptyPathSegments = function (path: string): string {
      if (path === '') {
        return path;
      }
      const collapsed = path.replace(/\/{2,}/g, '/');
      return collapsed;
    };

    const parseResourceDetails = function (
      resource: string
    ): urlparsed_resource_details_t {
      const resource_parsed: urlparsed_resource_details_t = {
        resource: null,
        extension: null,
        parts: [],
        is_hidden_file: false,
        name: null,
        resource_unique_chars: []
      };

      if (!resource) return resource_parsed;
      if (!resource.length) return resource_parsed;

      // set resource and name
      resource_parsed.resource = resource;
      resource_parsed.name = resource;

      // extract unique charas
      resource_parsed.resource_unique_chars = extractUniqueCharacters(resource);

      // No dots at all → no extension
      if (!resource.includes('.')) {
        resource_parsed.parts.push(resource);
        return resource_parsed;
      }

      // Dotfile with no basename (e.g., ".env")
      if (resource.startsWith('.') && resource.indexOf('.', 1) === -1) {
        resource_parsed.is_hidden_file = true;
        resource_parsed.name = resource.replaceAll('.', '');
        resource_parsed.parts.push(resource_parsed.name);
        return resource_parsed;
      }

      // split the parts
      const parts = resource.split('.');
      resource_parsed.parts = parts;

      // Single extension (foo.txt)
      if (parts.length === 2) {
        resource_parsed.name = parts[0];
        resource_parsed.extension = parts[1];
        return resource_parsed;
      }

      resource_parsed.name = parts[0];
      resource_parsed.extension = parts.slice(1).join('.');

      // return the resource parsed
      return resource_parsed;
    };

    // this will perform the majority of parsing
    const parsePathAndResource = function (raw_path: string): urlparsed_path_t {
      const parsed_path: urlparsed_path_t = {
        path: [],
        path_sorted: [],
        path_str: null,
        path_str_unique_chars: [],
        resource: null,
        resource_details: {
          resource: '',
          name: '',
          extension: '',
          parts: [],
          is_hidden_file: false,
          resource_unique_chars: []
        },
        resource_details_lowercase: {
          resource: '',
          name: '',
          extension: '',
          parts: [],
          is_hidden_file: false,
          resource_unique_chars: []
        },
        path_elem_details: []
      };

      if (!raw_path) {
        return parsed_path;
      }

      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%% Basic Parsing %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

      // Normalize multiple slashes
      const normalized = raw_path.replace(/\/+/g, '/');

      // Detect whether the path ends with a slash (root-style path)
      const ends_with_slash = normalized.endsWith('/');

      // Remove leading slash only; preserve trailing semantics
      const trimmed = normalized.replace(/^\/+/, '').replace(/\/+$/, '');

      // if it's an empty string, just set the resource and return the empty object
      if (trimmed === '') {
        parsed_path.resource = '/';
        return parsed_path;
      }

      const segments = trimmed.split('/');

      if (ends_with_slash) {
        // Entire thing is path; resource is "/"
        parsed_path.path = segments;
        parsed_path.resource = '';
      } else {
        // Last segment is the resource
        parsed_path.resource = segments.pop() ?? null;
        parsed_path.path = segments;
      }

      // gather path string and gather unique chars
      // parsed_path.path = path;
      parsed_path.path_str =
        parsed_path.path.length > 0 ? parsed_path.path.join('/') : null;
      parsed_path.path_sorted =
        parsed_path.path.length > 0
          ? parsed_path.path.toSorted()
          : parsed_path.path;

      if (parsed_path.path_str) {
        parsed_path.path_str_unique_chars = extractUniqueCharacters(
          parsed_path.path_str
        );
      }

      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%% Parse Resource/Details %%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

      if (parsed_path.resource) {
        if (parsed_path.resource.length) {
          parsed_path.resource_details = parseResourceDetails(
            parsed_path.resource
          );
          parsed_path.resource_details_lowercase = parseResourceDetails(
            parsed_path.resource.toLowerCase()
          );
        }
      }

      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
      // %%% Parse Out Individual Path Details %%%%%%%%%%%%%%
      // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

      function stringArrayToPathComponents(
        str_arr: string[]
      ): urlparsed_path_component_t[] | null {
        if (!str_arr) return null;

        const path_components: Array<urlparsed_path_component_t> = [];

        for (let idx = 0; idx < str_arr.length; idx++) {
          const str = str_arr[idx];
          if (typeof str === 'string') {
            const path_component: urlparsed_path_component_t = {
              idx: idx,
              content: str,
              length: str.length,
              char_set: extractUniqueCharacters(str)
            };
            path_components.push(path_component);
          }
        }

        return path_components;
      }

      // create detail set
      const path_elem_details: Array<urlparsed_path_element_details_t> =
        new Array<urlparsed_path_element_details_t>();

      // iterate through paths
      if (parsed_path.path.length) {
        for (let idx = 0; idx < parsed_path.path.length; idx++) {
          const path_elem = parsed_path.path[idx];
          const path_details: urlparsed_path_element_details_t = {
            // path verbatim
            idx: idx,
            path_elem: path_elem,
            length: path_elem.length,

            // numerics
            numeric: [],
            numeric_unique: [],

            // non-numerics
            non_numeric: [],
            non_numeric_unique: [],

            // non-numeric/non-alphabetic (symbols)
            non_alpha_non_numeric: [],

            // alphabetic
            alphabetic: [],
            alphabetic_unique: [],

            // nonalphanumeric (symbols)
            nonalphanumeric: [],
            nonalphanumeric_unique: []
          };

          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%% Numerics %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

          // extract numerics
          const extracted_numerics_from_path = extractNumericStrings(path_elem);
          if (extracted_numerics_from_path) {
            // non-unique numerics
            const numeric = stringArrayToPathComponents(
              extracted_numerics_from_path
            );
            if (numeric) path_details.numeric = numeric;

            // unique numerics
            const numeric_path_set = new Set<string>();
            for (const elem of extracted_numerics_from_path) {
              numeric_path_set.add(elem);
            }
            const extracted_numeric_unique = [...numeric_path_set];
            const numeric_unique = stringArrayToPathComponents(
              extracted_numeric_unique
            );
            if (numeric_unique) path_details.numeric_unique = numeric_unique;
          }

          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%% Non-Numerics %%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

          // extract non-numerics
          const extracted_non_numerics_from_path =
            extractNonNumericStrings(path_elem);
          if (extracted_non_numerics_from_path) {
            const non_numeric = stringArrayToPathComponents(
              extracted_non_numerics_from_path
            );
            if (non_numeric) path_details.non_numeric = non_numeric;

            // unique non-numerics
            const non_numeric_path_set = new Set<string>();
            for (const elem of extracted_non_numerics_from_path) {
              non_numeric_path_set.add(elem);
            }
            const extracted_non_numeric_unique = [...non_numeric_path_set];
            const non_numeric_unique = stringArrayToPathComponents(
              extracted_non_numeric_unique
            );
            if (non_numeric_unique)
              path_details.non_numeric_unique = non_numeric_unique;
          }

          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%% Alphabetic %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

          // extract alphabetic
          const extracted_alphabetic_from_path =
            extractAlphabeticStrings(path_elem);
          if (extracted_alphabetic_from_path) {
            const alphabetic = stringArrayToPathComponents(
              extracted_alphabetic_from_path
            );
            if (alphabetic) path_details.alphabetic = alphabetic;

            // unique alphabetic
            const alphabetic_path_set = new Set<string>();
            for (const elem of extracted_alphabetic_from_path) {
              alphabetic_path_set.add(elem);
            }
            const extracted_alphabetic_unique = [...alphabetic_path_set];
            const alphabetic_unique = stringArrayToPathComponents(
              extracted_alphabetic_unique
            );
            if (alphabetic_unique)
              path_details.alphabetic_unique = alphabetic_unique;
          }

          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%% Symbols %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
          // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

          // extract alphabetic
          const extracted_nonalphanumeric_from_path =
            extractNonAlphanumericStrings(path_elem);
          if (extracted_nonalphanumeric_from_path) {
            const nonalphanumeric = stringArrayToPathComponents(
              extracted_nonalphanumeric_from_path
            );
            if (nonalphanumeric) path_details.nonalphanumeric = nonalphanumeric;

            // unique alphabetic
            const nonalphanumeric_path_set = new Set<string>();
            for (const elem of extracted_nonalphanumeric_from_path) {
              nonalphanumeric_path_set.add(elem);
            }
            const extracted_nonalphanumeric = [...nonalphanumeric_path_set];
            const nonalphanumeric_unique = stringArrayToPathComponents(
              extracted_nonalphanumeric
            );
            if (nonalphanumeric_unique)
              path_details.nonalphanumeric_unique = nonalphanumeric_unique;
          }

          path_elem_details.push(path_details);
        }
      }

      parsed_path.path_elem_details = path_elem_details;

      // return the parsed path
      return parsed_path;
    };

    // gather pathname/collapsed
    const pathname = url.pathname;
    const pathname_with_collapsed_empty_segments = collapseEmptyPathSegments(
      url.pathname
    );

    // set pathinfo members
    pathinfo.pathname = pathname;
    pathinfo.pathname_lowercase = pathname.toLowerCase();
    pathinfo.pathname_normalized = collapseEmptyPathSegments(pathinfo.pathname);
    pathinfo.pathname_normalized_lowercase = collapseEmptyPathSegments(
      pathinfo.pathname.toLowerCase()
    );
    pathinfo.pathname_length = pathname.length;

    // perform actual path parsing
    const path_array_and_resource = parsePathAndResource(pathname);
    const path_array_and_resource_with_collapsed_empty_segments =
      parsePathAndResource(pathname_with_collapsed_empty_segments);
    const path_array_and_resource_with_collapsed_empty_segments_lowercase =
      parsePathAndResource(
        pathname_with_collapsed_empty_segments.toLowerCase()
      );

    pathinfo.path_parsed = path_array_and_resource;
    pathinfo.path_parsed_collapsed =
      path_array_and_resource_with_collapsed_empty_segments;
    pathinfo.path_parsed_collapsed_lowercase =
      path_array_and_resource_with_collapsed_empty_segments_lowercase;

    pathinfo.resource_str = path_array_and_resource.resource;

    if (pathinfo.resource_str)
      pathinfo.resource_str_length = pathinfo.resource_str.length;

    pathinfo.resource_str_lowercase =
      path_array_and_resource_with_collapsed_empty_segments_lowercase.resource;

    // return the path info
    return pathinfo;
  }

  parseParams(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): urlparsed_param_info_t | null {
    const { url } = params;

    const parseSearchParams = function (
      searchParams: URLSearchParams
    ): urlparsed_queryparam_t[] {
      const result: urlparsed_queryparam_t[] = [];
      let idx = 0;
      for (const [key, value] of searchParams.entries()) {
        const queryparam: urlparsed_queryparam_t = {
          idx: idx,
          // key
          key: key === '' ? null : key,
          key_alphabetics: [],
          key_nonalphanumerics: [],
          key_nonnumerics: [],
          key_numerics: [],
          key_unique_chars: [],
          // key lowercase
          key_lowercase: '',
          key_lowercase_alphabetics: [],
          key_lowercase_nonalphanumerics: [],
          key_lowercase_nonnumerics: [],
          key_lowercase_numerics: [],
          key_lowercase_unique_chars: [],
          // value
          val: value === '' ? null : value,
          val_alphabetics: [],
          val_nonalphanumerics: [],
          val_nonnumerics: [],
          val_numerics: [],
          val_unique_chars: [],
          // value lowercase
          val_lowercase: '',
          val_lowercase_alphabetics: [],
          val_lowercase_nonalphanumerics: [],
          val_lowercase_nonnumerics: [],
          val_lowercase_numerics: [],
          val_lowercase_unique_chars: []
        };

        if (queryparam.key) {
          // key
          queryparam.key_alphabetics = extractAlphabeticStrings(queryparam.key);
          queryparam.key_nonalphanumerics = extractNonAlphanumericStrings(
            queryparam.key
          );
          queryparam.key_nonnumerics = extractNonNumericStrings(queryparam.key);
          queryparam.key_numerics = extractNumericStrings(queryparam.key);
          queryparam.key_unique_chars = extractUniqueCharacters(queryparam.key);

          // key lowercase
          queryparam.key_lowercase = queryparam.key.toLowerCase();
          queryparam.key_lowercase_alphabetics = extractAlphabeticStrings(
            queryparam.key_lowercase
          );
          queryparam.key_lowercase_nonalphanumerics =
            extractNonAlphanumericStrings(queryparam.key_lowercase);
          queryparam.key_lowercase_nonnumerics = extractNonNumericStrings(
            queryparam.key_lowercase
          );
          queryparam.key_lowercase_numerics = extractNumericStrings(
            queryparam.key_lowercase
          );
          queryparam.key_lowercase_unique_chars = extractUniqueCharacters(
            queryparam.key_lowercase
          );
        }

        if (queryparam.val) {
          // val
          queryparam.val_alphabetics = extractAlphabeticStrings(queryparam.val);
          queryparam.val_nonalphanumerics = extractNonAlphanumericStrings(
            queryparam.val
          );
          queryparam.val_nonnumerics = extractNonNumericStrings(queryparam.val);
          queryparam.val_numerics = extractNumericStrings(queryparam.val);
          queryparam.val_unique_chars = extractUniqueCharacters(queryparam.val);

          // val lowercase
          queryparam.val_lowercase = queryparam.val.toLowerCase();
          queryparam.val_lowercase_alphabetics = extractAlphabeticStrings(
            queryparam.val_lowercase
          );
          queryparam.val_lowercase_nonalphanumerics =
            extractNonAlphanumericStrings(queryparam.val_lowercase);
          queryparam.val_lowercase_nonnumerics = extractNonNumericStrings(
            queryparam.val_lowercase
          );
          queryparam.val_lowercase_numerics = extractNumericStrings(
            queryparam.val_lowercase
          );
          queryparam.val_lowercase_unique_chars = extractUniqueCharacters(
            queryparam.val_lowercase
          );
        }

        result.push(queryparam);
        idx++;
      }
      return result;
    };

    const param_array: urlparsed_queryparam_t[] = parseSearchParams(
      url.searchParams
    );

    const param_info: urlparsed_param_info_t = {
      param_str: url.search,
      param_str_lowercase: url.search.toLowerCase(),
      params_as_array: param_array
    };

    return param_info;
  }
}
