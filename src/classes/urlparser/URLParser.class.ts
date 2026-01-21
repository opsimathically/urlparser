import type {
  urlparse_user_and_password_info_t,
  urlparse_port_and_protocol_info_t,
  urlparse_host_info_t,
  urlparse_base_info_t,
  urlparsed_baseinfo_t,
  urlparsed_resource_t,
  urlparsed_domain_result_t,
  urlparsed_resource_details_t,
  urlparsed_path_component_t,
  urlparsed_path_element_details_t,
  urlparsed_path_and_resource_info_t,
  urlparsed_indicators_t,
  urlparse_fail_indicators_t,
  urlparsed_path_t,
  urlparsed_queryparam_t,
  urlparsed_param_info_t,
  urlparsed_t
} from '@src/index';

import { isEmpty } from '../../functions/emptyvals/emptyvals';
import { VerboseURLAnalyticParser } from '../verboseurlanalyticparser/VerboseURLAnalyticParser.class';
import { parseDomain } from 'parse-domain';
import type { ParseResult as parsed_domain_info_t } from 'parse-domain';
// import type { url_diagnostic_result_t } from '../verboseurlanalyticparser/VerboseURLAnalyticParser.class';

const stringEndsWith = function (str: string, ends_with: string): boolean {
  if (str.substring(str.length - ends_with.length) == ends_with) return true;
  return false;
};

function extractNumericStrings(input: string): string[] | null {
  if (!input) return null;
  const matches: RegExpMatchArray | null = input.match(/\d+/g);
  return matches ? matches : null;
}

function extractNonNumericStrings(input: string): string[] | null {
  const parts: string[] = input.split(/\d+/).filter((part) => part.length > 0);
  return parts.length > 0 ? parts : null;
}

function extractNonNumericStringsLowercase(input: string): string[] | null {
  const parts: string[] = input
    .split(/\d+/)
    .map((part) => part.toLowerCase())
    .filter((part) => part.length > 0);

  return parts.length > 0 ? parts : null;
}

function extractAlphabeticStrings(input: string): string[] | null {
  const matches: RegExpMatchArray | null = input.match(/[A-Za-z]+/g);
  return matches ? matches : null;
}

function extractAlphabeticStringsLowercase(input: string): string[] | null {
  const matches: RegExpMatchArray | null = input.match(/[A-Za-z]+/g);
  return matches ? matches.map((part) => part.toLowerCase()) : null;
}

function extractNonAlphanumericStrings(input: string): string[] | null {
  const matches: RegExpMatchArray | null = input.match(/[^A-Za-z0-9]+/g);
  return matches ? matches : null;
}

function extractUniqueCharacters(input: string): string[] {
  const seen = new Set<string>();
  let result: string[] = [];

  for (const char of input) {
    if (!seen.has(char)) {
      seen.add(char);
      result.push(char);
    }
  }
  if (result.length) result = result.toSorted();
  return result;
}

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

export class URLParser {
  private verbose_analytic_parser: VerboseURLAnalyticParser =
    new VerboseURLAnalyticParser();
  constructor() {}

  public parse(url_to_parse: string): urlparsed_t {
    // set self ref
    const urlparser_ref = this;

    const final_urlparse_data: urlparsed_t = {
      indicators: {
        failures: {}
      }
    };

    // 1) Use built in URL parser to parse.
    let parsed_url: URL | null = null;
    try {
      // Note:
      // The url class will fail to parse for erroneous urls.  Things with bad ports, etc, will fail naturally.
      parsed_url = new URL(url_to_parse, url_to_parse);
    } catch (err: any) {
      if (err) {
        final_urlparse_data.indicators.has_failures = true;
        final_urlparse_data.indicators.failures.failed_basic_parsing = true;

        // create diagnostics
        final_urlparse_data.failed_parse_diagnostics =
          urlparser_ref.verbose_analytic_parser.analyzeUrl(
            url_to_parse,
            url_to_parse
          );

        return final_urlparse_data;
      }
    }
    if (!parsed_url) {
      final_urlparse_data.indicators.has_failures = true;
      final_urlparse_data.indicators.failures.failed_basic_parsing = true;
      return final_urlparse_data;
    }

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

    // user_and_password_info

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

    return final_urlparse_data;
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
    // host_info.host_domain_information_parsed

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
    }
    debugger;

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
      // Don't use this:
      // url_base = url.href.slice(0, url.href.indexOf(url.pathname));
      // Why: We use the original url string instead of url.href here due to the
      // native node URL parser automatically converting the host part to lowercase. For
      // the sake of accuracy, we want the actual url base rather than the lowercase
      // version only.
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
      if (
        stringEndsWith(
          base_info.base,
          `:${parse_data.scheme_and_port_info.port}`
        )
      ) {
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

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Parameter Parsing %%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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
