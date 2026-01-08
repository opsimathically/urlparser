import { isEmpty } from '../../functions/emptyvals/emptyvals';

import { parseDomain } from 'parse-domain';
import type { ParseResult as parsed_domain_info_t } from 'parse-domain';

const stringEndsWith = function (str: string, ends_with: string): boolean {
  if (str.substring(str.length - ends_with.length) == ends_with) return true;
  return false;
};

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

export type urlparse_user_and_password_info_t = {
  username: string | null;
  username_lowercase: string | null;
  password: string | null;
  password_lowercase: string | null;
};

export type urlparse_port_and_protocol_info_t = {
  protocol: string;
  port: number;
  protocol_std_port: number;
};

export type urlparse_host_info_t = {
  host: string;
  host_with_protocol: string;
  host_lowercase: string;
  host_with_protocol_lowercase: string;
  host_domain_information_parsed: parsed_domain_info_t | null;
};

export type urlparse_base_info_t = {
  base: string;
  base_lowercase: string;
  base_without_port: string;
  base_without_port_lowercase: string;
};

export type urlparsed_baseinfo_t = {
  base: string;
  base_with_port: string;
};

export type urlparsed_resource_t = {
  name: string | null;
  extension: string | null;
};

export type urlparsed_path_and_resource_info_t = {
  // resource info
  resource_str: string | null;
  resource_str_lowercase: string | null;
  resource_info: urlparsed_resource_t;
  resource_info_lowercase: urlparsed_resource_t;

  // pathname strings
  pathname: string;
  pathname_lowercase: string;
  pathname_normalized: string;
  pathname_normalized_lowercase: string;

  // parsed path
  path_parsed: urlparsed_path_t | null;
  path_parsed_collapsed: urlparsed_path_t | null;
  path_parsed_collapsed_lowercase: urlparsed_path_t | null;
};

export type urlparsed_indicators_t = {
  failures: {
    failed_basic_parsing?: boolean;
    port_is_missing?: boolean;
  };
  has_failures?: boolean;
  has_url_base?: boolean;
  has_embedded_port?: boolean;
  has_embedded_username?: boolean;
  has_embedded_password?: boolean;
  is_not_http_or_https?: boolean;
  is_http?: boolean;
  is_https?: boolean;
  is_websocket?: boolean;
  is_ipv4_address?: boolean;
  is_ipv6_address?: boolean;
  has_nonstandard_protocol_port?: boolean;
  has_url_parameters?: boolean;
  has_paths?: boolean;
  has_numeric_path?: boolean;
  has_numeric_parameters?: boolean;
  has_numeric_parameter_names?: boolean;
  has_script_filename_extension?: boolean;
  is_protocol_standard_port?: boolean;
  has_invalid_tcp_port?: boolean;
};

export type urlparse_fail_indicators_t = {
  url_failed_basic_parse: boolean;
};

export type urlparsed_old_t = {
  url: string;
  url_base: string;
  url_with_just_path: string;
  url_without_params: string;
  url_without_hash: string;
  url_without_hash_sha1: string;
  script_part: string;
  split_script: string[];
  script_extension: string;
  script_extension_lowercase: string;
  scheme: string;
  protocol: string;
  protocol_standard_port: number;
  username: string;
  password: string;
  host: string;
  hostname: string;
  host_without_subdomains: string;
  top_level_domain: string;
  host_parsed: {
    type: string;
    hostname: string;
    labels: string[];
    icann: {
      subDomains: string[];
      domain: string;
      topLevelDomains: string[];
    };
    subDomains: string[];
    domain: string;
    topLevelDomains: string[];
  };
  // port can be null in the case that you have a custom protocol with no port provided (e.g.: whatever://something.com/)
  port: number | null;
  port_str: string;
  path: string;
  path_without_script: string[];
  path_with_script: string[];
  path_without_script_part_hash: string | null;
  paths_with_script_hash: string | null;

  path_as_string: string;
  paths_as_urls: string[];
  path_entries_with_numeric_values: string[];
  path_numeric_entry_count: number;
  query: string;
  query_data: {
    as_array: [string[]];
    as_obj: Record<string, string | undefined>;
  };
  query_data_unique_keys_only: string[];
  query_data_unique_vals_only: string[];
  query_data_unique_keys_only_hash: string | null;
  query_data_unique_vals_only_hash: string | null;
  query_var_count: number;
  hash: string;
  script_flags: {
    has_hidden_file_prefix: boolean;
    has_tilde_file_prefix: boolean;
    has_non_alphanumeric_file_prefix: boolean;
  };
  total_non_alphanumeric_chars: number;
  total_alphanumeric_chars: number;
  total_non_numeric_chars: number;
  total_numeric_chars: number;
  total_non_alphabetic_chars: number;
  total_alphabetic_chars: number;
  indicators: urlparsed_indicators_t;
};

export type urlparsed_path_t = {
  path: string[];
  path_sorted: string[];
  path_str: string | null;
  resource: string | null;
};

export interface urlparsed_queryparam_t {
  key: string | null;
  val: string | null;
}

export type urlparsed_param_info_t = {
  param_str: string;
  param_str_lowercase: string;
  params_as_array: urlparsed_queryparam_t[];
  params_as_array_lowercase: urlparsed_queryparam_t[];
};

export type urlparsed_t = {
  scheme_and_port_info?: urlparse_port_and_protocol_info_t | null;
  user_and_password_info?: urlparse_user_and_password_info_t | null;
  host_info?: urlparse_host_info_t | null;
  base_info?: urlparse_base_info_t | null;
  path_and_resource_info?: urlparsed_path_and_resource_info_t | null;
  parameter_info?: urlparsed_param_info_t | null;
  indicators: urlparsed_indicators_t;
};

export class URLParser {
  constructor() {}

  public parse(url_to_parse: string): urlparsed_t {
    // set self ref
    const urlparser_ref = this;

    const final_urlparse_data: urlparsed_t = {
      indicators: {
        failures: {}
      }
    };

    // attempt to parse the crawl target
    let parsed_url: URL | null = null;
    try {
      // Note:
      // The url class will fail to parse for erroneous urls.  Things with bad ports, etc, will fail naturally.
      parsed_url = new URL(url_to_parse, url_to_parse);
    } catch (err: any) {
      if (err) {
        final_urlparse_data.indicators.has_failures = true;
        final_urlparse_data.indicators.failures.failed_basic_parsing = true;
        return final_urlparse_data;
      }
    }
    if (!parsed_url) {
      final_urlparse_data.indicators.has_failures = true;
      final_urlparse_data.indicators.failures.failed_basic_parsing = true;
      return final_urlparse_data;
    }

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

    host_info.host_domain_information_parsed = parseDomain(
      host_info.host_lowercase
    );

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

  /**
   * @description Parses the base part of a url into useful data.
   */
  private parseBaseInfo(params: {
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
      url_base = url.href;
    } else {
      url_base = url.href.slice(0, url.href.indexOf(url.pathname));
    }
    if (url_base) parse_data.indicators.has_url_base = true;

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

    //

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

    const pathinfo: urlparsed_path_and_resource_info_t = {
      pathname: '',
      pathname_lowercase: '',
      pathname_normalized: '',
      pathname_normalized_lowercase: '',
      path_parsed: null,
      path_parsed_collapsed: null,
      path_parsed_collapsed_lowercase: null,
      resource_str: '',
      resource_info: {
        extension: null,
        name: null
      },
      resource_str_lowercase: '',
      resource_info_lowercase: {
        extension: null,
        name: null
      }
    };

    const collapseEmptyPathSegments = function (path: string): string {
      if (path === '') {
        return path;
      }
      const collapsed = path.replace(/\/{2,}/g, '/');
      return collapsed;
    };

    const parsePathAndResource = function (raw_path: string): urlparsed_path_t {
      if (!raw_path) {
        return { path: [], path_sorted: [], path_str: null, resource: null };
      }
      const trimmed = raw_path.replace(/^\/|\/$/g, '');
      if (trimmed === '') {
        return { path: [], path_sorted: [], path_str: null, resource: null };
      }
      const segments = trimmed.split('/');
      const resource = segments.pop() ?? null;
      return {
        path: segments,
        path_sorted: segments.length > 0 ? segments.toSorted() : segments,
        path_str: segments.length > 0 ? segments.join('/') : null,
        resource: resource
      };
    };

    const pathname = url.pathname;
    const pathname_with_collapsed_empty_segments = collapseEmptyPathSegments(
      url.pathname
    );

    pathinfo.pathname = pathname;
    pathinfo.pathname_lowercase = pathname.toLowerCase();
    pathinfo.pathname_normalized = collapseEmptyPathSegments(pathinfo.pathname);
    pathinfo.pathname_normalized_lowercase = collapseEmptyPathSegments(
      pathinfo.pathname.toLowerCase()
    );

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
    pathinfo.resource_str_lowercase =
      path_array_and_resource_with_collapsed_empty_segments_lowercase.resource;

    /**
     * Parses a resource filename and extracts its extension.
     *
     * Examples:
     * "something_blah.php"   → { name: "something_blah", extension: "php" }
     * "archive.tar.gz"       → { name: "archive", extension: "tar.gz" }
     * "README"               → { name: "README", extension: null }
     * ".env"                 → { name: ".env", extension: null }
     */
    const parseResourceExtension = function (
      resource: string
    ): urlparsed_resource_t {
      // No dots at all → no extension
      if (!resource.includes('.')) {
        return { name: resource, extension: null };
      }

      // Dotfile with no basename (e.g., ".env")
      if (resource.startsWith('.') && resource.indexOf('.', 1) === -1) {
        return { name: resource, extension: null };
      }

      const parts = resource.split('.');

      // Single extension (foo.txt)
      if (parts.length === 2) {
        return {
          name: parts[0],
          extension: parts[1]
        };
      }

      // Multiple dots — treat everything after the first dot as extension
      // (archive.tar.gz → tar.gz)
      return {
        name: parts[0],
        extension: parts.slice(1).join('.')
      };
    };

    // pathinfo.resource_info: urlparsed_resource_t;
    // pathinfo.resource_info_lowercase: urlparsed_resource_t;
    // pathinfo.resource_str

    if (pathinfo.resource_str)
      pathinfo.resource_info = parseResourceExtension(pathinfo.resource_str);
    if (pathinfo.resource_str_lowercase)
      pathinfo.resource_info_lowercase = parseResourceExtension(
        pathinfo.resource_str_lowercase
      );

    // return the path info
    return pathinfo;
  }

  parseParams(params: {
    url: URL;
    parse_data: urlparsed_t;
  }): urlparsed_param_info_t | null {
    const { url } = params;

    /**
     * Converts URLSearchParams into an array of key/value objects.
     *
     * Examples:
     * "?value1=1&value2&value3"
     * →
     * [
     *   { key: "value1", val: "1" },
     *   { key: "value2", val: null },
     *   { key: "value3", val: null }
     * ]
     */
    const parseSearchParams = function (
      searchParams: URLSearchParams
    ): urlparsed_queryparam_t[] {
      const result: urlparsed_queryparam_t[] = [];
      for (const [key, value] of searchParams.entries()) {
        result.push({
          key: key === '' ? null : key,
          val: value === '' ? null : value
        });
      }
      return result;
    };

    const param_array: urlparsed_queryparam_t[] = parseSearchParams(
      url.searchParams
    );

    const param_array_lc: Array<urlparsed_queryparam_t> = [];
    for (let idx = 0; idx < param_array.length; idx++) {
      const entry = param_array[idx];
      param_array_lc.push({
        key: !entry.key ? null : entry.key.toLowerCase(),
        val: !entry.val ? null : entry.val.toLowerCase()
      });
    }

    const param_info: urlparsed_param_info_t = {
      param_str: url.search,
      param_str_lowercase: url.search.toLowerCase(),
      params_as_array: param_array,
      params_as_array_lowercase: param_array_lc
    };

    return param_info;
  }
}
