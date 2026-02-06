// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% parse-domain Specific Package Types %%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

// NOTE: IMPORTANT
// ts-to-zod will not generate schemas for types not present
// in this file.  The problem is, that the parse-domain package
// uses types that use generics, and ts-to-zod does not support
// generating schemas for type generics.  For that reason we're
// forced to cast this type as an opaque unknown.  In real use
// cases,

// export type parsed_domain_info_t = unknown;

type parse_domain_validation_error = {
  type: string;
  message: string;
  column: number;
};

export type urlparsed_domain_result_t = {
  type: 'INVALID' | 'IP' | 'RESERVED' | 'NOT_LISTED' | 'LISTED';
  hostname: string;
  errors: Array<parse_domain_validation_error>;
  labels: Array<string>;
  subdomains: Array<string>;
  domain: string;
  top_level_domains: Array<string>;
  icann: {
    subdomains: Array<string>;
    domain: string;
    top_level_domains: Array<string>;
  };
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% URLFuzzer Class %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type url_generation_options_t = {
  seed?: number;

  /*
   * 0..1: controls typical complexity distribution for parsable URLs.
   * - 0 => mostly simple
   * - 1 => mostly complex
   */
  complexity_bias?: number;

  include_tricky_valid_cases?: boolean;

  /*
   * Strength of complexity bias within weightedPick.
   * 0 => weightedPick ignores complexity (but other logic still uses it)
   * 1 => strong push toward later options as complexity grows
   */
  complexity_weighting_strength?: number;
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% VerboseURLAnalyticParser Class %%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type url_diagnostic_issue_t = {
  code: string;
  message: string;
  offset: number;
  length: number;
  found?: string;
  expected?: string;
  context?: string;
  severity: 'fatal' | 'warning';
};

export type node_url_error_t = {
  name: string;
  message: string;
  code?: string;
};

export type url_diagnostic_result_t =
  | {
      ok: true;
      url: string;
      normalized: string;
      issues: url_diagnostic_issue_t[];
    }
  | {
      ok: false;
      issues: url_diagnostic_issue_t[];
      node_error?: node_url_error_t;
    };

export type parser_context_t = {
  input: string;
  base?: string;
  issues: url_diagnostic_issue_t[];
};

export type parsed_components_t = {
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

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% URLParserPostParseAnalysisAndHashing Class %%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type urlparsed_hashes_t = {
  url: string;
};

export type urlparsed_analysis_t = {
  has_params: boolean;
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% URLParser Class %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type urlparse_user_and_password_info_t = {
  username: string | null;
  username_lowercase: string | null;
  password: string | null;
  password_lowercase: string | null;
};

export type urlparse_port_and_protocol_info_t = {
  scheme: string;
  protocol: string;
  port: number;
  protocol_std_port: number;
};

export type urlparse_host_info_t = {
  host: string;
  host_with_protocol: string;
  host_lowercase: string;
  host_with_protocol_lowercase: string;
  domain: string | null;
  domain_with_tld: string | null;
  domain_with_subdomains_and_tld: string | null;
  top_level_domain: string | null;
  subdomains: string | null;
  host_domain_information_parsed: urlparsed_domain_result_t | null;
};

export type urlparse_base_info_t = {
  base: string;
  base_lowercase: string;
  base_without_port: string;
  base_without_port_lowercase: string;
};

export type urlparsed_path_charsets_t = {
  idx: number;
  chars: string[];
  chars_lowercase: string[];
  path: string;
};

export type url_parsed_path_part_t = {
  part: string;
  length: string;
};

export type urlparsed_path_component_t = {
  idx: number;
  content: string;
  length: number;
  char_set: string[];
};

export type urlparsed_path_element_details_t = {
  idx: number;

  // path verbatim
  path_elem: string;
  length: number;

  // numerics
  numeric: urlparsed_path_component_t[];
  numeric_unique: urlparsed_path_component_t[];

  // non-numerics
  non_numeric: urlparsed_path_component_t[];
  non_numeric_unique: urlparsed_path_component_t[];

  // non-numeric/non-alphabetic (symbols)
  non_alpha_non_numeric: urlparsed_path_component_t[];

  // alphabetic
  alphabetic: urlparsed_path_component_t[];
  alphabetic_unique: urlparsed_path_component_t[];

  // nonalphanumeric (symbols)
  nonalphanumeric: urlparsed_path_component_t[];
  nonalphanumeric_unique: urlparsed_path_component_t[];
};

export type urlparsed_resource_details_t = {
  resource: string | null;
  name: string | null;
  extension: string | null;
  parts: string[];
  is_hidden_file: boolean;
  resource_unique_chars: string[];
};

export type urlparsed_path_t = {
  path: string[];
  path_sorted: string[];
  path_str: string | null;
  path_str_unique_chars: string[];
  resource: string | null;
  resource_details: urlparsed_resource_details_t;
  resource_details_lowercase: urlparsed_resource_details_t;
  path_elem_details: urlparsed_path_element_details_t[];
};

export type urlparsed_path_and_resource_info_t = {
  // resource
  resource_str: string | null;
  resource_str_lowercase: string | null;
  resource_str_length: number;

  // pathname
  pathname: string;
  pathname_lowercase: string;
  pathname_normalized: string;
  pathname_normalized_lowercase: string;
  pathname_length: number;

  // parsed path
  path_parsed: urlparsed_path_t | null;
  path_parsed_collapsed: urlparsed_path_t | null;
  path_parsed_collapsed_lowercase: urlparsed_path_t | null;
};

export type urlparsed_path_numeric_components_t = number[];

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
  has_resource_filename_extension?: boolean;
  is_protocol_standard_port?: boolean;
  has_invalid_tcp_port?: boolean;
};

export interface urlparsed_queryparam_t {
  idx: number;
  // key related data
  key: string | null;
  key_alphabetics: string[] | null;
  key_nonalphanumerics: string[] | null;
  key_nonnumerics: string[] | null;
  key_numerics: string[] | null;
  key_unique_chars: string[] | null;

  // key lowercase
  key_lowercase: string | null;
  key_lowercase_alphabetics: string[] | null;
  key_lowercase_nonalphanumerics: string[] | null;
  key_lowercase_nonnumerics: string[] | null;
  key_lowercase_numerics: string[] | null;
  key_lowercase_unique_chars: string[] | null;

  // val related data
  val: string | null;
  val_alphabetics: string[] | null;
  val_nonalphanumerics: string[] | null;
  val_nonnumerics: string[] | null;
  val_numerics: string[] | null;
  val_unique_chars: string[] | null;

  val_lowercase: string | null;
  val_lowercase_alphabetics: string[] | null;
  val_lowercase_nonalphanumerics: string[] | null;
  val_lowercase_nonnumerics: string[] | null;
  val_lowercase_numerics: string[] | null;
  val_lowercase_unique_chars: string[] | null;
}

export type urlparsed_param_info_t = {
  param_str: string;
  param_str_lowercase: string;
  params_as_array: urlparsed_queryparam_t[];
};

export type url_hash_data_t = {
  hash: string | null;
  hash_lowercase: string | null;
};

export type unusual_url_type_t =
  | 'unknown_type'
  | 'data_url_type'
  | 'blob_url_type'
  | 'about_url_type'
  | 'mailto_url_type'
  | 'telephone_url_type'
  | 'urn_url_type'
  | 'unknown_type';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Data URLs %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type data_url_info_t = {
  scheme: 'data';
  media_type: string; // e.g. "text/plain", "image/png"
  charset: string | null; // e.g. "utf-8"
  is_base64: boolean; // true if ";base64" present
  data: string; // everything after the first comma (not decoded)
  metadata: string; // everything between "data:" and the comma (raw, not decoded)
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Blob URLs %%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type blob_url_info_t = {
  scheme: 'blob';
  origin: string; // e.g. "https://example.com", "null", "chrome-extension://abc123"
  uuid: string; // typically a UUID, but returned as-is
  query: string | null; // without leading "?"
  fragment: string | null; // without leading "#"
  raw: string; // trimmed original input
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% About URLs %%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type about_url_info_t = {
  scheme: 'about';
  identifier: string; // main page token (may be empty)
  query: string | null; // without leading "?"
  fragment: string | null; // without leading "#"
  raw: string; // trimmed original input
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Mailto URLs %%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type mailto_url_info_t = {
  scheme: 'mailto';
  raw: string; // trimmed original input
  to: string[]; // recipients from the mailto path (raw, not decoded)
  cc: string[]; // recipients from cc query params (split on , and ;)
  bcc: string[]; // recipients from bcc query params (split on , and ;)
  subject: string[]; // all subject values (raw, not decoded) - repeated keys preserved
  body: string[]; // all body values (raw, not decoded) - repeated keys preserved
  other_query_params: Record<string, string[]>; // any other query params, repeated keys preserved
  fragment: string | null; // content after '#', if present (raw, not decoded)
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Telephone URLs %%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type tel_url_info_t = {
  scheme: 'tel';
  phone_number: string; // raw phone portion (no params)
  parameters: Record<string, string[]>; // semicolon params (raw, repeated keys preserved)
  raw: string; // trimmed original input
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Uniform Resource Name URLs %%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type urn_url_info_t = {
  scheme: 'urn';
  nid: string; // namespace identifier (raw)
  nss: string; // namespace-specific string (raw; may contain colons)
  query: string | null; // without leading "?"
  fragment: string | null; // without leading "#"
  raw: string; // trimmed original input
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% URL Parsed Type %%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

export type urlparsed_t = {
  type:
    | 'websocket'
    | 'web'
    | 'email'
    | 'service'
    | 'data'
    | 'blob'
    | 'about'
    | 'mailto'
    | 'telephone'
    | 'urn'
    | 'other'
    | 'unset';

  parsed_ok: boolean;

  // if it's a data: url
  data_url_info?: data_url_info_t | null;
  // if it's a blob url
  blob_url_info?: blob_url_info_t | null;
  // if it's a about url
  about_url_info?: about_url_info_t | null;
  // if it's a mailto url
  mailto_url_info?: mailto_url_info_t | null;
  // if it's a tel url
  tel_url_info?: tel_url_info_t | null;
  // if it's a tel url
  urn_url_info?: urn_url_info_t | null;

  scheme_and_port_info?: urlparse_port_and_protocol_info_t | null;
  user_and_password_info?: urlparse_user_and_password_info_t | null;
  host_info?: urlparse_host_info_t | null;
  base_info?: urlparse_base_info_t | null;
  path_and_resource_info?: urlparsed_path_and_resource_info_t | null;
  parameter_info?: urlparsed_param_info_t | null;
  hash_info?: url_hash_data_t | null;
  failed_parse_diagnostics?: url_diagnostic_result_t | null;
  indicators?: any;
};
