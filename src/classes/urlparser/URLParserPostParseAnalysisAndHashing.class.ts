import type { urlparsed_t } from '@src/types/custom_zod_types/custom_zod_types';

export class URLParserPostParseAnalysisAndHashing {
  constructor() {}

  public generateAnalysis(urlparsed: urlparsed_t): null {
    if (!urlparsed) return null;
    /*

    export type urlparsed_t = {
      scheme_and_port_info?: urlparse_port_and_protocol_info_t | null;
      user_and_password_info?: urlparse_user_and_password_info_t | null;
      host_info?: urlparse_host_info_t | null;
      base_info?: urlparse_base_info_t | null;
      path_and_resource_info?: urlparsed_path_and_resource_info_t | null;
      parameter_info?: urlparsed_param_info_t | null;
      failed_parse_diagnostics?: url_diagnostic_result_t | null;
      indicators: urlparsed_indicators_t;
    };
    */

    return null;
  }
}
