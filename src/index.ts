// export project types
export type * from './types/custom_zod_types/custom_zod_types';
export type * from './types/project_types';

// export generated validators
export * from './zod_type_validators/custom_ts_to_zod_generated_validators';

// export classes

// datas
export { DataURLFuzzer } from './classes/dataurlfuzzer/DataURLFuzzer.class';
export { DataURLValidator } from './classes/dataurlvalidator/DataURLValidator.class';

// blobs
export { BlobURLFuzzer } from './classes/bloburlfuzzer/BlobURLFuzzer.class';
export { BlobURLValidator } from './classes/bloburlvalidator/BlobURLValidator.class';

// abouts
export { AboutURLFuzzer } from './classes/abouturlfuzzer/AboutURLFuzzer.class';
export { AboutURLValidator } from './classes/abouturlvalidator/AboutURLValidator.class';

// mailtos
export { MailtoURLFuzzer } from './classes/mailtourlfuzzer/MailtoURLFuzzer.class';
export { MailtoURLValidator } from './classes/mailtourlvalidator/MailtoURLValidator.class';

// tel (telephone)
export { TelURLValidator } from './classes/telurlvalidator/TelURLValidator.class';

// urns
export { URNURLFuzzer } from './classes/urnurlfuzzer/URNURLFuzzer.class';
export { URNURLValidator } from './classes/urnurlvalidator/URNURLValidator.class';

// standard urls
export { URLFuzzer } from './classes/urlfuzzer/URLFuzzer.class';
export { URLParser } from './classes/urlparser/URLParser.class';

export { VerboseURLAnalyticParser } from './classes/verboseurlanalyticparser/VerboseURLAnalyticParser.class';
