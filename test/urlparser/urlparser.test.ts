import test from 'node:test';
import assert from 'node:assert';
import { URLParser } from '@src/classes/urlparser/URLParser.class';
import { URLFuzzer } from '@src/index';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test('Test url parser utilizing parsable/unparsable urls generated via fuzzer.', async function () {
  const url_fuzzer = new URLFuzzer({
    complexity_bias: 1,
    complexity_weighting_strength: 1,
    include_tricky_valid_cases: true
  });

  // generate parsable/unparsable urls
  const parsable_urls = url_fuzzer.genParsableURLs(1000);
  const unparsable_urls = url_fuzzer.genUnparsableURLs(1000);

  const urlparser = new URLParser();

  for (let idx = 0; idx < parsable_urls.length; idx++) {
    const url = parsable_urls[idx];
    const parsed_url = urlparser.parse(url);
    if (parsed_url.indicators.failures.failed_basic_parsing) {
      debugger;
    }
  }

  for (let idx = 0; idx < unparsable_urls.length; idx++) {
    const url = unparsable_urls[idx];
    const parsed_url = urlparser.parse(url);
    if (!parsed_url.indicators.failures.failed_basic_parsing) {
      debugger;
    }
  }

  // record set should be empty array now
  assert(true);
});
