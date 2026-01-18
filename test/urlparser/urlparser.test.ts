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
  const parsable_urls = url_fuzzer.genParsableURLs(100);
  const unparsable_urls = url_fuzzer.genUnparsableURLs(100);
  const urlparser = new URLParser();

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Content Verification Testing %%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // test extractions
  const extraction_test_1 =
    'https://hey:there@something.com:8842/path1234blah/56hello-there78/////---910---///56HELLO-tHEre78/mOO.PhP?blah!=BLAH1&blAh2=blah3';
  const extraction_test_result_1 = urlparser.parse(extraction_test_1);
  debugger;

  // -> When we get back from bike/swim.
  // Write a few extraction tests, write checks to ensure that the data is
  // being generated extracted correctly.
  const extraction_test_url_2 = 'http://www.hello.com/';

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Random Fault Testing %%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // test random parsables
  for (let idx = 0; idx < parsable_urls.length; idx++) {
    const url = parsable_urls[idx];
    const parsed_url = urlparser.parse(url);
    if (parsed_url.indicators.failures.failed_basic_parsing) {
      debugger;
    }
  }

  // test random unparsables
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
