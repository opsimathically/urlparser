import test from 'node:test';
import assert from 'node:assert';
import { VerboseURLAnalyticParser } from '@src/classes/verboseurlanalyticparser/VerboseURLAnalyticParser.class';
import { URLFuzzer } from '@src/classes/urlfuzzer/URLFuzzer.class';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

// Since the nodejs URL parser doesn't give us much information about why a parse
// failed, and we'd like that information, we have to utilize our own secondary, more
// verbose parser.  Outside of unit testing, this parser is never intended to be
// invoked unless a regular URL parse fails.

test('Test verbose parser (good parse/bad parse)', async function () {
  const url_fuzzer = new URLFuzzer({
    complexityBias: 1,
    complexityWeightingStrength: 1,
    includeTrickyValidCases: true
  });

  // generate parsable/unparsable urls
  const parsable_urls = url_fuzzer.genParsableURLs(10000);
  const unparsable_urls = url_fuzzer.genUnparsableURLs(10000);

  // create verbose parser instance
  const verbose_url_parser = new VerboseURLAnalyticParser();

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Check Parsed OK %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  let parsed_ok_count = 0;
  let idx = 0;
  for (; idx < parsable_urls.length; idx++) {
    const url = parsable_urls[idx];

    const analysis = verbose_url_parser.analyzeUrl(url);
    if (analysis.ok !== true) {
      console.log('\n\n' + url);
      console.log(analysis);
      debugger;
    } else {
      parsed_ok_count++;
    }
  }

  assert.ok(
    idx === parsed_ok_count,
    'Mismatch, verbose parser did not match the expected count.'
  );

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Check Parse Fails %%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  let parse_fail_count = 0;
  for (idx = 0; idx < unparsable_urls.length; idx++) {
    const url = unparsable_urls[idx];
    const analysis = verbose_url_parser.analyzeUrl(url);
    if (analysis.ok !== true) {
      parse_fail_count++;
    } else {
      console.log('\n\n' + url);
      console.log(analysis);
      debugger;
    }
  }

  assert.ok(
    idx === parse_fail_count,
    'Mismatch, verbose parser did not match the expected count.'
  );
});
