import test from 'node:test';
import assert from 'node:assert';
import { URLFuzzer } from '@src/index';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test('Test parsable/unparsable url generation in url fuzzer.', async function () {
  const url_fuzzer = new URLFuzzer({
    complexity_bias: 1,
    complexity_weighting_strength: 1,
    include_tricky_valid_cases: true
  });

  // generate parsable/unparsable urls
  const parsable_urls = url_fuzzer.genParsableURLs(10000);
  const unparsable_urls = url_fuzzer.genUnparsableURLs(10000);

  // test parsable
  for (let idx = 0; idx < parsable_urls.length; idx++) {
    const url = parsable_urls[idx];
    let parsed_ok = true;
    try {
      new URL(url, url);
    } catch (err) {
      if (err) {
        parsed_ok = false;
        console.log(err);
      }
    }
    assert.ok(parsed_ok, `#${idx}: Parsed Valid Had Error:\n` + url);
  }

  // test unparsable
  for (let idx = 0; idx < unparsable_urls.length; idx++) {
    const url = unparsable_urls[idx];
    let parsed_ok = true;
    try {
      new URL(url, url);
    } catch (err) {
      if (err) parsed_ok = false;
    }
    assert.ok(
      !parsed_ok,
      `#${idx}: Parsed Invalid When Should Have Failed:\n` + url
    );
  }
});
