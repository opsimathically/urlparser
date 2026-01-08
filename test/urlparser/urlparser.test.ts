import test from 'node:test';
import assert from 'node:assert';

import { URLParser } from '@src/classes/urlparser/URLParser.class';

import { unusual_or_bad_urls } from './badurls/badurls';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test('Arbitrary test(s).', async function () {
  const urlparser = new URLParser();

  const basic_test_urls = [
    // 'whatever://example.com:45/something_blah.php?a=1&b=2&c=3&d&e&f=4&=g&=h',
    'http://example.com:99999:999/',
    'whatever://Someuser:Something@example.com:45/something///////abcd1234/56/id=1/weird=string/something_blah.php?a=1&b=2&c=3&d&e&f=4&=g&=h',
    'whatever://example.com',
    'whatever://example.com',

    'https://example.com',
    'https://example.com/'
  ];

  for (let idx = 0; idx < basic_test_urls.length; idx++) {
    const url = basic_test_urls[idx];
    const parsed_url = urlparser.parse(url);
    debugger;
  }

  for (let idx = 0; idx < unusual_or_bad_urls.length; idx++) {
    const url = unusual_or_bad_urls[idx];
    const parsed_url = urlparser.parse(url);
  }

  // record set should be empty array now
  assert(true);
});
