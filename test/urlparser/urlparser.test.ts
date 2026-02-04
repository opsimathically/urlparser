import test, { beforeEach } from 'node:test';
import assert from 'node:assert';
import { URLParser } from '@src/classes/urlparser/URLParser.class';
import {
  URLFuzzer,
  BlobURLFuzzer,
  AboutURLFuzzer,
  MailtoURLFuzzer
} from '@src/index';

const urlparser = new URLParser();

// Dedupe/sort our test arrays in the case we add something duped.
function uniqueAndSorted(values: string[]): string[] {
  return Array.from(new Set(values)).sort();
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if (false)
  test('Blob url parsing tests', async function () {
    const blob_url_fuzzer = new BlobURLFuzzer({});

    // test urls for blobs
    const test_urls: string[] = uniqueAndSorted([
      'blob:https://example.com/550e8400-e29b-41d4-a716-446655440000'
    ]);

    const bad_vals: string[] = uniqueAndSorted([
      'blob:',
      'blob:/',
      'blob://',
      'blob://///',
      ' blob:https://example.com/550e8400-e29b',
      'BLOB:https://example.com/550e8400-e29b',
      'BLOB:https://example.com/UUID',
      'Blob:null/abc',
      'bLoB:http://localhost/xyz',
      'blob:about:blank/550e8400-e29b',
      'blob:about:blank/uuid',
      'blob:about:srcdoc/abc',
      'blob:chrome-extension://abc/uuid',
      'blob:chrome-extension://abcdef/xyz?foo=bar#hash',
      'blob:chrome-extension://abcdef123456/550e8400-e29b',
      'blob:file:///C:/temp/test.html/abc',
      'blob:file:///Users/me/test.html/550e8400-e29b',
      'blob:file:///tmp/test.html/uuid',
      'blob:http://127.0.0.1/abc',
      'blob:http://example.com/550e8400-e29b',
      'blob:http://localhost:3000/550e8400-e29b',
      'blob:http://localhost:3000/uuid',
      'blob:https://example.com/550e8400-e29b',
      'blob:https://example.com/550e8400-e29b ',
      'blob:https://example.com/550e8400-e29b#',
      'blob:https://example.com/550e8400-e29b#p',
      'blob:https://example.com/550e8400-e29b#section-1',
      'blob:https://example.com/550e8400-e29b?',
      'blob:https://example.com/550e8400-e29b?x=1',
      'blob:https://example.com/550e8400-e29b?x=1#p',
      'blob:https://example.com/550e8400-e29b?x=1&y=2',
      'blob:https://example.com/a',
      'blob:https://example.com/a%2Fb',
      'blob:https://example.com/a%2Fb%3Fc',
      'blob:https://example.com/abc123',
      'blob:https://example.com/this-is-not-a-uuid',
      'blob:https://example.com/uuid',
      'blob:https://example.com/uuid#p',
      'blob:https://example.com/uuid?x=1',
      'blob:https://example.com/uuid?x=1#p',
      'blob:moz-extension://abc/uuid',
      'blob:moz-extension://abcdef12-3456-7890-abcd-ef1234567890/550e8400-e29b',
      'blob:null/550e8400-e29b',
      'blob:null/abc',
      'blob:null/abc?debug=true#top',
      'blob:null/uuid'
    ]);

    /*
  Detected Invalids:
  blob:http://54.205.103.92/00000000-0000-0000-0000-00000000000Z
  */

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result, `Parser failed static test: ${url}`);
    }

    for (const url of bad_vals) {
      const parse_result = urlparser.parse(url);
      assert.ok(!parse_result, `Parser failed bad values: ${url}`);
    }

    const generated_valid_blobs = blob_url_fuzzer.generateValidBlobUrls({
      count: 100
    });
    for (const blob of generated_valid_blobs) {
      const parse_result = urlparser.parse(blob);
      assert.ok(parse_result, `Parser failed generated valid: ${blob}`);
    }

    const generated_invalid_blobs = blob_url_fuzzer.generateInvalidBlobUrls({
      count: 100
    });
    for (const blob of generated_invalid_blobs) {
      const parse_result = urlparser.parse(blob);
      if (parse_result) debugger;
      assert.ok(!parse_result, `Parser failed generated invalid: ${blob}`);
    }

    debugger;
  });

if (false)
  test('About url parsing tests', async function () {
    const about_url_fuzzer = new AboutURLFuzzer({
      max_component_length_u32: 100,
      max_total_length_u32: 10000
    });

    const test_urls: string[] = uniqueAndSorted([
      // ' about:blank',
      'ABOUT:blank',
      'About:Blank',
      // 'about:',
      // 'about:#',
      // 'about:###',
      // 'about:#fragment',
      'about:%62%6C%61%6E%6B',
      // 'about:////',
      // 'about:?',
      // 'about:???',
      // 'about:?query',
      'about:BLANK',
      'about:CONFIG',
      'about:Reader',
      'about:addons',
      'about:blank',
      // 'about:blank ',
      'about:blank#',
      'about:blank#top',
      'about:blank?',
      // 'about:blank?# ',
      'about:config',
      'about:config#network',
      'about:config?filter=network',
      'about:crashes',
      'about:debugging',
      'about:extensions',
      'about:flags',
      'about:foo/bar/baz',
      'about:gpu',
      'about:home',
      'about:internals',
      'about:library',
      'about:logins',
      'about:memory',
      'about:newtab',
      'about:newtab?source=tiles',
      'about:newtab?source=tiles#top',
      'about:page/subpage',
      'about:performance',
      'about:policies',
      'about:preferences',
      'about:preferences#privacy.cookies',
      'about:preferences?category=privacy#cookies',
      'about:preferences?category=privacy&expanded=true',
      'about:privatebrowsing',
      'about:profiles',
      'about:reader#',
      'about:reader#section-2',
      'about:reader/content',
      'about:reader?',
      // 'about:reader??##',
      'about:reader?url=https%3A%2F%2Fexample.com',
      'about:reader?url=https://example.com',
      // 'about:reader?url=https://example.com ',
      'about:reader?url=https://example.com#section',
      'about:reader?url=https://example.com&mode=dark',
      // 'about:reader?url=https://example.com??##',
      'about:sessionrestore',
      'about:settings',
      'about:srcdoc',
      'about:support',
      'about:support#info',
      'about:version'
      // 'about:中文',
      //'about:💥'
    ]);

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result, `Parser failed: ${url}`);
    }

    const valid_about_urls = about_url_fuzzer.generateValidAboutUrls({
      count_u32: 100
    });
    for (const about of valid_about_urls) {
      const parse_result = urlparser.parse(about);
      assert.ok(parse_result, `Parser failed valid tests: ${about}`);
    }

    // try and parse some known invalid urls in order to get the parser to throw exceptions
    // Note: Already run about 10,000,000 fuzz tests through here but we just leave a few in case
    // through some weird odds we are able to catch something.  We don't just assert.ok() because
    // it's possible for the fuzzer to generate urls that don't parse as about, but do parse as
    // other protocols, which means instead of null we get a valid object.
    const invalid_about_urls = about_url_fuzzer.generateInvalidAboutUrls({
      count_u32: 100
    });
    for (const about of invalid_about_urls) {
      try {
        const parse_result = urlparser.parse(about);
      } catch (err) {
        if (err) {
          assert.ok(false, `Parser failed and threw exception: ${about}`);
        }
      }
    }
  });

if (false)
  test('Mailto url parsing tests', async function () {
    const test_urls: string[] = uniqueAndSorted([
      // ' mailto:support@example.com',
      'MAILTO:support@example.com',
      'Mailto:support@example.com?Subject=Help',
      'mAiLtO:?body=Hi',
      'mailto',
      'mailto:',
      // 'mailto: support@example.com',
      // 'mailto:"Support Team" <support@example.com>',
      // 'mailto:%22Support%20Team%22%20%3Csupport@example.com%3E',
      // 'mailto:%22Support%20Team%22%20%3Csupport@example.com%3E?subject=Hi',
      // 'mailto:,,,',
      // 'mailto:; ; ;',
      'mailto:?',
      // 'mailto:?&&&',
      'mailto:?body=Hi',
      'mailto:?body=Hi#frag',
      'mailto:?subject=Hello',
      'mailto:?subject=Hello&body=Hi',
      // 'mailto:?subject=Help&&body=Hello',
      'mailto:?subject=Help;body=Hello',
      // 'mailto:Support%20Team%20%3Csupport@example.com%3E',
      'mailto:USER@EXAMPLE.COM',
      'mailto:alice@example.com,bob@example.com',
      'mailto:alice@example.com,bob@example.com,charlie@example.com',
      //'mailto:alice@example.com,bob@example.com;charlie@example.com',
      // 'mailto:alice@example.com;bob@example.com',
      // 'mailto:alice@example.com;bob@example.com,charlie@example.com',
      // 'mailto:alice@example.com;bob@example.com;charlie@example.com',
      'mailto:support@example.com',
      // 'mailto:support@example.com ',
      // 'mailto:support@example.com#frag',
      'mailto:support@example.com?',
      // 'mailto:support@example.com?&subject=Help',
      // 'mailto:support@example.com?=value',
      // 'mailto:support@example.com??subject=Help',
      'mailto:support@example.com?bcc=a@example.com;b@example.com',
      'mailto:support@example.com?bcc=audit@example.com',
      'mailto:support@example.com?body=',
      'mailto:support@example.com?body=Hello',
      'mailto:support@example.com?body=Hello&subject=Help',
      // 'mailto:support@example.com?body=Line1%0ALine2',
      'mailto:support@example.com?body=Line1&body=Line2',
      'mailto:support@example.com?cc=a@example.com&cc=b@example.com',
      'mailto:support@example.com?cc=team@example.com',
      'mailto:support@example.com?cc=team@example.com&bcc=audit@example.com',
      'mailto:support@example.com?cc=team@example.com&subject=Help&body=Hello',
      'mailto:support@example.com?cc=team@example.com,a@example.com',
      // 'mailto:support@example.com?subject',
      'mailto:support@example.com?subject=',
      'mailto:support@example.com?subject=%F0%9F%91%8B',
      // 'mailto:support@example.com?subject=&body',
      'mailto:support@example.com?subject=Hello%20World',
      'mailto:support@example.com?subject=Help',
      'mailto:support@example.com?subject=Help ',
      'mailto:support@example.com?subject=Help#frag',
      // 'mailto:support@example.com?subject=Help&',
      'mailto:support@example.com?subject=Help&body=Hello',
      'mailto:support@example.com?subject=Help&body=Hello%20there',
      'mailto:support@example.com?subject=Help&cc=team@example.com&body=Hello&bcc=audit@example.com',
      'mailto:support@example.com?subject=Help;body=Hello',
      'mailto:support@example.com?subject=Help?body=Hello',
      'mailto:support@example.com?subject=One&subject=Two',
      'mailto:user.name+tag@example.co.uk',
      'mailto:user_name@example-domain.com'
    ]);

    const mailto_fuzzer = new MailtoURLFuzzer();

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result, `Mailto static test failed: ${url}`);
    }

    const valid_urls = mailto_fuzzer.generateValidMailtoUrls({
      count_u32: 10000
    });

    for (const url of valid_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(
        parse_result?.type === 'mailto',
        `Mailto valid parse failed: ${url}`
      );
    }

    /*
  "MAILTO:q.ca%5EU%25kDZ!.o1S4.%25Iy
  @%5BIPv6%3A17ae%3Aefd%5D?x-foo=kJc2.%3AYJQ%3A%40-SgyoaH7o6qh2d5xDCl%2FuJNNFeYiyy-m.DIVze-_7%21K-9gFceZ%2194T9TNGJvfxoRWbjzr%40REXQMYyB%3FBxlAMXucvQm763%20xxk0EURIbSVfU%2C-2wT%2CE%206tT.nm5hSYfkb%2F_&x-foo=jEa4nRM0WMY&subject=ceKUwe2%3Ab4%21r%3Bi&subject=n%5CeAewQGTI4WX%5C2&to=%21KeD%3A%5C3Mfj80"

  'MAILTO:q.ca%5EU%25kDZ!.o1S4.%25Iy@%5BIPv6%3A17ae%3Aefd%5D?x-foo=kJc2.%3AYJQ%3A%40-SgyoaH7o6qh2d5xDCl%2FuJNNFeYiyy-m.DIVze-_7%21K-9gFceZ%2194T9TNGJvfxoRWbjzr%40REXQMYyB%3FBxlAMXucvQm763%20xxk0EURIbSVfU%2C-2wT%2CE%206tT.nm5hSYfkb%2F_&x-foo=jEa4nRM0WMY&subject=ceKUwe2%3Ab4%21r%3Bi&subject=n%5CeAewQGTI4WX%5C2&to=%21KeD%3A%5C3Mfj80'
  */

    /*
  const invalid_urls = mailto_fuzzer.generateInvalidMailtoUrls({
    count_u32: 1000
  });

  for (const url of invalid_urls) {
    const parse_result = urlparser.parse(url);

    debugger;
  }
  */
  });

test('Telphone url parsing tests', async function () {
  const test_urls: string[] = uniqueAndSorted([
    'TEL:+15551234567',
    'TEL:+15551234567;ext=123',
    'Tel:+15551234567;ext=123',
    'tEl:5551234567',
    'tel',
    'tel:',
    'tel:   ',
    'tel:%2B15551234567',
    'tel:()',
    'tel:(555)123-4567',
    'tel:+',
    'tel:+1 (555) 123-4567',
    'tel:+1 555 123 4567',
    'tel:+1%20555%20123%204567',
    'tel:+1(555)123-4567',
    'tel:+1-555-123-4567',
    'tel:+1.555.123.4567',
    'tel:+15551234567',
    'tel:+15551234567 ;ext=123',
    'tel:+15551234567,123',
    'tel:+15551234567,p123',
    'tel:+15551234567; ext=123',
    'tel:+15551234567;123',
    'tel:+15551234567;;;ext=123',
    'tel:+15551234567;;ext=123',
    'tel:+15551234567;=123',
    'tel:+15551234567;ext',
    'tel:+15551234567;ext =123',
    'tel:+15551234567;ext=',
    'tel:+15551234567;ext=%31%32%33',
    'tel:+15551234567;ext=123',
    'tel:+15551234567;ext=123;flag',
    'tel:+15551234567;ext=123;foo=bar',
    'tel:+15551234567;ext=123?x=1',
    'tel:+15551234567;ext==123',
    'tel:+15551234567;extension=123',
    'tel:+15551234567;extension=123;foo=bar;foo=baz',
    'tel:+15551234567;foo',
    'tel:+15551234567;foo=',
    'tel:+15551234567;postd=pp22',
    'tel:+15551234567?',
    'tel:+15551234567?x=1',
    'tel:+15551234567?x=1?y=2',
    'tel:+15551234567p123',
    'tel:+15551234567w123',
    'tel:+1555☎1234567',
    'tel:+44 20 7183 8750',
    'tel:+442071838750',
    'tel:+819012345678',
    'tel:+１（５５５）１２３－４５６７',
    'tel:-',
    'tel:00115551234567',
    'tel:02071838750',
    'tel:555-123-4567',
    'tel:555.123.4567',
    'tel:5551234567',
    'tel:5551234567;ext=99',
    'tel:;;;?&&&',
    'tel:?x=1'
  ]);

  for (const url of test_urls) {
    const parse_result = urlparser.parse(url);
    assert.ok(parse_result, 'Parser failed.');
  }
});

test('URN parsing tests', async function () {
  const test_urls: string[] = uniqueAndSorted([
    ' urn:ietf:rfc:3986',
    'URN:ietf:rfc:3986',
    'URN:uuid:550e8400-e29b-41d4-a716-446655440000',
    'UrN:Example:abc',
    'urn:a:b',
    'urn:ex ample:abc',
    'urn:example:%F0%9F%91%8B',
    'urn:example::abc',
    'urn:example:a#b',
    'urn:example:a%2Fb',
    'urn:example:a%3Ab%3Ac',
    'urn:example:a/b/c',
    'urn:example:a:b:c',
    'urn:example:a:b:c:d:e',
    'urn:example:a:b:c?x=1&y=2#frag',
    'urn:example:a?b=c',
    'urn:example:ab cd',
    'urn:example:abc',
    'urn:example:abc#',
    'urn:example:abc##frag',
    'urn:example:abc#section',
    'urn:example:abc::def',
    'urn:example:abc?',
    'urn:example:abc?# ',
    'urn:example:abc??x=1',
    'urn:example:abc?x=1',
    'urn:example:abc?x=1#p',
    'urn:example:abc?x=1?y=2',
    'urn:example:https://example.com/path',
    'urn:example:part1:part2:part3',
    'urn:example:thing?param=value',
    'urn:example:x',
    'urn:example:💥',
    'urn:foo:bar',
    'urn:ietf:rfc:2119',
    'urn:ietf:rfc:3986',
    'urn:ietf:rfc:3986 ',
    'urn:ietf:rfc:3986#page-1',
    'urn:ietf:rfc:8259',
    'urn:isbn:0451450523',
    'urn:isbn:9780131103627',
    'urn:mpeg:mpeg7:schema:2001',
    'urn:oid:1.2.840.113549.1.1.11',
    'urn:oid:2.5.4.3',
    'urn:uuid:00000000-0000-0000-0000-000000000000',
    'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
    'urn:uuid:550e8400-e29b-41d4-a716-446655440000#section',
    'urn:uuid:550e8400-e29b-41d4-a716-446655440000?download=true',
    'urn:uuid:550e8400-e29b-41d4-a716-446655440000?x=1#y'
  ]);

  const bad_vals: string[] = uniqueAndSorted([
    'urn:',
    'urn:example:',
    'urn:abc',
    'urn::abc'
  ]);

  for (const url of test_urls) {
    const parse_result = urlparser.parse(url);
    assert.ok(parse_result, 'Parser failed.');
  }

  for (const url of bad_vals) {
    const parse_result = urlparser.parse(url);
    assert.ok(!parse_result, 'Parser failed.');
  }
});

if (false)
  test('Test url parser utilizing parsable/unparsable urls generated via fuzzer.', async function () {
    const url_fuzzer = new URLFuzzer({
      complexity_bias: 1,
      complexity_weighting_strength: 1,
      include_tricky_valid_cases: true
    });

    // generate parsable/unparsable urls
    const parsable_urls = url_fuzzer.genParsableURLs(100);
    const unparsable_urls = url_fuzzer.genUnparsableURLs(100);

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Content Verification Testing %%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    /*
  chrome://settings
  edge://inspect
  mailto:support@example.com
  tel:+15551234567
  urn:ietf:rfc:3986
  */

    // test a basic data url
    const extraction_test_1 = 'data:text/plain;base64,SGVsbG8=';
    const extraction_test_result_1 = urlparser.parse(extraction_test_1);
    debugger;

    // test a basic blob url
    const extraction_test_2 = 'blob:https://example.com/550e8400-e29b';
    const extraction_test_result_2 = urlparser.parse(extraction_test_2);
    debugger;

    // test a basic about url
    const extraction_test_3 = 'about:debugging';
    const extraction_test_result_3 = urlparser.parse(extraction_test_3);
    debugger;

    // test extractions
    const extraction_test_4 =
      'https://hey:ThEre@something.someTHING.blah.TEST.co.uk:8842/path1234blah/56hello-there78/////---910---///56HELLO-tHEre78/mOO.PhP?blah!=BLAH1&blAh2=blah3#some-hash_here_whatEVER#someSECOND_HASH_WHAT';
    const extraction_test_result_4 = urlparser.parse(extraction_test_4);
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
