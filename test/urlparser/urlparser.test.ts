import test from 'node:test';
import assert from 'node:assert';
import { URLParser } from '@src/classes/urlparser/URLParser.class';
import {
  DataURLFuzzer,
  URLFuzzer,
  BlobURLFuzzer,
  AboutURLFuzzer,
  MailtoURLFuzzer,
  URNURLFuzzer
} from '@src/index';

// create urlparser instance
const urlparser = new URLParser();

// test flags
const enabled = {
  data_url_tests: true,
  blob_url_tests: true,
  about_url_tests: true,
  mailto_url_tests: true,
  tel_url_tests: true,
  urn_url_tests: true,
  web_url_tests: true
};

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Data URL Tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if (enabled.data_url_tests)
  test('Data url parsing tests', async function () {
    let data_url_fuzzer = new DataURLFuzzer({
      include_minimal_cases_bool: false,
      include_non_ascii_bool: false,
      include_quoted_param_values_bool: true,
      max_data_length_u32: 4096,
      max_total_length_u32: 4096 * 2
    });

    const generated_valid_dataurls = data_url_fuzzer.generateValidDataUrls({
      count_u32: 100
    });

    for (const url of generated_valid_dataurls) {
      const parse_result = urlparser.parse(url);

      assert.ok(
        parse_result?.parsed_ok,
        `Parser failed generated valid: ${url}`
      );
      assert.ok(
        parse_result?.type === 'data',
        `Parser failed data type check: ${url}`
      );
    }

    data_url_fuzzer = new DataURLFuzzer({
      include_minimal_cases_bool: true,
      include_non_ascii_bool: true,
      include_quoted_param_values_bool: true,
      max_data_length_u32: 4096,
      max_total_length_u32: 4096 * 2
    });

    const generated_invalid_dataurls = data_url_fuzzer.generateInvalidDataUrls({
      count_u32: 10000
    });
    for (const url of generated_invalid_dataurls) {
      try {
        urlparser.parse(url);
      } catch (err) {
        if (err) assert.ok(false, `Parser failed generated invalid: ${url}`);
      }
    }
  });

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Blob URL Tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if (enabled.blob_url_tests)
  test('Blob url parsing tests', async function () {
    const blob_url_fuzzer = new BlobURLFuzzer({});

    // test urls for blobs
    const test_urls: string[] = [
      'blob:https://example.com/550e8400-e29b-41d4-a716-446655440000'
    ];

    const bad_vals: string[] = [
      'blob:http://54.205.103.92/00000000-0000-0000-0000-00000000000Z',
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
    ];

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result?.parsed_ok, `Parser failed static test: ${url}`);
    }

    for (const url of bad_vals) {
      const parse_result = urlparser.parse(url);
      assert.ok(!parse_result?.parsed_ok, `Parser failed bad values: ${url}`);
    }

    const generated_valid_blobs = blob_url_fuzzer.generateValidBlobUrls({
      count: 100
    });
    for (const blob of generated_valid_blobs) {
      const parse_result = urlparser.parse(blob);
      assert.ok(
        parse_result?.parsed_ok,
        `Parser failed generated valid: ${blob}`
      );
    }

    const generated_invalid_blobs = blob_url_fuzzer.generateInvalidBlobUrls({
      count: 100
    });
    for (const blob of generated_invalid_blobs) {
      const parse_result = urlparser.parse(blob);
      assert.ok(
        !parse_result?.parsed_ok,
        `Parser failed generated invalid: ${blob}`
      );
    }
  });

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% About URL Tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if (enabled.about_url_tests)
  test('About url parsing tests', async function () {
    const about_url_fuzzer = new AboutURLFuzzer({
      max_component_length_u32: 100,
      max_total_length_u32: 10000
    });

    const test_urls: string[] = [
      'ABOUT:blank',
      'About:Blank',
      'about:%62%6C%61%6E%6B',
      'about:BLANK',
      'about:CONFIG',
      'about:Reader',
      'about:addons',
      'about:blank',
      'about:blank#',
      'about:blank#top',
      'about:blank?',
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
      'about:reader?url=https%3A%2F%2Fexample.com',
      'about:reader?url=https://example.com',
      'about:reader?url=https://example.com#section',
      'about:reader?url=https://example.com&mode=dark',
      'about:sessionrestore',
      'about:settings',
      'about:srcdoc',
      'about:support',
      'about:support#info',
      'about:version'
    ];

    const bad_vals: string[] = [
      ' about:blank',
      'about:',
      'about:#',
      'about:###',
      'about:#fragment',
      'about:////',
      'about:?',
      'about:???',
      'about:?query',
      'about:blank ',
      'about:blank?# ',
      'about:reader??##',
      'about:reader?url=https://example.com ',
      'about:reader?url=https://example.com??##',
      'about:中文',
      'about:💥'
    ];

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result?.parsed_ok, `Parser failed (valid): ${url}`);
    }

    for (const url of bad_vals) {
      const parse_result = urlparser.parse(url);
      assert.ok(!parse_result?.parsed_ok, `Parser failed (invalid): ${url}`);
    }

    const valid_about_urls = about_url_fuzzer.generateValidAboutUrls({
      count_u32: 100
    });
    for (const about of valid_about_urls) {
      const parse_result = urlparser.parse(about);
      assert.ok(
        parse_result?.parsed_ok,
        `Parser failed autogenerated (valid): ${about}`
      );
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
        urlparser.parse(about);
      } catch (err) {
        if (err) {
          console.log({ err: err });
          assert.ok(
            false,
            `Parser invalid autogenerated threw an exception: ${about}`
          );
        }
      }
    }
  });

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Mailto URL Tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
if (enabled.mailto_url_tests)
  test('Mailto url parsing tests', async function () {
    const test_urls: string[] = [
      'MAILTO:support@example.com',
      'Mailto:support@example.com?Subject=Help',
      'mailto:USER@EXAMPLE.COM',
      'mailto:alice@example.com,bob@example.com',
      'mailto:alice@example.com,bob@example.com,charlie@example.com',
      'mailto:support@example.com',
      'mailto:support@example.com?',
      'mailto:support@example.com?bcc=a@example.com;b@example.com',
      'mailto:support@example.com?bcc=audit@example.com',
      'mailto:support@example.com?body=',
      'mailto:support@example.com?body=Hello',
      'mailto:support@example.com?body=Hello&subject=Help',
      'mailto:support@example.com?body=Line1&body=Line2',
      'mailto:support@example.com?cc=a@example.com&cc=b@example.com',
      'mailto:support@example.com?cc=team@example.com',
      'mailto:support@example.com?cc=team@example.com&bcc=audit@example.com',
      'mailto:support@example.com?cc=team@example.com&subject=Help&body=Hello',
      'mailto:support@example.com?cc=team@example.com,a@example.com',
      'mailto:support@example.com?subject=',
      'mailto:support@example.com?subject=%F0%9F%91%8B',
      'mailto:support@example.com?subject=Hello%20World',
      'mailto:support@example.com?subject=Help',
      'mailto:support@example.com?subject=Help ',
      'mailto:support@example.com?subject=Help#frag',
      'mailto:support@example.com?subject=Help&body=Hello',
      'mailto:support@example.com?subject=Help&body=Hello%20there',
      'mailto:support@example.com?subject=Help&cc=team@example.com&body=Hello&bcc=audit@example.com',
      'mailto:support@example.com?subject=Help;body=Hello',
      'mailto:support@example.com?subject=Help?body=Hello',
      'mailto:support@example.com?subject=One&subject=Two',
      'mailto:user.name+tag@example.co.uk',
      'mailto:user_name@example-domain.com'
    ];

    const bad_vals: string[] = [
      ' mailto:support@example.com',
      'mAiLtO:?body=Hi',
      'mailto',
      'mailto:',
      'mailto: support@example.com',
      'mailto:"Support Team" <support@example.com>',
      'mailto:%22Support%20Team%22%20%3Csupport@example.com%3E',
      'mailto:%22Support%20Team%22%20%3Csupport@example.com%3E?subject=Hi',
      'mailto:,,,',
      'mailto:; ; ;',
      'mailto:?',
      'mailto:?&&&',
      'mailto:?body=Hi',
      'mailto:?body=Hi#frag',
      'mailto:?subject=Hello',
      'mailto:?subject=Hello&body=Hi',
      'mailto:?subject=Help&&body=Hello',
      'mailto:?subject=Help;body=Hello',
      'mailto:Support%20Team%20%3Csupport@example.com%3E',
      'mailto:alice@example.com,bob@example.com;charlie@example.com',
      'mailto:alice@example.com;bob@example.com',
      'mailto:alice@example.com;bob@example.com,charlie@example.com',
      'mailto:alice@example.com;bob@example.com;charlie@example.com',
      'mailto:support@example.com ',
      'mailto:support@example.com#frag',
      'mailto:support@example.com?&subject=Help',
      'mailto:support@example.com?=value',
      'mailto:support@example.com??subject=Help',
      'mailto:support@example.com?body=Line1%0ALine2',
      'mailto:support@example.com?subject',
      'mailto:support@example.com?subject=&body',
      'mailto:support@example.com?subject=Help&'
    ];

    const mailto_fuzzer = new MailtoURLFuzzer();

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result?.parsed_ok, `Mailto static test failed: ${url}`);
    }

    for (const url of bad_vals) {
      const parse_result = urlparser.parse(url);
      assert.ok(!parse_result?.parsed_ok, `Mailto static test failed: ${url}`);
    }

    const valid_urls = mailto_fuzzer.generateValidMailtoUrls({
      count_u32: 100
    });

    for (const url of valid_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(
        parse_result?.type === 'mailto',
        `Mailto valid parse failed: ${url}`
      );
    }

    const invalid_urls = mailto_fuzzer.generateInvalidMailtoUrls({
      count_u32: 100
    });

    for (const url of invalid_urls) {
      try {
        urlparser.parse(url);
      } catch (err) {
        console.log({ err: err });
        assert.ok(
          false,
          `Invalid mailto testing resulted in an exception: ${url}`
        );
      }
    }
  });

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Tel URL Tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
if (enabled.tel_url_tests)
  test('Telphone url parsing tests', async function () {
    const test_urls: string[] = [
      'TEL:+15551234567',
      'TEL:+15551234567;ext=123',
      'Tel:+15551234567;ext=123',
      'tEl:5551234567',
      'tel:(555)123-4567',
      'tel:+1 (555) 123-4567',
      'tel:+1 555 123 4567',
      'tel:+1%20555%20123%204567',
      'tel:+1(555)123-4567',
      'tel:+1-555-123-4567',
      'tel:+1.555.123.4567',
      'tel:+15551234567',
      'tel:+15551234567 ;ext=123',
      'tel:+15551234567; ext=123',
      'tel:+15551234567;123',
      'tel:+15551234567;ext =123',
      'tel:+15551234567;ext=%31%32%33',
      'tel:+15551234567;ext=123',
      'tel:+15551234567;ext=123;flag',
      'tel:+15551234567;ext=123;foo=bar',
      'tel:+15551234567;ext=123?x=1',
      'tel:+15551234567;extension=123',
      'tel:+15551234567;foo',
      'tel:+15551234567;postd=pp22',
      'tel:+15551234567?',
      'tel:+15551234567?x=1',
      'tel:+15551234567?x=1?y=2',
      'tel:+44 20 7183 8750',
      'tel:+442071838750',
      'tel:+819012345678',
      'tel:00115551234567',
      'tel:02071838750',
      'tel:555-123-4567',
      'tel:555.123.4567',
      'tel:5551234567',
      'tel:5551234567;ext=99'
    ];

    const bad_vals: Array<string> = [
      'tel',
      'tel:',
      'tel:   ',
      'tel:%2B15551234567',
      'tel:()',
      'tel:+',
      'tel:+15551234567,123',
      'tel:+15551234567,p123',
      'tel:+15551234567;;;ext=123',
      'tel:+15551234567;;ext=123',
      'tel:+15551234567;=123',
      'tel:+15551234567;ext',
      'tel:+15551234567;ext=',
      'tel:+15551234567;ext==123',
      'tel:+15551234567;extension=123;foo=bar;foo=baz',
      'tel:+15551234567;foo=',
      'tel:+15551234567p123',
      'tel:+15551234567w123',
      'tel:+1555☎1234567',
      'tel:+１（５５５）１２３－４５６７',
      'tel:-',
      'tel:;;;?&&&',
      'tel:?x=1'
    ];

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result, 'Parser failed.');
    }

    for (const url of bad_vals) {
      const parse_result = urlparser.parse(url);
      if (parse_result) if (parse_result.type !== 'mailto') continue;
      assert.ok(parse_result.parsed_ok, `Parser failed ${url}`);
    }
  });

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% URN URL Tests %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if (enabled.urn_url_tests)
  test('URN parsing tests', async function () {
    const test_urls: string[] = [
      'URN:ietf:rfc:3986',
      'URN:uuid:550e8400-e29b-41d4-a716-446655440000',
      'UrN:Example:abc',
      'urn:a:b',
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
      'urn:example:abc',
      'urn:example:abc#section',
      'urn:example:abc::def',
      'urn:example:abc?',
      'urn:example:abc??x=1',
      'urn:example:abc?x=1',
      'urn:example:abc?x=1#p',
      'urn:example:abc?x=1?y=2',
      'urn:example:https://example.com/path',
      'urn:example:part1:part2:part3',
      'urn:example:thing?param=value',
      'urn:example:x',
      'urn:example:💥',
      'urn:example:abc#',
      'urn:example:abc##frag',
      'urn:foo:bar',
      'urn:ietf:rfc:2119',
      'urn:ietf:rfc:3986',
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
    ];

    const bad_vals: string[] = [
      ' urn:ietf:rfc:3986',
      'urn:ex ample:abc',
      'urn:example:ab cd',
      'urn:example:abc?# ',
      'urn:ietf:rfc:3986 ',
      'urn:',
      'urn:example:',
      'urn:abc',
      'urn::abc'
    ];

    for (const url of test_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result?.parsed_ok, `Parser failed: ${url}`);
    }

    for (const url of bad_vals) {
      const parse_result = urlparser.parse(url);
      if (parse_result?.parsed_ok) debugger;
      assert.ok(!parse_result?.parsed_ok, `Parser failed badval: ${url}.`);
    }

    const urnurl_fuzzer = new URNURLFuzzer({
      include_f_component_bool: true,
      include_known_examples_bool: true,
      include_non_ascii_bool: true,
      include_pct_encoding_bool: true,
      include_q_component_bool: true,
      include_r_component_bool: true
    });

    const valid_urls = urnurl_fuzzer.generateValidUrnUrls({ count_u32: 100 });
    for (const url of valid_urls) {
      const parse_result = urlparser.parse(url);
      assert.ok(parse_result?.parsed_ok, `Parser failed valid: ${url}`);
    }

    const invalid_urls = urnurl_fuzzer.generateInvalidUrnUrls({
      count_u32: 100
    });
    for (const url of invalid_urls) {
      try {
        urlparser.parse(url);
      } catch (err) {
        if (err) assert.ok(false, `Parser failed invalid: ${url}`);
      }
    }
  });

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Individual URL Type Tests %%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if (enabled.web_url_tests)
  test('Test url parser utilizing parsable/unparsable urls generated via fuzzer.', async function () {
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Data URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    const extraction_test_1 = 'data:text/plain;base64,SGVsbG8=';
    const extraction_test_result_1 = urlparser.parse(extraction_test_1);
    assert.ok(
      extraction_test_result_1?.parsed_ok,
      'Extraction test 1 failed parse.'
    );
    assert.ok(
      extraction_test_result_1?.type === 'data',
      'Extraction test 1 failed type check.'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Blob URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // test a basic blob url
    const extraction_test_2 =
      'blob:https://example.com/550e8400-e29b-41d4-a716-446655440000';
    const extraction_test_result_2 = urlparser.parse(extraction_test_2);
    assert.ok(
      extraction_test_result_2?.parsed_ok,
      'Extraction test 2 failed parse.'
    );
    assert.ok(
      extraction_test_result_2?.type === 'blob',
      'Extraction test 2 failed type check.'
    );
    assert.ok(
      extraction_test_result_2?.blob_url_info?.uuid ===
        '550e8400-e29b-41d4-a716-446655440000',
      'Extraction test 3 failed uuid check'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% About URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // test a basic about url
    const extraction_test_3 = 'about:debugging';
    const extraction_test_result_3 = urlparser.parse(extraction_test_3);
    assert.ok(
      extraction_test_result_3?.parsed_ok,
      'Extraction test 3 failed parse.'
    );
    assert.ok(
      extraction_test_result_3?.type === 'about',
      'Extraction test 3 failed type check.'
    );
    assert.ok(
      extraction_test_result_3?.about_url_info?.identifier === 'debugging',
      'Extraction test 3 failed identifier check.'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Mailto URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    const extraction_test_4 =
      'mailto:support@example.com?subject=Help&cc=team@example.com&body=Hello&bcc=audit@example.com';
    const extraction_test_result_4 = urlparser.parse(extraction_test_4);
    assert.ok(
      extraction_test_result_4?.parsed_ok,
      'Extraction test 4 failed parse.'
    );
    assert.ok(
      extraction_test_result_4?.type === 'mailto',
      'Extraction test 4 failed type check.'
    );
    assert.ok(
      extraction_test_result_4?.mailto_url_info?.bcc[0] === 'audit@example.com',
      'Extraction test 4 bcc value check failed.'
    );
    assert.ok(
      extraction_test_result_4?.mailto_url_info?.subject[0] === 'Help',
      'Extraction test 4 help value check failed.'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Tel URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    const extraction_test_5 = 'tel:+15551234567;ext=123;foo=bar';
    const extraction_test_result_5 = urlparser.parse(extraction_test_5);
    assert.ok(
      extraction_test_result_5?.parsed_ok,
      'Extraction test 5 failed parse.'
    );
    assert.ok(
      extraction_test_result_5?.type === 'telephone',
      'Extraction test 5 failed type check.'
    );
    assert.ok(
      extraction_test_result_5?.tel_url_info?.parameters?.ext[0] === '123',
      'Extraction test 5 failed parameter value check.'
    );
    assert.ok(
      extraction_test_result_5?.tel_url_info?.parameters?.ext[0] === '123',
      'Extraction test 5 failed parameter value check.'
    );
    assert.ok(
      extraction_test_result_5?.tel_url_info?.phone_number === '+15551234567',
      'Extraction test 5 phone number value check failed.'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% URN URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    const extraction_test_6 = 'urn:example:part1:part2:part3';
    const extraction_test_result_6 = urlparser.parse(extraction_test_6);
    assert.ok(
      extraction_test_result_6?.parsed_ok,
      'Extraction test 6 failed parse.'
    );
    assert.ok(
      extraction_test_result_6?.type === 'urn',
      'Extraction test 6 failed type check.'
    );
    assert.ok(
      extraction_test_result_6?.urn_url_info?.nid === 'example',
      'Extraction test 6 nid value check failed'
    );
    assert.ok(
      extraction_test_result_6?.urn_url_info?.nss === 'part1:part2:part3',
      'Extraction test 6 nid value check failed'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% HTTPS URL Test %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // attempt to parse out an extremely wacky looking url
    const extraction_test_7 =
      'https://hey:ThEre@something.someTHING.blah.TEST.co.uk:8842/path1234blah/56hello-there78/////---910---///56HELLO-tHEre78/mOO.PhP?blah!=BLAH1&blAh2=blah3#some-hash_here_whatEVER#someSECOND_HASH_WHAT';
    const extraction_test_result_7 = urlparser.parse(extraction_test_7);
    assert.ok(
      extraction_test_result_7?.parsed_ok,
      'Extraction test 7 failed parse.'
    );
    assert.ok(
      extraction_test_result_7?.type === 'web',
      'Extraction test 7 failed type check.'
    );
    assert.ok(
      extraction_test_result_7?.hash_info?.hash ===
        '#some-hash_here_whatEVER#someSECOND_HASH_WHAT',
      'Extraction test 7 failed hash check.'
    );
    assert.ok(
      extraction_test_result_7?.host_info?.top_level_domain === 'co.uk',
      'Extraction test 7 failed tld parse check.'
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Random Fault Testing %%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    const url_fuzzer = new URLFuzzer({
      complexity_bias: 1,
      complexity_weighting_strength: 1,
      include_tricky_valid_cases: true
    });

    // generate parsable/unparsable urls
    const parsable_urls = url_fuzzer.genParsableURLs(100);
    const unparsable_urls = url_fuzzer.genUnparsableURLs(100);

    // test random parsables
    for (let idx = 0; idx < parsable_urls.length; idx++) {
      const url = parsable_urls[idx];
      try {
        urlparser.parse(url);
      } catch (err) {
        if (err)
          assert.ok(false, `Parsing supposedly valid url threw error: ${url}`);
      }
    }

    // test random unparsables
    for (let idx = 0; idx < unparsable_urls.length; idx++) {
      const url = unparsable_urls[idx];
      try {
        urlparser.parse(url);
      } catch (err) {
        if (err) assert.ok(false, `Parsing invalid url threw error: ${url}`);
      }
    }

    // record set should be empty array now
    assert(true);
  });
