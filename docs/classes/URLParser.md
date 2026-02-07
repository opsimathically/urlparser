[**@opsimathically/urlparser**](../README.md)

***

[@opsimathically/urlparser](../README.md) / URLParser

# Class: URLParser

Defined in: [src/classes/urlparser/URLParser.class.ts:116](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L116)

## Constructors

### Constructor

> **new URLParser**(): `URLParser`

Defined in: [src/classes/urlparser/URLParser.class.ts:119](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L119)

#### Returns

`URLParser`

## Methods

### parse()

> **parse**(`url_to_parse`): [`urlparsed_t`](../type-aliases/urlparsed_t.md)

Defined in: [src/classes/urlparser/URLParser.class.ts:125](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L125)

#### Parameters

##### url\_to\_parse

`string`

#### Returns

[`urlparsed_t`](../type-aliases/urlparsed_t.md)

***

### parseAboutURL()

> **parseAboutURL**(`input_url`): [`about_url_info_t`](../type-aliases/about_url_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:520](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L520)

#### Parameters

##### input\_url

`string`

#### Returns

[`about_url_info_t`](../type-aliases/about_url_info_t.md) \| `null`

***

### parseBlobURL()

> **parseBlobURL**(`input_url`): [`blob_url_info_t`](../type-aliases/blob_url_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:450](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L450)

#### Parameters

##### input\_url

`string`

#### Returns

[`blob_url_info_t`](../type-aliases/blob_url_info_t.md) \| `null`

***

### parseDataURL()

> **parseDataURL**(`input_url`): [`data_url_info_t`](../type-aliases/data_url_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:353](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L353)

#### Parameters

##### input\_url

`string`

#### Returns

[`data_url_info_t`](../type-aliases/data_url_info_t.md) \| `null`

***

### parseMailtoURL()

> **parseMailtoURL**(`input_url`): [`mailto_url_info_t`](../type-aliases/mailto_url_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:577](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L577)

#### Parameters

##### input\_url

`string`

#### Returns

[`mailto_url_info_t`](../type-aliases/mailto_url_info_t.md) \| `null`

***

### parseParams()

> **parseParams**(`params`): [`urlparsed_param_info_t`](../type-aliases/urlparsed_param_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:1602](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L1602)

#### Parameters

##### params

###### parse_data

[`urlparsed_t`](../type-aliases/urlparsed_t.md)

###### url

`URL`

#### Returns

[`urlparsed_param_info_t`](../type-aliases/urlparsed_param_info_t.md) \| `null`

***

### parsePathAndResourceInfo()

> **parsePathAndResourceInfo**(`params`): [`urlparsed_path_and_resource_info_t`](../type-aliases/urlparsed_path_and_resource_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:1205](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L1205)

#### Parameters

##### params

###### parse_data

[`urlparsed_t`](../type-aliases/urlparsed_t.md)

###### url

`URL`

#### Returns

[`urlparsed_path_and_resource_info_t`](../type-aliases/urlparsed_path_and_resource_info_t.md) \| `null`

***

### parseTelephoneURL()

> **parseTelephoneURL**(`input_url`): [`tel_url_info_t`](../type-aliases/tel_url_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:724](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L724)

#### Parameters

##### input\_url

`string`

#### Returns

[`tel_url_info_t`](../type-aliases/tel_url_info_t.md) \| `null`

***

### parseURNURL()

> **parseURNURL**(`input_url`): [`urn_url_info_t`](../type-aliases/urn_url_info_t.md) \| `null`

Defined in: [src/classes/urlparser/URLParser.class.ts:796](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/urlparser/URLParser.class.ts#L796)

#### Parameters

##### input\_url

`string`

#### Returns

[`urn_url_info_t`](../type-aliases/urn_url_info_t.md) \| `null`
