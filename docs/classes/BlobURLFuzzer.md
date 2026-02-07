[**@opsimathically/urlparser**](../README.md)

***

[@opsimathically/urlparser](../README.md) / BlobURLFuzzer

# Class: BlobURLFuzzer

Defined in: [src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts:32](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts#L32)

## Implements

- `blob_url_fuzzer_i`

## Constructors

### Constructor

> **new BlobURLFuzzer**(`params`): `BlobURLFuzzer`

Defined in: [src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts:35](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts#L35)

#### Parameters

##### params

###### seed?

`number`

#### Returns

`BlobURLFuzzer`

## Methods

### generateInvalidBlobUrls()

> **generateInvalidBlobUrls**(`params`): `string`[]

Defined in: [src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts:78](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts#L78)

#### Parameters

##### params

###### count

`number`

###### seed?

`number`

#### Returns

`string`[]

#### Implementation of

`blob_url_fuzzer_i.generateInvalidBlobUrls`

***

### generateValidBlobUrls()

> **generateValidBlobUrls**(`params`): `string`[]

Defined in: [src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts:39](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/classes/bloburlfuzzer/BlobURLFuzzer.class.ts#L39)

#### Parameters

##### params

###### count

`number`

###### seed?

`number`

#### Returns

`string`[]

#### Implementation of

`blob_url_fuzzer_i.generateValidBlobUrls`
