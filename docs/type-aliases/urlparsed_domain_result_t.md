[**@opsimathically/urlparser**](../README.md)

***

[@opsimathically/urlparser](../README.md) / urlparsed\_domain\_result\_t

# Type Alias: urlparsed\_domain\_result\_t

> **urlparsed\_domain\_result\_t** = `object`

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:21](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L21)

## Properties

### domain

> **domain**: `string`

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:27](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L27)

***

### errors

> **errors**: [`parse_domain_validation_error`](parse_domain_validation_error.md)[]

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:24](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L24)

***

### hostname

> **hostname**: `string`

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:23](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L23)

***

### icann

> **icann**: `object`

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:29](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L29)

#### domain

> **domain**: `string`

#### subdomains

> **subdomains**: `string`[]

#### top\_level\_domains

> **top\_level\_domains**: `string`[]

***

### labels

> **labels**: `string`[]

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:25](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L25)

***

### subdomains

> **subdomains**: `string`[]

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:26](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L26)

***

### top\_level\_domains

> **top\_level\_domains**: `string`[]

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:28](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L28)

***

### type

> **type**: `"INVALID"` \| `"IP"` \| `"RESERVED"` \| `"NOT_LISTED"` \| `"LISTED"`

Defined in: [src/types/custom\_zod\_types/custom\_zod\_types.d.ts:22](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/types/custom_zod_types/custom_zod_types.d.ts#L22)
