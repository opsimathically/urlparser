[**@opsimathically/urlparser**](../README.md)

***

[@opsimathically/urlparser](../README.md) / urlparsed\_domain\_result\_t\_zods

# Variable: urlparsed\_domain\_result\_t\_zods

> `const` **urlparsed\_domain\_result\_t\_zods**: `ZodObject`\<\{ `domain`: `ZodString`; `errors`: `ZodArray`\<`ZodObject`\<\{ `column`: `ZodNumber`; `message`: `ZodString`; `type`: `ZodString`; \}, `$strip`\>\>; `hostname`: `ZodString`; `icann`: `ZodObject`\<\{ `domain`: `ZodString`; `subdomains`: `ZodArray`\<`ZodString`\>; `top_level_domains`: `ZodArray`\<`ZodString`\>; \}, `$strip`\>; `labels`: `ZodArray`\<`ZodString`\>; `subdomains`: `ZodArray`\<`ZodString`\>; `top_level_domains`: `ZodArray`\<`ZodString`\>; `type`: `ZodUnion`\<readonly \[`ZodLiteral`\<`"INVALID"`\>, `ZodLiteral`\<`"IP"`\>, `ZodLiteral`\<`"RESERVED"`\>, `ZodLiteral`\<`"NOT_LISTED"`\>, `ZodLiteral`\<`"LISTED"`\>\]\>; \}, `$strip`\>

Defined in: [src/zod\_type\_validators/custom\_ts\_to\_zod\_generated\_validators.ts:10](https://github.com/opsimathically/urlparser/blob/f9480a12b1036ac329dd921b72cb40c95bc77766/src/zod_type_validators/custom_ts_to_zod_generated_validators.ts#L10)
