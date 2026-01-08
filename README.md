# URLParser

Very (VERY) verbose URL parser intended to search into URLs and gather detailed information. Since a lot of my work involves application analysis and testing, I needed a URL parser which would very carefully examine URLs and format them and their components in a variety of ways. I also typically needed a number of flaggable indicators which I can use to quickly index and search stored results for particular data. A URL database with millions/billions of records is not uncommon, and this code is intended to allow easy storage, indexing, and search of URL sets. Ease of use, and ease of searchability require some degree of data duplication, so parsed URLs from this library are not indented to be the most compact, whereas they're intended to be the most useful for my use cases. We also detail failed URL parses, and have indicator flags regarding where they fail and why. We try to return information about how a parse failed, along with partial data if it's available due to again, this tool intended to be using for security tooling/analysis. A partial parse still has value in my case, but partial parsing is indicated so you can filter for it.

The point is to work in advance to parse any relevant details so we can shove detailed information into the database as it's encountered for later analysis/investigation.

## Install

```bash
npm install @opsimathically/urlparser
```

## Building from source

This package is intended to be run via npm, but if you'd like to build from source,
clone this repo, enter directory, and run `npm install` for dev dependencies, then run
`npm run build`.

## Usage

[See API Reference for documentation](https://github.com/opsimathically/urlparser/docs/)

[See unit tests for more direct usage examples](https://github.com/opsimathically/urlparser/test/index.test.ts)
