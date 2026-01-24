export const stringEndsWith = function (
  str: string,
  ends_with: string
): boolean {
  if (str.substring(str.length - ends_with.length) == ends_with) return true;
  return false;
};

export const extractNumericStrings = function (input: string): string[] | null {
  if (!input) return null;
  const matches: RegExpMatchArray | null = input.match(/\d+/g);
  return matches ? matches : null;
};

export const extractNonNumericStrings = function (
  input: string
): string[] | null {
  const parts: string[] = input.split(/\d+/).filter((part) => part.length > 0);
  return parts.length > 0 ? parts : null;
};

export const extractNonNumericStringsLowercase = function (
  input: string
): string[] | null {
  const parts: string[] = input
    .split(/\d+/)
    .map((part) => part.toLowerCase())
    .filter((part) => part.length > 0);

  return parts.length > 0 ? parts : null;
};

export const extractAlphabeticStrings = function (
  input: string
): string[] | null {
  const matches: RegExpMatchArray | null = input.match(/[A-Za-z]+/g);
  return matches ? matches : null;
};

export const extractAlphabeticStringsLowercase = function (
  input: string
): string[] | null {
  const matches: RegExpMatchArray | null = input.match(/[A-Za-z]+/g);
  return matches ? matches.map((part) => part.toLowerCase()) : null;
};

export const extractNonAlphanumericStrings = function (
  input: string
): string[] | null {
  const matches: RegExpMatchArray | null = input.match(/[^A-Za-z0-9]+/g);
  return matches ? matches : null;
};

export const extractUniqueCharacters = function (input: string): string[] {
  const seen = new Set<string>();
  let result: string[] = [];

  for (const char of input) {
    if (!seen.has(char)) {
      seen.add(char);
      result.push(char);
    }
  }
  if (result.length) result = result.toSorted();
  return result;
};
