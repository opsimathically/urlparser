export const isEmpty = function (test_if_this_is_empty: any): boolean {
  // null values are considered empty
  if (test_if_this_is_empty === null) return true;

  // undefined values are considered empty
  if (typeof test_if_this_is_empty === 'undefined') return true;

  // zero length strings are considered empty
  if (typeof test_if_this_is_empty === 'string') {
    if (test_if_this_is_empty == '') return true;
    if (test_if_this_is_empty.length === 0) return true;
  }

  // zero length arrays are considered empty
  if (Array.isArray(test_if_this_is_empty) === true) {
    if (test_if_this_is_empty.length === 0) return true;
  }

  // check if it's an empty buffer
  if (Buffer.isBuffer(test_if_this_is_empty) === true) {
    if (Buffer.length <= 0) return true;
    else return false;
  }

  // object with no keys is considered empty
  if (typeof test_if_this_is_empty === 'object') {
    // Ensure the prototype is exactly Object.prototype
    // so things like Object.create(null) are NOT treated as empty objects.
    if (Object.getPrototypeOf(test_if_this_is_empty) !== Object.prototype) {
      return false;
    }

    // No own string keys
    if (Object.keys(test_if_this_is_empty).length !== 0) {
      return false;
    }

    // No own symbol keys
    if (Object.getOwnPropertySymbols(test_if_this_is_empty).length !== 0) {
      return false;
    }

    // check if this is a regular expression
    if (test_if_this_is_empty instanceof RegExp) return false;

    // check if we have a getMonth property
    let has_get_month = false;
    try {
      if (typeof test_if_this_is_empty.getMonth === 'function') {
        has_get_month = true;
      }
    } catch (err) {
      if (err) return false;
    }
    if (has_get_month === true) return false;

    // check if it's an empty object with no keys
    let key_length = 0;
    try {
      key_length = Object.keys(test_if_this_is_empty).length;
    } catch (err) {
      if (err) return true;
    }
    if (key_length === 0) return true;
  }

  // the tested value is not empty
  return false;
};

// check if an arbitrary parameter is not empty
export const isNotEmpty = function (test_if_this_is_empty: any): boolean {
  return !isEmpty(test_if_this_is_empty);
};

// Check if any of the values in the array are empty.
export const valuesAreEmpty = function (
  array_of_values_to_check: Array<any>
): boolean {
  if (Array.isArray(array_of_values_to_check) !== true) return true;
  if (array_of_values_to_check.length === 0) return true;

  for (const array_idx in array_of_values_to_check) {
    if (isEmpty(array_of_values_to_check[array_idx]) !== true) return false;
  }

  return true;
};

export const valuesAreNotEmpty = function (
  array_of_values_to_check: Array<any>
): boolean {
  if (Array.isArray(array_of_values_to_check) !== true) return true;
  if (array_of_values_to_check.length === 0) return false;

  for (const array_idx in array_of_values_to_check) {
    if (isNotEmpty(array_of_values_to_check[array_idx]) !== true) return false;
  }

  return true;
};

// check if single value is a non-empty string
export const isNonEmptyString = function (val: any): boolean {
  if (typeof val !== 'string') return false;
  if (val.length <= 0) return false;
  return true;
};

// Check if values are not empty strings
export const valuesAreNonEmptyStrings = function (vals: any): boolean {
  if (Array.isArray(vals) !== true) return false;
  if (vals.length <= 0) return false;

  // iterate vals and run checks
  for (let idx = 0; idx < vals.length; idx++) {
    if (typeof vals[idx] !== 'string') return false;
    if (vals[idx].length <= 0) return false;
  }
  return true;
};
