base64mix
=========

[![test](https://github.com/mah0x211/base64mix/actions/workflows/test.yml/badge.svg)](https://github.com/mah0x211/base64mix/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/mah0x211/base64mix/branch/master/graph/badge.svg)](https://codecov.io/gh/mah0x211/base64mix)

A C header library for Base64 encoding and decoding with support for standard (RFC 4648) and URL-safe formats.


## Features

- **Header-only library** - Single `base64mix.h` file with inline functions
- **Multiple formats** - Standard Base64, URL-safe Base64, and mixed format support
- **Zero allocation options** - Use your own buffers with `*_to_buffer` functions
- **Memory safe** - Overflow protection and bounds checking


## Installation

base64mix is a header-only library. Simply copy `base64mix.h` to your project and include it:

```c
#include "base64mix.h"
```

No compilation or linking required.


### Basic Encoding

```c
const char *data = "Hello World";
size_t len = strlen(data);

// Standard Base64 encoding (with padding)
char *encoded = b64m_encode_std(data, &len);
printf("Encoded: %s\n", encoded);
free(encoded);

// URL-safe encoding (without padding)
len = strlen(data);
char *url_encoded = b64m_encode_url(data, &len);
printf("URL-safe: %s\n", url_encoded);
free(url_encoded);
```


### Basic Decoding

```c
const char *encoded = "SGVsbG8gV29ybGQ=";
size_t len = strlen(encoded);

// Decode standard Base64
char *decoded = b64m_decode_std(encoded, &len);
printf("Decoded: %.*s\n", (int)len, decoded);
free(decoded);

// Mixed format decoder (handles both standard and URL-safe)
len = strlen(encoded);
char *mixed = b64m_decode_mix(encoded, &len);
free(mixed);
```


### Zero-Allocation API

For performance-critical applications, use the buffer-based functions:

```c
const char *data = "Hello World";
size_t input_len = strlen(data);

// Calculate required buffer size
size_t encoded_size = b64m_encoded_len(input_len) + 1; // +1 for null terminator
char *buffer = malloc(encoded_size);

// Encode to your buffer
size_t actual_len = b64m_encode_to_buffer_std(
    data, input_len, buffer, encoded_size
);

printf("Encoded: %s (length: %zu)\n", buffer, actual_len);
free(buffer);
```

## Encoding Functions

### `char *b64m_encode_std(const char *src, size_t *len)`

Encode binary data to standard Base64 format (with padding).

**Parameters:**

- `src` - Input binary data to encode (must not be NULL)
- `len` - Input/Output: input data length → encoded string length

**Returns:**

- Allocated Base64 string (caller must free), or NULL on error

**Errors:**

- `EINVAL` - Invalid arguments (NULL pointers)
- `ERANGE` - Input size too large (overflow protection)
- `ENOMEM` - Memory allocation failure


### `char *b64m_encode_url(const char *src, size_t *len)`

Encode binary data to URL-safe Base64 format (without padding).

**Parameters:**

- `src` - Input binary data to encode (must not be NULL)
- `len` - Input/Output: input data length → encoded string length

**Returns:**

- Allocated URL-safe Base64 string (caller must free), or NULL on error

**Errors:** Same as `b64m_encode_std`


### `size_t b64m_encode_to_buffer_std(const char *src, size_t srclen, char *dst, size_t dstlen)`

Encode binary data to standard Base64 using user-provided buffer.

**Parameters:**

- `src` - Input binary data to encode (must not be NULL)
- `srclen` - Length of input data
- `dst` - Output buffer for encoded string (must not be NULL)
- `dstlen` - Size of output buffer

**Returns:**

- Length of encoded string (excluding null terminator), or 0 on error

**Errors:**

- `EINVAL` - Invalid arguments (NULL pointers)
- `ENOSPC` - Output buffer too small


### `size_t b64m_encode_to_buffer_url(const char *src, size_t srclen, char *dst, size_t dstlen)`

Encode binary data to URL-safe Base64 using user-provided buffer.

**Parameters:** Same as `b64m_encode_to_buffer_std`
**Returns:** Same as `b64m_encode_to_buffer_std`
**Errors:** Same as `b64m_encode_to_buffer_std`


## Decoding Functions

### `char *b64m_decode_std(const char *src, size_t *len)`

Decode standard Base64 string to binary data.

**Parameters:**

- `src` - Input Base64 string to decode (must not be NULL)
- `len` - Input/Output: input string length → decoded data length

**Returns:**

- Allocated binary data (caller must free), or NULL on error

**Errors:**

- `EINVAL` - Invalid arguments (NULL pointers, invalid characters, malformed padding)
- `ENOMEM` - Memory allocation failure


### `char *b64m_decode_url(const char *src, size_t *len)`

Decode URL-safe Base64 string to binary data.

**Parameters:** Same as `b64m_decode_std`
**Returns:** Same as `b64m_decode_std`
**Errors:** Same as `b64m_decode_std`


### `char *b64m_decode_mix(const char *src, size_t *len)`

Decode mixed format Base64 (handles both standard and URL-safe).

**Parameters:** Same as `b64m_decode_std`
**Returns:** Same as `b64m_decode_std`
**Errors:** Same as `b64m_decode_std`


### `size_t b64m_decode_to_buffer_std(const char *src, size_t srclen, char *dst, size_t dstlen)`

Decode standard Base64 string using user-provided buffer.

**Parameters:**

- `src` - Input Base64 string to decode (must not be NULL)
- `srclen` - Length of input Base64 string
- `dst` - Output buffer for decoded binary data (must not be NULL)
- `dstlen` - Size of output buffer

**Returns:**

- Length of decoded data (excluding null terminator), or 0 on error

**Errors:**
- `EINVAL` - Invalid arguments (NULL pointers, invalid characters, malformed padding)
- `ENOSPC` - Output buffer too small


### `size_t b64m_decode_to_buffer_url(const char *src, size_t srclen, char *dst, size_t dstlen)`

Decode URL-safe Base64 string using user-provided buffer.

**Parameters:** Same as `b64m_decode_to_buffer_std`
**Returns:** Same as `b64m_decode_to_buffer_std`
**Errors:** Same as `b64m_decode_to_buffer_std`


### `size_t b64m_decode_to_buffer_mix(const char *src, size_t srclen, char *dst, size_t dstlen)`

Decode mixed format Base64 using user-provided buffer.

**Parameters:** Same as `b64m_decode_to_buffer_std`
**Returns:** Same as `b64m_decode_to_buffer_std`
**Errors:** Same as `b64m_decode_to_buffer_std`


## Utility Functions

### `size_t b64m_encoded_len(size_t len)`

Calculate required buffer size for Base64 encoding.

**Parameters:**

- `len` - Length of input data to encode

**Returns:**

- Required buffer size for encoded output, or `SIZE_MAX` on overflow

**Note:** Always returns size for padded Base64 (standard format)

### `size_t b64m_decoded_len(size_t enclen)`

Calculate maximum buffer size needed for Base64 decoding.

**Parameters:**

- `enclen` - Length of Base64 encoded string

**Returns:**

- Maximum buffer size needed for decoded output (excluding null terminator)

**Note:** Actual decoded length may be smaller due to padding


## Error Handling

All functions set `errno` on error:

- `EINVAL` - Invalid arguments (NULL pointers, invalid characters, malformed padding)
- `ENOSPC` - Output buffer too small
- `ERANGE` - Input size overflow
- `ENOMEM` - Memory allocation failure

```c
char *result = b64m_encode_std(data, &len);
if (!result) {
    switch (errno) {
        case EINVAL: printf("Invalid input\n"); break;
        case ENOMEM: printf("Out of memory\n"); break;
        case ERANGE: printf("Input too large\n"); break;
    }
}
```

## Building and Testing

```bash
# Run tests with coverage
make test

# Generate HTML coverage report (requires lcov)
make coverage

# Run with Address Sanitizer
make asan

# Clean build artifacts
make clean
```


## License

MIT License - see the header file for full license text.

