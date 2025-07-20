/**
 *  base64mix.h
 *  Created by Masatoshi Teruya on 14/10/23.
 *
 *  Copyright 2014-present Masatoshi Fukunaga. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#ifndef BASE64MIX_H
#define BASE64MIX_H

#include <errno.h>
#include <stdlib.h>

/* Get SIZE_MAX.  */
#ifdef __BIONIC__
# include <limits.h>
#else
# include <stdint.h>
#endif
// https://lists.gnu.org/archive/html/bug-gnulib/2013-01/msg00094.html
// fix include for SIZE_MAX with Bionic libc

/**
 * @name Encoding Tables
 * @{
 */

/** @brief Standard Base64 encoding table (RFC 4648)
 *  Uses '+' and '/' as the last two characters, with '=' padding */
static const unsigned char BASE64MIX_STDENC[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

/** @brief URL-safe Base64 encoding table (RFC 4648)
 *  Uses '-' and '_' as the last two characters, without padding */
static const unsigned char BASE64MIX_URLENC[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};

/** @} */

/**
 * @brief Calculate encoded length for base64 encoding
 *
 * @param len Length of input data to encode
 * @param enctbl Encoding table (BASE64MIX_STDENC or BASE64MIX_URLENC)
 *
 * @return Required buffer size for encoded output (including null terminator)
 *
 * @note For standard base64, includes padding to nearest 4-byte boundary
 * @note For URL-safe base64, no padding is added
 */
static inline size_t b64m_encoded_len(size_t len, const unsigned char enctbl[])
{
    size_t enclen = 0;

    if (len == 0) {
        return 1; // Just null terminator
    } else if (len > (SIZE_MAX / 4)) {
        return 0; // Indicate overflow error
    }

    // Base64 encoding: 3 input bytes -> 4 output bytes
    enclen = (len * 4 + 2) / 3;

    // Add padding only if requested (standard base64)
    if (enctbl == BASE64MIX_STDENC) {
        // Round up to nearest multiple of 4 (base64 padding requirement)
        size_t remainder = enclen % 4;
        if (remainder) {
            enclen += 4 - remainder;
        }
    }

    // Final overflow check
    if (enclen < len) {
        return 0; // Indicate overflow error
    }
    return enclen + 1; // +1 for null terminator
}

/**
 * @name Convenience Macros for Buffer Size Calculation
 * @{
 */

/** @brief Calculate buffer size needed for standard Base64 encoding
 *  @param len Input data length
 *  @return Required buffer size including null terminator */
#define b64m_encoded_len_std(len) b64m_encoded_len(len, BASE64MIX_STDENC)

/** @brief Calculate buffer size needed for URL-safe Base64 encoding
 *  @param len Input data length
 *  @return Required buffer size including null terminator */
#define b64m_encoded_len_url(len) b64m_encoded_len(len, BASE64MIX_URLENC)

/** @} */

/**
 * @brief Encode binary data to base64 string using user-provided buffer
 *
 * @param src Input binary data to encode (must not be NULL)
 * @param srclen Length of input data
 * @param dst Output buffer for encoded string (must not be NULL)
 * @param dstlen Size of output buffer
 * @param enctbl Encoding table (BASE64MIX_STDENC or BASE64MIX_URLENC)
 *
 * @return Length of encoded string (excluding null terminator), or 0 on error
 *
 * @errno EINVAL - Invalid arguments (NULL pointers)
 * @errno ENOSPC - Output buffer too small
 *
 * @note Zero-allocation version: uses caller-provided buffer
 * @note Buffer size can be calculated with b64m_encoded_len()
 * @note Result is always null-terminated
 */
static inline size_t b64m_encode_to_buffer(const unsigned char *src,
                                           size_t srclen, char *dst,
                                           size_t dstlen,
                                           const unsigned char enctbl[])
{
    const uint8_t *cur = src;
    unsigned char *ptr = (unsigned char *)dst;
    size_t remain      = 0;
    size_t i           = 0;

    // Validate input parameters
    if (!src || !dst || !enctbl) {
        errno = EINVAL;
        return 0;
    }

    // Check if we have enough space
    if (dstlen < b64m_encoded_len(srclen, enctbl)) {
        errno = ENOSPC;
        return 0;
    }

    // Handle empty input
    if (srclen == 0) {
        *dst = '\0';
        return 0;
    }

    // Process complete 3-byte groups with 4-block unrolling optimization

#define ENCODE_BLOCK(v, out)                                                   \
    do {                                                                       \
        (out)[0] = enctbl[(v >> 18) & 0x3f];                                   \
        (out)[1] = enctbl[(v >> 12) & 0x3f];                                   \
        (out)[2] = enctbl[(v >> 6) & 0x3f];                                    \
        (out)[3] = enctbl[v & 0x3f];                                           \
    } while (0)

    i = 0;
    // Process 4 blocks (12 bytes -> 16 chars) at a time for better performance
    size_t blocks_4 =
        (srclen / 12) * 12; // Number of bytes in complete 4-block groups
    for (; i < blocks_4; i += 12) {
        // Process 4 blocks simultaneously
        uint32_t val0 =
            ((uint32_t)cur[0] << 16) | ((uint32_t)cur[1] << 8) | cur[2];
        uint32_t val1 =
            ((uint32_t)cur[3] << 16) | ((uint32_t)cur[4] << 8) | cur[5];
        uint32_t val2 =
            ((uint32_t)cur[6] << 16) | ((uint32_t)cur[7] << 8) | cur[8];
        uint32_t val3 =
            ((uint32_t)cur[9] << 16) | ((uint32_t)cur[10] << 8) | cur[11];

        ENCODE_BLOCK(val0, ptr);
        ENCODE_BLOCK(val1, ptr + 4);
        ENCODE_BLOCK(val2, ptr + 8);
        ENCODE_BLOCK(val3, ptr + 12);

        ptr += 16; // Move pointer forward by 16 bytes
        cur += 12; // Move input pointer forward by 12 bytes
    }

    // Process remaining single blocks (3 bytes -> 4 chars)
    for (size_t n = (srclen / 3) * 3; i < n; i += 3) {
        uint32_t val =
            ((uint32_t)cur[0] << 16) | ((uint32_t)cur[1] << 8) | cur[2];
        ENCODE_BLOCK(val, ptr);
        ptr += 4;
        cur += 3;
    }

#undef ENCODE_BLOCK

    // Handle remaining bytes
    remain = srclen - i;
    if (remain > 0) {
        // Add the remaining small block
        uint32_t val = (uint32_t)cur[0] << 16;
        if (remain == 2) {
            // If we have 2 bytes left, shift the second byte
            val |= (uint32_t)cur[1] << 8;
        }

        // Encode the remaining bytes
        *ptr++ = enctbl[(val >> 18) & 0x3fU];
        *ptr++ = enctbl[(val >> 12) & 0x3fU];

        // Add remaining characters and padding
        if (remain == 2) {
            *ptr++ = enctbl[(val >> 6) & 0x3fU];
            if (enctbl == BASE64MIX_STDENC) {
                *ptr++ = '=';
            }
        } else if (remain == 1 && enctbl == BASE64MIX_STDENC) {
            *ptr++ = '=';
            *ptr++ = '=';
        }
    }

    // Null terminate
    *ptr = '\0';

    return (size_t)(ptr - (unsigned char *)dst);
}

/**
 * @name Convenience Macros for Buffer Encoding
 * @{
 */

/** @brief Encode to user buffer using standard Base64 format
 *  @param src Input binary data
 *  @param srclen Input data length
 *  @param dst Output buffer
 *  @param dstlen Output buffer size
 *  @return Length of encoded string or 0 on error */
#define b64m_encode_to_buffer_std(src, srclen, dst, dstlen)                    \
    b64m_encode_to_buffer(src, srclen, dst, dstlen, BASE64MIX_STDENC)

/** @brief Encode to user buffer using URL-safe Base64 format
 *  @param src Input binary data
 *  @param srclen Input data length
 *  @param dst Output buffer
 *  @param dstlen Output buffer size
 *  @return Length of encoded string or 0 on error */
#define b64m_encode_to_buffer_url(src, srclen, dst, dstlen)                    \
    b64m_encode_to_buffer(src, srclen, dst, dstlen, BASE64MIX_URLENC)

/** @} */

/**
 * @brief Encode binary data to base64 string
 *
 * @param src Input binary data to encode (must not be NULL)
 * @param len Input/Output: input data length -> encoded string length
 * @param enctbl Encoding table (BASE64MIX_STDENC or BASE64MIX_URLENC)
 *
 * @return Allocated base64 string (caller must free), or NULL on error
 *
 * @errno EINVAL - Invalid arguments (NULL pointers)
 * @errno ERANGE - Input size too large (overflow protection)
 * @errno ENOMEM - Memory allocation failure
 *
 * @note Empty input (len=0) returns empty string, not NULL
 * @note Standard encoding adds padding, URL-safe encoding does not
 * @note Result is always null-terminated for safe string handling
 */
static inline char *b64m_encode(const unsigned char *src, size_t *len,
                                const unsigned char enctbl[])
{
    char *res     = NULL;
    size_t buflen = 0;

    // Validate input parameters
    if (!src || !len || !enctbl) {
        errno = EINVAL;
        return NULL;
    }

    // Calculate required buffer size using zero-allocation helper
    buflen = b64m_encoded_len(*len, enctbl);
    // Check for overflow (buflen of 0 indicates overflow)
    if (buflen == 0) {
        errno = ERANGE;
        return NULL;
    }

    // Allocate buffer
    if ((res = malloc(buflen))) {
        // Use zero-allocation version to do the actual encoding
        // Update length with actual encoded length
        *len = b64m_encode_to_buffer(src, *len, res, buflen, enctbl);
    }
    return res;
}
/**
 * @name Convenience Macros
 * @{
 */

/** @brief Encode using standard Base64 format (with padding)
 *  @param src Input binary data
 *  @param len Input/Output length pointer
 *  @return Encoded string or NULL on error */
#define b64m_encode_std(src, len) b64m_encode(src, len, BASE64MIX_STDENC)

/** @brief Encode using URL-safe Base64 format (without padding)
 *  @param src Input binary data
 *  @param len Input/Output length pointer
 *  @return Encoded string or NULL on error */
#define b64m_encode_url(src, len) b64m_encode(src, len, BASE64MIX_URLENC)

/** @} */

/**
 * @name Decoding Tables
 * @{
 */

/** @brief Standard Base64 decoding table
 *  @note Uses -1 (becomes 255 when cast to unsigned char) for invalid
 * characters. Valid Base64 values are 0-63, so 255 is safely distinguishable.
 */
static const unsigned char BASE64MIX_STDDEC[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    //  SP   !   "   #   $   %   &   '   (    )    *   +   ,    -    .   /
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    //   0   1   2   3   4   5   6   7   8   9
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    //   :   ;   <   =   >   ?   @
    -1, -1, -1, -1, -1, -1, -1,
    //  A  B  C  D  E  F  G  H  I  J   K   L   M   N   O   P   Q   R   S   T   U
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    //   V   W   X   Y   Z
    21, 22, 23, 24, 25,
    //   [   \   ]   ^   _   `
    -1, -1, -1, -1, -1, -1,
    //   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o   p   q   r s
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    //   t   u   v   w   x   y   z
    45, 46, 47, 48, 49, 50, 51,
    //   {   |   }   ~
    -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

/** @brief URL-safe Base64 decoding table
 *  @note Uses -1 (becomes 255 when cast to unsigned char) for invalid
 * characters. Accepts '-' and '_' instead of '+' and '/'. */
static const unsigned char BASE64MIX_URLDEC[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    //  SP   !   "   #   $   %   &   '   (    )    *   +   ,    -    .   /
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    //   0   1   2   3   4   5   6   7   8   9
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    //   :   ;   <   =   >   ?   @
    -1, -1, -1, -1, -1, -1, -1,
    //  A  B  C  D  E  F  G  H  I  J   K   L   M   N   O   P   Q   R   S   T   U
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    //   V   W   X   Y   Z
    21, 22, 23, 24, 25,
    //   [   \   ]   ^   _   `
    -1, -1, -1, -1, 63, -1,
    //   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o   p   q   r s
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    //   t   u   v   w   x   y   z
    45, 46, 47, 48, 49, 50, 51,
    //   {   |   }   ~
    -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

/** @brief Mixed format Base64 decoding table (handles both standard and
 * URL-safe)
 *  @note Uses -1 (becomes 255 when cast to unsigned char) for invalid
 * characters. Accepts both '+' and '-' at position 62, both '/' and '_' at
 * position 63. */
static const unsigned char BASE64MIX_DEC[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,

    //  SP   !   "   #   $   %   &   '   (    )    *   +   ,    -    .   /
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
    //   0   1   2   3   4   5   6   7   8   9
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    //   :   ;   <   =   >   ?   @
    -1, -1, -1, -1, -1, -1, -1,
    //  A  B  C  D  E  F  G  H  I  J   K   L   M   N   O   P   Q   R   S   T   U
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    //   V   W   X   Y   Z
    21, 22, 23, 24, 25,
    //   [   \   ]   ^   _   `
    -1, -1, -1, -1, 63, -1,
    //   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o   p   q   r s
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    //   t   u   v   w   x   y   z
    45, 46, 47, 48, 49, 50, 51,
    //   {   |   }   ~
    -1, -1, -1, -1,

    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

/**
 * @brief Decode base64 string to binary data
 *
 * @param src Input base64 string to decode (must not be NULL)
 * @param len Input/Output: input string length -> decoded data length
 * @param dectbl Decoding table (BASE64MIX_STDDEC, BASE64MIX_URLDEC, or
 * BASE64MIX_DEC)
 *
 * @return Allocated binary data (caller must free), or NULL on error
 *
 * @errno EINVAL - Invalid arguments (NULL pointers)
 * @errno EINVAL - Invalid base64 character encountered
 * @errno EINVAL - Invalid padding format (non-'=' after '=')
 * @errno ENOMEM - Memory allocation failure
 *
 * @note Handles both standard (with padding) and URL-safe (without padding)
 * formats
 * @note Result buffer is null-terminated for safety (length excludes
 * terminator)
 * @note Incomplete groups (1 char) are silently ignored as invalid
 */
static inline char *b64m_decode(const unsigned char *src, size_t *len,
                                const unsigned char dectbl[])
{
    unsigned char *res = NULL;
    size_t bytes       = 0;

    // Validate input parameters
    if (!src || !len || !dectbl) {
        errno = EINVAL;
        return NULL;
    }

    // Base64 decoding: 4 input bytes -> 3 output bytes (maximum)
    // Use integer arithmetic for precision and performance
    bytes = (*len * 3) / 4;

    if ((res = malloc(bytes + 1))) {
        const uint8_t *cur = src;
        unsigned char *ptr = res;
        uint8_t c          = 0;
        // 24-bit accumulator with sentinel bit for tracking completeness
        // Bit layout: [sentinel][23..18][17..12][11..6][5..0]
        // Each base64 char contributes 6 bits, 4 chars = 24 bits = 3 bytes
        uint32_t bit24     = 1; // Start with sentinel bit at position 0
        size_t tail        = *len;
        size_t i           = 0;

        for (; i < tail; i++) {
            // ignore padding
            if (*cur == '=') {
                // check remaining characters with proper bounds checking
                for (i++; i < tail; i++) {
                    cur++;
                    // remaining characters must be '='
                    if (*cur != '=') {
                        free((void *)res);
                        errno = EINVAL;
                        return NULL;
                    }
                }
                break;
            }
            // invalid character (valid base64 decode values are 0-63)
            else if ((c = dectbl[*cur]) > 63) {
                free((void *)res);
                errno = EINVAL;
                return NULL;
            }
            // Accumulate 6 bits from current base64 character
            // bit24 layout after each character:
            // 1st char: [1][000000][000000][000000][AAAAAA]
            // 2nd char: [1][000000][000000][AAAAAA][BBBBBB]
            // 3rd char: [1][000000][AAAAAA][BBBBBB][CCCCCC]
            // 4th char: [1][AAAAAA][BBBBBB][CCCCCC][DDDDDD] -> triggers
            // extraction
            bit24 = bit24 << 6 | c;
            // Check if sentinel bit reached position 24 (4 chars accumulated)
            if (bit24 & 0x1000000) {
                // Extract 3 bytes from accumulated 24 bits
                // [AAAAAA|BBBBBB] [BBBBBB|CCCCCC] [CCCCCC|DDDDDD]
                *ptr++ = bit24 >> 16; // Extract first byte: [AAAAAA|BB]
                *ptr++ = bit24 >> 8;  // Extract second byte: [BBBB|CCCC]
                *ptr++ = bit24;       // Extract third byte: [CC|DDDDDD]
                bit24  = 1;           // Reset with sentinel bit at position 0
            }
            cur++;
        }

        // Handle remaining bits for incomplete groups (due to padding)
        // Check sentinel bit position to determine how many chars were
        // accumulated
        if (bit24 & 0x40000) {
            // 3 base64 chars accumulated: [1][AAAAAA][BBBBBB][CCCCCC][000000]
            // 18 valid bits = 2 complete bytes + 2 padding bits (ignored)
            // Extract: [AAAAAA|BBBBBB] [BBBBBB|CCCCCC]
            *ptr++ = bit24 >> 10; // First byte: bits [17..10] = [AAAAAA|BB]
            *ptr++ = bit24 >> 2;  // Second byte: bits [9..2] = [BBBB|CCCC]
            // Ignore bits [1..0] as padding
        } else if (bit24 & 0x1000) {
            // 2 base64 chars accumulated: [1][AAAAAA][BBBBBB][000000][000000]
            // 12 valid bits = 1 complete byte + 4 padding bits (ignored)
            // Extract: [AAAAAA|BBBBBB]
            *ptr++ = bit24 >> 4; // Single byte: bits [11..4] = [AAAAAA|BB]
            // Ignore bits [3..0] as padding
        }
        // If bit24 & 0x40 (only 1 char), ignore as invalid incomplete group
        *ptr = 0;
        // set result length
        *len = (size_t)(ptr - res);
    }

    return (char *)res;
}

/**
 * @name Decode Convenience Macros
 * @{
 */

/** @brief Decode standard Base64 format (expects padding)
 *  @param src Input base64 string
 *  @param len Input/Output length pointer
 *  @return Decoded binary data or NULL on error */
#define b64m_decode_std(src, len) b64m_decode(src, len, BASE64MIX_STDDEC)

/** @brief Decode URL-safe Base64 format (no padding expected)
 *  @param src Input base64 string
 *  @param len Input/Output length pointer
 *  @return Decoded binary data or NULL on error */
#define b64m_decode_url(src, len) b64m_decode(src, len, BASE64MIX_URLDEC)

/** @brief Decode mixed format (handles both standard and URL-safe)
 *  @param src Input base64 string
 *  @param len Input/Output length pointer
 *  @return Decoded binary data or NULL on error */
#define b64m_decode_mix(src, len) b64m_decode(src, len, BASE64MIX_DEC)

/** @} */

#endif /* BASE64MIX_H */
