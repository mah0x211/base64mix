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
    unsigned char *res = NULL;
    size_t tail        = 0;
    size_t bytes       = 0;

    // Validate input parameters
    if (!src || !len || !enctbl) {
        errno = EINVAL;
        return NULL;
    }
    tail = *len;

    // return empty string for zero length input
    if (tail == 0) {
        if ((res = malloc(1))) {
            *res = '\0';
            *len = 0;
        }
        return (char *)res;
    }

    // Check for overflow before calculation
    if (tail > (SIZE_MAX / 4)) {
        errno = ERANGE;
        return NULL;
    }

    // Base64 encoding: 3 input bytes -> 4 output bytes
    // Formula: (len * 4 + 2) / 3 handles padding correctly
    bytes = (tail * 4 + 2) / 3;

    // Add padding only if requested (standard base64)
    if (enctbl == BASE64MIX_STDENC) {
        // Round up to nearest multiple of 4 (base64 padding requirement)
        size_t remainder = bytes % 4;
        if (remainder) {
            bytes += 4 - remainder;
        }
    }

    // Final overflow check
    if (bytes < tail) {
        errno = ERANGE;
        return NULL;
    }

    if ((res = malloc(bytes + 1))) {
        const unsigned char *cur = src;
        unsigned char *ptr       = res;
        uint8_t c                = -1;
        uint8_t state            = 0;
        size_t i                 = 0;

        for (; i < tail; i++) {
            switch (state) {
            case 0:
                // State 0: Process first byte of 3-byte input group
                // Produces: first complete base64 character + partial second
                // character Input:  [AAAAAABB] Output: [AAAAAA] -> first base64
                // char, [BB????] -> partial second char
                c      = (*cur >> 2) & 0x3f; // Extract upper 6 bits: AAAAAA
                *ptr++ = enctbl[c];
                c = (*cur & 0x3) << 4; // Extract lower 2 bits: BB, shift left
                state = 1;
                break;
            case 1:
                // State 1: Process second byte of 3-byte input group
                // Completes: second base64 character + partial third character
                // Input:  [CCCCDDDD]
                // Combine: [BB????] + [CCCC] -> [BBCCCC] -> second base64 char
                // Prepare: [DDDD??] -> partial third char
                c |= (*cur >> 4) & 0xf; // Combine: BB + CCCC -> BBCCCC
                *ptr++ = enctbl[c];
                c = (*cur & 0xf) << 2; // Extract lower 4 bits: DDDD, shift left
                state = 2;
                break;
            case 2:
                // State 2: Process third byte of 3-byte input group
                // Completes: third base64 character + fourth base64 character
                // Input:  [EEFFFFFFFF]
                // Combine: [DDDD??] + [EE] -> [DDDDEE] -> third base64 char
                // Extract: [FFFFFF] -> fourth base64 char
                // Result: 3 input bytes -> 4 output base64 characters
                c |= (*cur >> 6) & 0x3; // Combine: DDDD + EE -> DDDDEE
                *ptr++ = enctbl[c];
                c      = *cur & 0x3f; // Extract lower 6 bits: FFFFFF
                *ptr++ = enctbl[c];
                // Reset state and restart 3-byte cycle
                c      = -1;
                state  = 0;
                break;
            }
            cur++;
        }

        // append last bit if there's remaining data
        if (c != (uint8_t)-1) {
            *ptr++ = enctbl[c];
        }
        // append padding if standard base64
        if (enctbl == BASE64MIX_STDENC) {
            for (i = ptr - res; i < bytes; i++) {
                *ptr++ = '=';
            }
        }
        // set result length
        *len = ptr - res;
        *ptr = 0;
    }

    return (char *)res;
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
        const unsigned char *cur = src;
        unsigned char *ptr       = res;
        uint8_t c                = 0;
        // 24-bit accumulator with sentinel bit for tracking completeness
        // Bit layout: [sentinel][23..18][17..12][11..6][5..0]
        // Each base64 char contributes 6 bits, 4 chars = 24 bits = 3 bytes
        uint32_t bit24           = 1; // Start with sentinel bit at position 0
        size_t tail              = *len;
        size_t i                 = 0;

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
        *len = ptr - res;
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
