#ifndef BASE64_H_
#define BASE64_H_

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

void base64_encode(const unsigned char* input, int input_len, char* output, int output_len);

int base64_decode(const char* input, int input_len, unsigned char* output, int output_len);

#ifdef __cplusplus
}
#endif

#endif  // BASE64_H_
