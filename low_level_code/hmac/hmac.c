#include "hmac.h"

void hmac_sha256(
    const unsigned char *key,
    int                  key_len,
    const unsigned char *text,
    int                  text_len,
    void                *digest)
{
    unsigned int result_len;
    unsigned char result[EVP_MAX_MD_SIZE];

    HMAC(EVP_sha256(),
         key, key_len,
         text, text_len,
         result, &result_len);
    memcpy(digest, result, result_len);
}
