#ifndef HMAC_H 
#define HMAC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/hmac.h>

void hmac_sha256(
    const unsigned char *key,
    int                  key_len,
    const unsigned char *text,
    int                  text_len,
    void                *digest);
#endif
