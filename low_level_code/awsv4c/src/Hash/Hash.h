#ifndef AWSV4_C_HASH_H
#define AWSV4_C_HASH_H

#include <stdlib.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "../StrLen/StrLen.h"


typedef struct {
    const EVP_MD *type;
    StrLen bin;
    StrLen hex_str;
} Hash;

Hash Hash_new(const char *hash_name);

void Hash_free(Hash *hash);

void Hash_digest(Hash *hash, StrLen msg);

void Hash_hmac(Hash *hash, StrLen key, StrLen msg);

void Hash_hex_str(Hash *hash);


#endif /* AWSV4_C_HASH_H */
