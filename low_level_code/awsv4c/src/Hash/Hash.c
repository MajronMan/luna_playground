#include "Hash.h"


Hash Hash_new(const char *hash_name) {
    Hash h;
    h.type = EVP_get_digestbyname(hash_name);
    if (!h.type) {
        fprintf(stderr, "Unknown hash type %s\n", hash_name);
        exit(EXIT_FAILURE);
    }
    h.bin = StrLen_new(EVP_MAX_MD_SIZE - LEN("\0"));
    h.hex_str = StrLen_new(2 * EVP_MAX_MD_SIZE);
    return h;
}

void Hash_free(Hash *hash) {
    free(hash->bin.str);
    free(hash->hex_str.str);
}

void Hash_digest(Hash *hash, const StrLen msg) {
    EVP_MD_CTX *md_ctx;
    int ret;

    md_ctx = EVP_MD_CTX_new();
    if ((ret = EVP_DigestInit_ex(md_ctx, hash->type, NULL)) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex: error return value %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = EVP_DigestUpdate(md_ctx, msg.str, msg.len)) != 1) {
        fprintf(stderr, "EVP_DigestUpdate: error return value %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = EVP_DigestFinal_ex(md_ctx,
                                  (unsigned char *) hash->bin.str,
                                  (unsigned int *) &hash->bin.len)) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex: error return value %d\n", ret);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(md_ctx);
}

void Hash_hmac(Hash *hash, const StrLen key, const StrLen msg) {
    if (!HMAC(hash->type,
              key.str,
              (int) key.len,
              (const unsigned char *) msg.str,
              msg.len,
              (unsigned char *) hash->bin.str,
              (unsigned int *) &hash->bin.len)) {
        fprintf(stderr, "HMAC: unknown error\n");
        exit(EXIT_FAILURE);
    }
}

void Hash_hex_str(Hash *hash) {
    char *dest = hash->hex_str.str;
    size_t i = 0;
    for (; i < hash->bin.len; ++i) {
        sprintf(dest, "%02x", (unsigned char) hash->bin.str[i]);
        dest += 2;
    }
    hash->hex_str.len = 2 * hash->bin.len;
}
