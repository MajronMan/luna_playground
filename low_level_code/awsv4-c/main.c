#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <curl/curl.h>


#define LEN(str) (sizeof(str) - /* '\0' */ 1)

#define HASH_NAME ("sha256")
#define SIGN_ALGORITHM ("AWS4-HMAC-SHA256")

#define AMZDATE_FORMAT ("YYYYMMDDTHHMMSSZ")
#define DATESTAMP_FORMAT ("YYYYMMDD")

#define AWS_ACCESS_KEY_LEN (20)
#define AWS_SECRET_KEY_LEN (40)

#define SIGNED_HEADERS ("content-type;host;x-amz-date")


typedef struct {
    char *str;
    size_t len;
} StrLen;

StrLen StrLen_new(const size_t len) {
    StrLen s;
    s.str = calloc(len + LEN("\0"), sizeof(char));
    s.len = len;
    return s;
}

StrLen StrLen_const(char *const str, const size_t len) {
    StrLen s;
    s.str = str;
    s.len = len;
    return s;
}

#define StrLen_of(static_str) StrLen_const(static_str, LEN(static_str))


typedef struct {
    const EVP_MD *type;
    StrLen bin;
    StrLen hex_str;
} Hash;

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

void get_aws_credentials(StrLen *aws_access_key, StrLen *aws_secret_key) {
    *aws_access_key = StrLen_const(getenv("AWS_ACCESS_KEY"), AWS_ACCESS_KEY_LEN);
    *aws_secret_key = StrLen_const(getenv("AWS_SECRET_KEY"), AWS_SECRET_KEY_LEN);

    if (aws_access_key->str == NULL || aws_secret_key->str == NULL) {
        fprintf(stderr, "Set AWS credentials:\n"
                        "  export AWS_ACCESS_KEY=<your_access_key_id>\n"
                        "  export AWS_SECRET_KEY=<your_secret_access_key>\n");
        exit(EXIT_FAILURE);
    }
}

StrLen get_amzdate() {
    StrLen amzdate = StrLen_new(LEN(AMZDATE_FORMAT));
    time_t t = time(NULL);
    struct tm *tmp = gmtime(&t);
    strftime(amzdate.str, amzdate.len + LEN("\0"), "%Y%m%dT%H%M%SZ", tmp);
    return amzdate;
}

StrLen get_datestamp(const StrLen amzdate) {
    StrLen datestamp = StrLen_new(LEN(DATESTAMP_FORMAT));
    memcpy(datestamp.str, amzdate.str, datestamp.len);
    datestamp.str[datestamp.len] = '\0';
    return datestamp;
}

StrLen get_canon_request_hash_hex_str(Hash *hash,
                                      const StrLen http_method,
                                      const StrLen canon_uri,
                                      const StrLen canon_query,
                                      const StrLen content_type,
                                      const StrLen host,
                                      const StrLen amzdate,
                                      const StrLen body) {

    size_t canon_headers_len = LEN("content-type:") + content_type.len + LEN("\n") +
                               +LEN("host:") + host.len + LEN("\n")
                               + LEN("x-amz-date:") + amzdate.len + LEN("\n");
    size_t canon_request_len;
    StrLen canon_request;
    StrLen canon_request_hash_hex_str;

    Hash_digest(hash, body);
    Hash_hex_str(hash);

    canon_request_len = http_method.len + LEN("\n")
                        + canon_uri.len + LEN("\n")
                        + canon_query.len + LEN("\n")
                        + canon_headers_len + LEN("\n")
                        + LEN(SIGNED_HEADERS) + LEN("\n")
                        + hash->hex_str.len;
    canon_request = StrLen_new(canon_request_len);

    sprintf(canon_request.str,
            "%s\n%s\n%s\ncontent-type:%s\nhost:%s\nx-amz-date:%s\n\n%s\n%s",
            http_method.str,
            canon_uri.str,
            canon_query.str,
            /* header */ content_type.str,
            /* header */ host.str,
            /* header */ amzdate.str,
            SIGNED_HEADERS,
            hash->hex_str.str);

    Hash_digest(hash, canon_request);
    Hash_hex_str(hash);

    free(canon_request.str);

    canon_request_hash_hex_str = StrLen_new(hash->hex_str.len);
    strcpy(canon_request_hash_hex_str.str, hash->hex_str.str);

    return canon_request_hash_hex_str;
}

StrLen get_credential_scope(const StrLen datestamp,
                            const StrLen region,
                            const StrLen service) {

    size_t credential_scope_len = datestamp.len + LEN("/")
                                  + region.len + LEN("/")
                                  + service.len + LEN("/aws4_request");
    StrLen credential_scope = StrLen_new(credential_scope_len);

    sprintf(credential_scope.str, "%s/%s/%s/aws4_request",
            datestamp.str,
            region.str,
            service.str);

    return credential_scope;
}

StrLen get_str_to_sign(const StrLen amzdate,
                       const StrLen credential_scope,
                       const StrLen canon_request_hash_hex_str) {

    size_t str_to_sign_len = LEN(SIGN_ALGORITHM) + LEN("\n")
                             + amzdate.len + LEN("\n")
                             + credential_scope.len + LEN("\n")
                             + canon_request_hash_hex_str.len;
    StrLen str_to_sign = StrLen_new(str_to_sign_len);

    sprintf(str_to_sign.str, "%s\n%s\n%s\n%s",
            SIGN_ALGORITHM,
            amzdate.str,
            credential_scope.str,
            canon_request_hash_hex_str.str);

    return str_to_sign;
}

StrLen get_signing_key(Hash *hash,
                       const StrLen aws_secret_key,
                       const StrLen datestamp,
                       const StrLen region,
                       const StrLen service) {

    StrLen secret = StrLen_new(LEN("AWS4") + aws_secret_key.len);
    StrLen signing_key;

    memcpy(secret.str, "AWS4", LEN("AWS4"));
    memcpy(secret.str + LEN("AWS4"), aws_secret_key.str, aws_secret_key.len);

    Hash_hmac(hash, secret, datestamp);
    Hash_hmac(hash, hash->bin, region);
    Hash_hmac(hash, hash->bin, service);
    Hash_hmac(hash, hash->bin, StrLen_of("aws4_request"));

    free(secret.str);

    signing_key = StrLen_new(hash->bin.len);
    memcpy(signing_key.str, hash->bin.str, hash->bin.len);
    signing_key.str[signing_key.len] = '\0';

    return signing_key;
}

StrLen get_signature(Hash *hash,
                     const StrLen signing_key,
                     const StrLen str_to_sign) {
    StrLen signature;

    Hash_hmac(hash, signing_key, str_to_sign);
    Hash_hex_str(hash);

    signature = StrLen_new(hash->hex_str.len);
    strcpy(signature.str, hash->hex_str.str);

    return signature;
}

StrLen get_auth_header(const StrLen aws_access_key,
                       const StrLen credential_scope,
                       const StrLen signature) {

    size_t auth_header_len = LEN("Authorization: ") + LEN(SIGN_ALGORITHM)
                             + LEN(" Credential=") + aws_access_key.len
                             + LEN("/") + credential_scope.len
                             + LEN(", SignedHeaders=") + LEN(SIGNED_HEADERS)
                             + LEN(", Signature=") + signature.len;
    StrLen auth_header = StrLen_new(auth_header_len);

    sprintf(auth_header.str, "Authorization: %s"
                             " Credential=%s/%s, SignedHeaders=%s, Signature=%s",
            SIGN_ALGORITHM,
            aws_access_key.str,
            credential_scope.str,
            SIGNED_HEADERS,
            signature.str);

    return auth_header;
}


int main(void) {
    StrLen aws_access_key, aws_secret_key;

    Hash hash = Hash_new(HASH_NAME);

    StrLen amzdate = get_amzdate();
    StrLen datestamp = get_datestamp(amzdate);

    StrLen http_method = StrLen_of("GET");
    StrLen canon_uri = StrLen_of("/2015-03-31/functions");
    StrLen canon_query = StrLen_of("");
    StrLen content_type = StrLen_of("application/x-www-form-urlencoded");
    StrLen host = StrLen_of("lambda.eu-west-2.amazonaws.com");
    StrLen body = StrLen_of("");

    StrLen region = StrLen_of("eu-west-2");
    StrLen service = StrLen_of("lambda");

    StrLen canon_request_hash_hex_str;
    StrLen credential_scope;
    StrLen str_to_sign;
    StrLen signing_key;
    StrLen signature;
    StrLen auth_header;

    CURL *curl;
    StrLen protocol;
    size_t url_len;
    StrLen url;
    struct curl_slist *headers;
    char header[256];


    get_aws_credentials(&aws_access_key, &aws_secret_key);

    canon_request_hash_hex_str = get_canon_request_hash_hex_str(&hash,
                                                                http_method,
                                                                canon_uri,
                                                                canon_query,
                                                                content_type,
                                                                host,
                                                                amzdate,
                                                                body);

    credential_scope = get_credential_scope(datestamp, region, service);

    str_to_sign = get_str_to_sign(amzdate, credential_scope, canon_request_hash_hex_str);
    free(canon_request_hash_hex_str.str);


    signing_key = get_signing_key(&hash, aws_secret_key, datestamp, region, service);
    free(datestamp.str);


    signature = get_signature(&hash, signing_key, str_to_sign);
    free(signing_key.str);
    free(str_to_sign.str);


    auth_header = get_auth_header(aws_access_key, credential_scope, signature);
    free(credential_scope.str);
    free(signature.str);


    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    protocol = StrLen_of("https://");

    url_len = protocol.len + host.len + canon_uri.len;
    url = StrLen_new(url_len);
    sprintf(url.str, "%s%s%s", protocol.str, host.str, canon_uri.str);

    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    headers = NULL;
    headers = curl_slist_append(headers, "Accept:");

    sprintf(header, "Content-Type: %s", content_type.str);
    headers = curl_slist_append(headers, header);

    sprintf(header, "X-Amz-Date: %s", amzdate.str);
    headers = curl_slist_append(headers, header);

    headers = curl_slist_append(headers, auth_header.str);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    curl_global_cleanup();


    free(auth_header.str);
    free(amzdate.str);

    Hash_free(&hash);

    exit(EXIT_SUCCESS);
}
