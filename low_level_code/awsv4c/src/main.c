#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "StrLen/StrLen.h"
#include "Hash/Hash.h"


#define HASH_NAME ("sha256")
#define SIGN_ALGORITHM ("AWS4-HMAC-SHA256")

#define DATESTAMP_FORMAT ("YYYYMMDD")

#define SIGNED_HEADERS ("accept;host;x-amz-date")


StrLen get_datestamp(StrLen amzdate) {
    StrLen datestamp = StrLen_new(LEN(DATESTAMP_FORMAT));
    memcpy(datestamp.str, amzdate.str, datestamp.len);
    return datestamp;
}

StrLen get_canon_request_hash_hex_str(Hash *hash,
                                      StrLen http_method,
                                      StrLen canon_uri,
                                      StrLen canon_query,
                                      StrLen host,
                                      StrLen amzdate,
                                      StrLen body) {

    StrLen canon_request;
    StrLen canon_request_hash_hex_str;

    Hash_digest(hash, body);
    Hash_hex_str(hash);

    canon_request = StrLen_catf("{}\n{}\n{}\naccept:{}\nhost:{}\nx-amz-date:{}\n\n{}\n{}",
                                http_method,
                                canon_uri,
                                canon_query,
                                StrLen_of("*/*"),
                                host,
                                amzdate,
                                StrLen_of(SIGNED_HEADERS),
                                hash->hex_str);

    Hash_digest(hash, canon_request);
    Hash_hex_str(hash);

    free(canon_request.str);

    canon_request_hash_hex_str = StrLen_new(hash->hex_str.len);
    strcpy(canon_request_hash_hex_str.str, hash->hex_str.str);

    return canon_request_hash_hex_str;
}

StrLen get_credential_scope(StrLen datestamp,
                            StrLen region,
                            StrLen service) {

    return StrLen_catf("{}/{}/{}/aws4_request", datestamp, region, service);
}

StrLen get_str_to_sign(StrLen amzdate,
                       StrLen credential_scope,
                       StrLen canon_request_hash_hex_str) {

    return StrLen_catf("{}\n{}\n{}\n{}",
                       StrLen_of(SIGN_ALGORITHM),
                       amzdate,
                       credential_scope,
                       canon_request_hash_hex_str);
}

StrLen get_signing_key(Hash *hash,
                       StrLen aws_secret_key,
                       StrLen datestamp,
                       StrLen region,
                       StrLen service) {

    StrLen secret = StrLen_catf("AWS4{}", aws_secret_key);

    Hash_hmac(hash, secret, datestamp);
    Hash_hmac(hash, hash->bin, region);
    Hash_hmac(hash, hash->bin, service);
    Hash_hmac(hash, hash->bin, StrLen_of("aws4_request"));

    free(secret.str);

    return StrLen_copy(hash->bin);
}

StrLen get_signature(Hash *hash,
                     StrLen signing_key,
                     StrLen str_to_sign) {

    Hash_hmac(hash, signing_key, str_to_sign);
    Hash_hex_str(hash);

    return StrLen_copy(hash->hex_str);
}

StrLen get_auth_header(StrLen aws_access_key,
                       StrLen credential_scope,
                       StrLen signature) {

    return StrLen_catf("{} Credential={}/{}, SignedHeaders={}, Signature={}",
                       StrLen_of(SIGN_ALGORITHM),
                       aws_access_key,
                       credential_scope,
                       StrLen_of(SIGNED_HEADERS),
                       signature);
}

char *awsv4sig_auth_header(char *c_aws_access_key,
                           char *c_aws_secret_key,
                           char *c_amzdate,
                           char *c_http_method,
                           char *c_canon_uri,
                           char *c_canon_query,
                           char *c_host,
                           char *c_body,
                           char *c_region,
                           char *c_service) {

    StrLen aws_access_key = StrLen_str(c_aws_access_key);
    StrLen aws_secret_key = StrLen_str(c_aws_secret_key);
    StrLen amzdate = StrLen_str(c_amzdate);
    StrLen http_method = StrLen_str(c_http_method);
    StrLen canon_uri = StrLen_str(c_canon_uri);
    StrLen canon_query = StrLen_str(c_canon_query);
    StrLen host = StrLen_str(c_host);
    StrLen body = StrLen_str(c_body);
    StrLen region = StrLen_str(c_region);
    StrLen service = StrLen_str(c_service);

    StrLen datestamp = get_datestamp(amzdate);

    Hash hash = Hash_new(HASH_NAME);


    StrLen canon_request_hash_hex_str = get_canon_request_hash_hex_str(&hash,
                                                                       http_method,
                                                                       canon_uri,
                                                                       canon_query,
                                                                       host,
                                                                       amzdate,
                                                                       body);
    StrLen credential_scope = get_credential_scope(datestamp, region, service);
    StrLen str_to_sign = get_str_to_sign(amzdate, credential_scope, canon_request_hash_hex_str);
    StrLen signing_key = get_signing_key(&hash, aws_secret_key, datestamp, region, service);
    StrLen signature = get_signature(&hash, signing_key, str_to_sign);

    StrLen auth_header = get_auth_header(aws_access_key, credential_scope, signature);

    free(signature.str);
    free(signing_key.str);
    free(str_to_sign.str);
    free(credential_scope.str);
    free(canon_request_hash_hex_str.str);

    free(datestamp.str);

    Hash_free(&hash);

    return auth_header.str;
}
