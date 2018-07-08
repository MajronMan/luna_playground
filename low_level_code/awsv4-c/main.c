#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <curl/curl.h>


void digest(const EVP_MD *md,
            const void *msg,
            size_t msg_len,
            unsigned char *md_val,
            unsigned int *md_len) {
  EVP_MD_CTX *md_ctx;
  int ret;

  md_ctx = EVP_MD_CTX_new();
  if ((ret = EVP_DigestInit_ex(md_ctx, md, NULL)) != 1) {
    fprintf(stderr, "EVP_DigestInit_ex: error return value %d\n", ret);
    exit(EXIT_FAILURE);
  }
  if ((ret = EVP_DigestUpdate(md_ctx, msg, msg_len)) != 1) {
    fprintf(stderr, "EVP_DigestUpdate: error return value %d\n", ret);
    exit(EXIT_FAILURE);
  }
  if ((ret = EVP_DigestFinal_ex(md_ctx, md_val, md_len)) != 1) {
    fprintf(stderr, "EVP_DigestFinal_ex: error return value %d\n", ret);
    exit(EXIT_FAILURE);
  }
  EVP_MD_CTX_free(md_ctx);
}

void hmac(const EVP_MD *md,
          const void *key,
          int key_len,
          const void *msg,
          int msg_len,
          unsigned char *md_val,
          unsigned int *md_len) {
  if (!HMAC(md, key, key_len, msg, msg_len, md_val, md_len)) {
    fprintf(stderr, "HMAC: unknown error\n");
    exit(EXIT_FAILURE);
  }
}

void hex_dump(char *dest, unsigned char *bytes, size_t bytes_len) {
  for (size_t i = 0; i < bytes_len; i++) {
    sprintf(dest, "%02x", bytes[i]);
    dest += 2;
  }
}

int main(int argc, char *argv[]) {
  // get AWS credentials
  char *access_key, *secret_key;

  access_key = getenv("AWS_ACCESS_KEY");
  secret_key = getenv("AWS_SECRET_KEY");
  if (access_key == NULL || secret_key == NULL) {
    fprintf(stderr, "Set AWS credentials:\n"
           "  export AWS_ACCESS_KEY=<your_access_key_id>\n"
           "  export AWS_SECRET_KEY=<your_secret_access_key>\n");
    exit(EXIT_FAILURE);
  }

  // get UTC date/time as: YYYYMMDDTHHMMSSZ
  char amzdate[17], datestamp[9];
  time_t t;
  struct tm *tmp;

  t = time(NULL);
  if (t == -1) {
    perror("time");
    exit(EXIT_FAILURE);
  }
  tmp = gmtime(&t);
  if (tmp == NULL) {
     perror("gmtime");
     exit(EXIT_FAILURE);
  }
  if (strftime(amzdate, sizeof(amzdate), "%Y%m%dT%H%M%SZ", tmp) == 0) {
     fprintf(stderr, "strftime: returned 0\n");
     exit(EXIT_FAILURE);
  }
  memcpy(datestamp, amzdate, sizeof(datestamp - 1));
  datestamp[sizeof(datestamp) - 1] = '\0';

  // create canonical request parts
  char canonical_uri[] = "/2015-03-31/functions/"; // todo param
  size_t canonical_uri_len = strlen(canonical_uri);
  char canonical_querystring[] = ""; // todo param

  char host[] = "lambda.eu-west-2.amazonaws.com"; // todo param
  size_t host_len = strlen(host);

  size_t canonical_headers_len = /* 'host:' */ 5 + host_len + /* '\n' */ 1
    + /* 'x-amz-date:' */ 11 + (sizeof(amzdate) - /* '\0' */ 1) + /* '\n' */ 1;

  char *canonical_headers = calloc(canonical_headers_len + /* '\0' */ 1, sizeof(char));
  sprintf(canonical_headers, "host:%s\nx-amz-date:%s\n", host, amzdate);

  char signed_headers[] = "host;x-amz-date"; // todo param
  size_t signed_headers_len = strlen(signed_headers);

  // calculate body hash
  char body[] = ""; // todo param
  size_t max_hash_len = 2 * EVP_MAX_MD_SIZE + 1;
  char hash[max_hash_len];

  char *md_name = "sha256"; // todo param

  const EVP_MD *md;
  unsigned char md_val[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  size_t body_len;

  md = EVP_get_digestbyname(md_name);
  if(!md) {
    fprintf(stderr, "Unknown message digest %s\n", md_name);
    exit(EXIT_FAILURE);
  }

  body_len = strlen(body);

  digest(md, body, body_len, md_val, &md_len);
  hex_dump(hash, md_val, md_len);
  size_t hash_len = 2 * md_len;

  // assemble and hash canonical request
  char method[] = "GET"; // todo param
  size_t canonical_request_len = strlen(method) + /* '\n' */ 1
    + strlen(canonical_uri) + /* '\n' */ 1
    + strlen(canonical_querystring) + /* '\n' */ 1
    + canonical_headers_len + /* '\n' */ 1
    + signed_headers_len + /* '\n' */ 1
    + hash_len;

  char *canonical_request = calloc(canonical_request_len + /* '\0' */ 1, sizeof(char));
  sprintf(canonical_request, "%s\n%s\n%s\n%s\n%s\n%s",
    method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, hash);

  printf("canonical_request\n%s\n", canonical_request);

  free(canonical_headers);

  digest(md, canonical_request, strlen(canonical_request), md_val, &md_len);
  hex_dump(hash, md_val, md_len);
  printf("%s\n%s\n", canonical_request, hash);

  // create string to sign
  char algorithm[] = "AWS4-HMAC-SHA256"; // todo param
  size_t algorithm_len = strlen(algorithm);
  char region[] = "eu-west-2"; //todo param
  size_t region_len = strlen(region);
  char service[] = "lambda"; //todo param
  size_t service_len = strlen(service);

  size_t credential_scope_len = (sizeof(datestamp) - /* '\0' */ 1) + /* '/' */ 1
    + region_len + /* '/' */ 1
    + service_len + /* '/aws4_request' */ 13;
  char *credential_scope = calloc(credential_scope_len + /* '\0' */ 1, sizeof(char));
  sprintf(credential_scope, "%s/%s/%s/aws4_request", datestamp, region, service);
  printf("credential_scope\n%s", credential_scope);

  size_t string_to_sign_len = sizeof(algorithm) + /* '\n' */ 1
    + sizeof(amzdate) + /* '\n' */ 1
    + credential_scope_len + /* '\n' */ 1
    + hash_len;
  char *string_to_sign = calloc(string_to_sign_len + /* '\0' */ 1, sizeof(char));
  sprintf(string_to_sign, "%s\n%s\n%s\n%s", algorithm, amzdate, credential_scope, hash);
  printf("string_to_sign\n%s\n", string_to_sign);

  // calculate the signing key
  char init_key[45];
  sprintf(init_key, "AWS4%s", secret_key);
  printf("init_key\n%s\n", init_key);

  hmac(md, init_key, sizeof(init_key) - /* '\0' */ 1, datestamp, sizeof(datestamp) - /* '\0' */ 1, md_val, &md_len);
  hmac(md, md_val, md_len, region, region_len, md_val, &md_len);
  hmac(md, md_val, md_len, service, service_len, md_val, &md_len);
  hmac(md, md_val, md_len, "aws4_request", /* 'aws4_request' */ 12, md_val, &md_len);
  hex_dump(hash, md_val, md_len);

  printf("%s\n", hash);

  // sign request
  char signature[max_hash_len];
  hmac(md, md_val, md_len, string_to_sign, string_to_sign_len, md_val, &md_len);
  hex_dump(signature, md_val, md_len);

  free(string_to_sign);

  printf("%s\n", signature);

  // create authorization header
  size_t authorization_header_len = /* 'Authorization: ' */ 15 + algorithm_len
    + /* ' Credential=' */ 12 + /* access_key_len + '/' */ 21 + credential_scope_len
    + /* ', SignedHeaders=' */ 16 + signed_headers_len
    + /* ', Signature=' */ 12 + hash_len;
  char *authorization_header = calloc(authorization_header_len, sizeof(char));
  sprintf(authorization_header, "Authorization: %s Credential=%s/%s"
    ", SignedHeaders=%s, Signature=%s",
    algorithm, access_key, credential_scope, signed_headers, signature);
  printf("authorization_header\n%s\n", authorization_header);

  free(credential_scope);

  // send request
  CURLcode ret;
  if(ret = curl_global_init(CURL_GLOBAL_DEFAULT)) {
    fprintf(stderr, "curl: error code %d\n", ret);
    exit(EXIT_FAILURE);
  }

  CURL *curl;
  if(!(curl = curl_easy_init())) {
    fprintf(stderr, "curl_easy_init: unknown init error\n");
    exit(EXIT_FAILURE);
  }

  char protocol[] = "https://";
  size_t protocol_len = strlen(protocol);
  size_t url_len = protocol_len + host_len + canonical_uri_len + 1;
  char *url = calloc(url_len, sizeof(char));
  sprintf(url, "%s%s%s", protocol, host, canonical_uri);
  printf("url\n%s\n", url);

  char header[256] = "";

  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_URL, url);

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Accept:");

  sprintf(header, "X-Amz-Date: %s", amzdate);
  headers = curl_slist_append(headers, header);

  headers = curl_slist_append(headers, authorization_header);

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_perform(curl);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  free(authorization_header);
  free(canonical_request);

  exit(EXIT_SUCCESS);
}
