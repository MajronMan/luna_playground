#include "hmac.h"

int main(int argc, char** argv)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    
    unsigned char key[128];
    printf("key: ");
    scanf("%s", key);
    int key_len = strlen((char *)key); 
    
    unsigned char text[1024];
    printf("message: ");
    scanf("%s", text);
    int text_len = strlen((char *)text);

    hmac_sha256(key, key_len, text, text_len, digest);

    printf("HMAC-SHA256:\n");
    for(int i=0; i<32; i++){
        printf("%02hhx", digest[i]);
    }
    printf("\n");
}