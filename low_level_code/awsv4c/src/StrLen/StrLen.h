#ifndef AWSV4_C_STRLEN_H
#define AWSV4_C_STRLEN_H

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


#define LEN(static_str) (sizeof(static_str) - /* '\0' */ 1)

typedef struct {
    char *str;
    size_t len;
} StrLen;

StrLen StrLen_new(size_t len);

StrLen StrLen_copy(StrLen s);

StrLen StrLen_str(char *str);

StrLen StrLen_buf(char *buf, size_t buf_size);

#define StrLen_of(static_str) StrLen_buf(static_str, sizeof(static_str))

StrLen StrLen_cat(StrLen first, ...);

StrLen StrLen_catf(char *format, ...);


#endif /* AWSV4_C_STRLEN_H */
