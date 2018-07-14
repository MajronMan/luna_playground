#include "StrLen.h"


StrLen StrLen_new(const size_t len) {
    StrLen s;
    s.str = calloc(len + LEN("\0"), sizeof(char));
    s.len = len;
    return s;
}

StrLen StrLen_copy(StrLen s) {
    StrLen r = StrLen_new(s.len);
    memcpy(r.str, s.str, s.len);
    return r;
}

StrLen StrLen_str(char *str) {
    return StrLen_buf(str, strlen(str) + LEN("\0"));
}

StrLen StrLen_buf(char *buf, size_t buf_size) {
    StrLen s;
    s.str = buf;
    s.len = buf_size - LEN("\0");
    return s;
}

StrLen StrLen_cat(StrLen first, ...) {
    size_t len;
    va_list strlens;
    StrLen s;
    StrLen concat;

    len = first.len;
    va_start(strlens, first);
    for (s = va_arg(strlens, StrLen); s.str; s = va_arg(strlens, StrLen)) {
        len += s.len;
    }
    va_end(strlens);

    concat = StrLen_new(len);

    memcpy(concat.str, first.str, first.len);

    len = first.len;
    va_start(strlens, first);
    for (s = va_arg(strlens, StrLen); s.str; s = va_arg(strlens, StrLen)) {
        memcpy(concat.str + len, s.str, s.len);
        len += s.len;
    }

    return concat;
}

StrLen StrLen_catf(char *format, ...) {
    size_t len;
    char *c, *end;
    va_list strlens;
    StrLen s, concat;

    len = 0;
    va_start(strlens, format);
    for (c = format; *c; ++c) {
        if (*c == '{') {
            switch (*(c + 1)) {
                case '}':
                    ++c;
                    s = va_arg(strlens, StrLen);
                    len += s.len;
                    continue;
                case '{':
                    ++c;
                    break;
                default:
                    break;
            }
        }
        ++len;
    }
    va_end(strlens);

    concat = StrLen_new(len);

    end = concat.str;
    va_start(strlens, format);
    for (c = format; *c; ++c) {
        if (*c == '{') {
            switch (*(c + 1)) {
                case '}':
                    ++c;
                    s = va_arg(strlens, StrLen);
                    memcpy(end, s.str, s.len);
                    end += s.len;
                    continue;
                case '{':
                    ++c;
                    break;
                default:
                    break;
            }
        }
        *end++ = *c;
    }
    va_end(strlens);

    return concat;
}
