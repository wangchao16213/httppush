
#ifndef _CHECK_H
#define _CHECK_H

class CryptObject
{
public:
    CryptObject() {};
    ~CryptObject() {};

    char* aes_encode(const char *sourcestr, char *key);

    char* aes_decode(const char *crypttext, char *key);

    char* base64_encode(const char *data, int data_len, bool with_new_line);

    char* base64_decode(const char * input, int length, bool with_new_line);

public:
    static char aeskey[32];
};



#endif

