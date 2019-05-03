#include "check.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h>

char CryptObject::aeskey[32]= "6262644673697650";

char *CryptObject::aes_encode(const char *sourcestr, char *key)
{
    if (strcmp(key, "") == 0) key = aeskey;
 
    int len = strlen(sourcestr);
    unsigned char iv[AES_BLOCK_SIZE+1] = "9636243414133788";  // 注意，iv绝对不能是const的，否则会段错误
 
    unsigned char * out = (unsigned char *)malloc(1024*1024);
    if (out == NULL) {
        fprintf(stderr, "No Memory!\n");
    }
    AES_KEY aes;
    if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return NULL;
    }
    /* 计算补0后的长度 */
    int out_len = ((len - 1) / 16 + 1)* 16;
    char * sstr = (char *)malloc(sizeof(char) * out_len + 1);
    /* 补0 */
    memset(sstr, 0, out_len+1);
    strcpy(sstr, sourcestr);
    AES_cbc_encrypt((unsigned char*)sstr, out, out_len, &aes, (unsigned char*)iv, AES_ENCRYPT);
    /* 这里的长度一定要注意，不能用strlen来获取，加密后的字符串中可能会包含\0 */
    char * out2 = base64_encode((char *)out, out_len, false);
    free(out);
    free(sstr);
    return out2;
}
 
char *CryptObject::aes_decode(const char *crypttext, char *key)
{
    if (strcmp(key, "") == 0) key = aeskey;
    int out_len = 0;
    unsigned char iv[AES_BLOCK_SIZE+1] = "9636243414133788";
 
    char *in = base64_decode(crypttext, strlen(crypttext), false);
    char *out = (char *) malloc(sizeof(char) * out_len + 1);
    memset(out, 0, out_len + 1);
    AES_KEY aes;
    if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
    {
        return NULL;
    }
 
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, out_len, &aes, (unsigned char*)iv, AES_DECRYPT);
    free(in);
    return out;
}

char * CryptObject::base64_encode(const char * input, int length, bool with_new_line)  
{  
    BIO * bmem = NULL;  
    BIO * b64 = NULL;  
    BUF_MEM * bptr = NULL;  
  
    b64 = BIO_new(BIO_f_base64());  
    if(!with_new_line) {  
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
    }  
    bmem = BIO_new(BIO_s_mem());  
    b64 = BIO_push(b64, bmem);  
    BIO_write(b64, input, length);  
    BIO_flush(b64);  
    BIO_get_mem_ptr(b64, &bptr);  
  
    char * buff = (char *)malloc(bptr->length + 1);  
    memcpy(buff, bptr->data, bptr->length);  
    buff[bptr->length] = 0;  
  
    BIO_free_all(b64);  
  
    return buff;  
}  
  
char * CryptObject::base64_decode(const char * input, int length, bool with_new_line)  
{  
    BIO * b64 = NULL;  
    BIO * bmem = NULL;  
    char * buffer = (char *)malloc(length);  
    memset(buffer, 0, length);  
  
    b64 = BIO_new(BIO_f_base64());  
    if(!with_new_line) {  
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
    }  
    bmem = BIO_new_mem_buf((void*)input, length);  
    bmem = BIO_push(b64, bmem);  
    BIO_read(bmem, buffer, length);  
  
    BIO_free_all(bmem);  
  
    return buffer;  
}


/*
char *CryptObject::base64_encode(const char *data, int data_len)
{
    int prepare = 0;
    int ret_len;
    int temp = 0;
    char *ret = NULL;
    char *f = NULL;
    int tmp = 0;
    char changed[4];
    int i = 0;
    ret_len = data_len / 3;
    temp = data_len % 3;
    if (temp > 0)
    {
	ret_len += 1;
    }
    ret_len = ret_len*4 + 1;
    ret = (char *)malloc(ret_len);
 
    if ( ret == NULL)
    {
	printf("No enough memory.\n");
	exit(0);
    }
    memset(ret, 0, ret_len);
    f = ret;
    while (tmp < data_len)
    {
	temp = 0;
	prepare = 0;
	memset(changed, '\0', 4);
	while (temp < 3)
	{
	    //printf("tmp = %d\n", tmp);
	    if (tmp >= data_len)
	    {
		break;
	    }
	    prepare = ((prepare << 8) | (data[tmp] & 0xFF));
	    tmp++;
	    temp++;
	}
	prepare = (prepare<<((3-temp)*8));
	//printf("before for : temp = %d, prepare = %d\n", temp, prepare);
	for (i = 0; i < 4 ;i++ )
	{
	    if (temp < i)
	    {
		changed[i] = 0x40;
	    }
	    else
	    {
		changed[i] = (prepare>>((3-i)*6)) & 0x3F;
	    }
	    *f = base[changed[i]];
	    //printf("%.2X", changed[i]);
	    f++;
	}
    }
    *f = '\0';
 
    return ret;
}
 
// out_len 解码后的数据长度
char *CryptObject::base64_decode(const char *data, int data_len, int &out_len)
{
    int ret_len = (data_len / 4) * 3;
    int equal_count = 0;
    char *ret = NULL;
    char *f = NULL;
    int tmp = 0;
    int temp = 0;
    char need[3];
    int prepare = 0;
    int i = 0;
    if (*(data + data_len - 1) == '=')
    {
	equal_count += 1;
    }
    if (*(data + data_len - 2) == '=')
    {
	equal_count += 1;
    }
    if (*(data + data_len - 3) == '=')
    {//seems impossible
	equal_count += 1;
    }
    switch (equal_count)
    {
    case 0:
	ret_len += 4;//3 + 1 [1 for NULL]
	break;
    case 1:
	ret_len += 4;//Ceil((6*3)/8)+1
	break;
    case 2:
	ret_len += 3;//Ceil((6*2)/8)+1
	break;
    case 3:
	ret_len += 2;//Ceil((6*1)/8)+1
	break;
    }
    ret = (char *)malloc(ret_len);
    if (ret == NULL)
    {
	printf("No enough memory.\n");
	exit(0);
    }
    memset(ret, 0, ret_len);
    f = ret;
    while (tmp < (data_len - equal_count))
    {
	temp = 0;
	prepare = 0;
	memset(need, 0, 3);
	while (temp < 4)
	{
	    if (tmp >= (data_len - equal_count))
	    {
		break;
	    }
	    prepare = (prepare << 6) | (find_pos(data[tmp]));
	    temp++;
	    tmp++;
	}
	prepare = prepare << ((4-temp) * 6);
	for (i=0; i<3 ;i++ )
	{
	    if (i == temp)
	    {
		break;
	    }
	    *f = (char)((prepare>>((2-i)*8)) & 0xFF);
	    f++;
	}
    }
    *f = '\0';
    out_len = (int)(f - ret);
    if (out_len < 0) out_len = 0;
    return ret;
}

*/
