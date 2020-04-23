#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "sha256.c"
void output(unsigned char *in,char format,int len){
	for(int i=0;i<len;i++)printf("%02X%c",in[i],format);
	printf("\n");
}
void xor(unsigned char *dest,int dest_len,unsigned char *src1,unsigned char *src2){
	for(int i=0;i<dest_len;i++){
		dest[i] = src1[i]^src2[i];
	}
}
void hmac_sha256(const unsigned char *data,size_t len,const unsigned char *key,int len_key,unsigned char *out){
	int block_size = 64;
	int hash_size = 32;
	int key_size = block_size;
	unsigned char buf[block_size];
	unsigned char buf2[block_size];
	//bzero(buf,block_size);
	//bzero(buf2,block_size);
	memset(buf,0x00,block_size);
	memset(buf2,0x00,block_size);
	if(len_key>block_size){
		sha256(key,len_key,buf);
		memcpy(buf2,buf,hash_size);
	}
	else{
		memcpy(buf,key,len_key);
		memcpy(buf2,key,len_key);
	}
	for(int i=0;i<key_size;i++){
		*(buf+i)=*(buf+i)^0x5c;
		*(buf2+i)=*(buf2+i)^0x36;
	}
	size_t hash_buf_size = key_size+(len<hash_size?hash_size:len);
	unsigned char hash_buf[hash_buf_size];
	memcpy(hash_buf,buf2,key_size);
	memcpy(hash_buf+key_size,data,len);
	unsigned char hash_out[hash_size];
	sha256(hash_buf,key_size+len,hash_out);
	memcpy(hash_buf,buf,key_size);
	memcpy(hash_buf+key_size,hash_out,hash_size);
	sha256(hash_buf,key_size+hash_size,out);
}
