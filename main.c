#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include "hmac.c"
#define ROUND 12


// block has to be 32 bytes long
// pwd is text, block is binary data
void encrypt(unsigned char *message,char *pwd,unsigned char *out){
	unsigned char lhs[16]={0},rhs[16]={0};
	unsigned char key[ROUND][16],tmp[32];
	memcpy(lhs,message,16);
	memcpy(rhs,message+16,16);
	sha256(pwd,strlen(pwd),tmp);
	memcpy(key[0],tmp,16);
	for(int i=1;i<ROUND;i++){
		sha256(key[i-1],16,tmp);
		memcpy(key[i],tmp,16);
	}
	memset(tmp,0x00,32);
	for(int i=0;i<ROUND;i++){
		hmac_sha256(rhs,16,key[i],16,tmp);
		xor(tmp,16,lhs,tmp);
		memcpy(lhs,rhs,16);
		memcpy(rhs,tmp,16);
	}
	memcpy(out+16,lhs,16);
	memcpy(out,rhs,16);
}

void decrypt(unsigned char *message,char *pwd,unsigned char *out){
	unsigned char lhs[16]={0},rhs[16]={0};
	unsigned char key[ROUND][16],tmp[32];
	memcpy(lhs,message,16);
	memcpy(rhs,message+16,16);
	sha256(pwd,strlen(pwd),tmp);
	memcpy(key[0],tmp,16);
	for(int i=1;i<ROUND;i++){
		sha256(key[i-1],16,tmp);
		memcpy(key[i],tmp,16);
	}
	memset(tmp,0x00,32);
	for(int i=ROUND-1;i>=0;i--){
		hmac_sha256(rhs,16,key[i],16,tmp);
		xor(tmp,16,lhs,tmp);
		memcpy(lhs,rhs,16);
		memcpy(rhs,tmp,16);
	}
	memcpy(out,lhs,16);
	memcpy(out+16,rhs,16);
}



int main(int argc,char *argv[]){
	unsigned char plain1[32],cipher[32],plain2[32];
	memset(plain1,0x41,32);
	encrypt(plain1,"test",cipher);
	decrypt(cipher,"test",plain2);


	output(plain1,' ',32);
	output(cipher,' ',32);
	output(plain2,' ',32);//*/

	return 0;
}
