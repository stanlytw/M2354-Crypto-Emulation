#ifndef _SHA1_H_
#define _SHA1_H_


// Signed variables are for wimps 
#define uchar unsigned char 
#define uint unsigned int 


typedef struct { 
   uchar data[64]; 
   uint datalen; 
   uint bitlen[2]; 
   uint state[5]; 
   uint k[4]; 
} SHA1_CTX; 


void sha1_transform(SHA1_CTX *ctx, uchar data[]);
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, uchar data[], uint len);
void sha1_final(SHA1_CTX *ctx, uchar hash[]);

#endif