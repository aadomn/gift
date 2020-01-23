#ifndef ENCRYPT_H_
#define ENCRYPT_H_

#define BLOCK_SIZE	16
#define KEY_SIZE	16

typedef unsigned char u8;
typedef unsigned int u32;

int gift128_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key);
int gift128_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key);

#endif  // ENCRYPT_H_