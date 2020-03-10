#ifndef GIFT64_H_
#define GIFT64_H_

#define KEY_SIZE    		16
#define GIFT64_BLOCK_SIZE   8

typedef unsigned char u8;
typedef unsigned int u32;

extern void gift64_rearrange_key(u32* rkey, const u8* key);
extern void giftb64_keyschedule(u32* rkey);
extern void gift64_encrypt_block(u8* out_block, const u32* rkey, const u8* in_block0, const u8* in_block1);
extern void giftb64_encrypt_block(u8* out_block, const u32* rkey, const u8* in_block0, const u8* in_block1);

#endif  // GIFT64_H_