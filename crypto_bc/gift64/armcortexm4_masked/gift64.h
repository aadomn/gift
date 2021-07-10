#ifndef GIFT64_H_
#define GIFT64_H_

#define KEY_SIZE    		16
#define GIFT64_BLOCK_SIZE   8

typedef unsigned char u8;
typedef unsigned int u32;

extern void gift64_rearrange_key(u32 rkey[112], const u8 key[8]);
extern void giftb64_keyschedule(u32 rkey[112]);
extern void gift64_encrypt_block(u8 out_block[16], const u32 rkey[112],const u8 in_block0[8], const u8 in_block1[8]);
extern void giftb64_encrypt_block(u8 out_block[16], const u32 rkey[112], const u8 in_block0[8], const u8 in_block1[8]);

#endif  // GIFT64_H_