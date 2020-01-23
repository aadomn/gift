#ifndef GIFT128_H_
#define GIFT128_H_

#define KEY_SIZE    16
#define GIFT128_BLOCK_SIZE  16

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct param_128 {
    u32 ctr;
    u8 nonce[12];
    u32 rkey[80];
} param_128;

extern void gift128_keyschedule(const u8* key, u32* rkey);
extern void giftb128_encrypt_block(u8* out_block, const u32* rkey, const u8* in_block);

#endif  // GIFT128_H_