#ifndef GIFT64_H_
#define GIFT64_H_

#define KEY_SIZE    		16
#define GIFT64_BLOCK_SIZE   8

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct param_64 {
    u32 ctr[2];
    u32 rkey[56];
} param_64;

extern void gift64_rearrange_key(u32* rkey, const u8* key);
extern void giftb64_keyschedule(u32* rkey);
extern void gift64_encrypt_block(u8* out_block, const u32* rkey, const u8* in_block0, const u8* in_block1);
extern void giftb64_encrypt(u8* out_block, const u32* rkey, const u8* in_block0, const u8* in_block1);
extern void gift64_encrypt_ctr(u8* ctext, param_64 const* p, const u8* ptext, const u32 ptext_len);
extern void giftb64_encrypt_ctr(u8* ctext, param_64 const* p, const u8* ptext, const u32 ptext_len);

#endif  // GIFT64_H_