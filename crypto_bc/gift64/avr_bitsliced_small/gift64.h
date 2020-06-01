#ifndef GIFT64_H_
#define GIFT64_H_

#define GIFT64_KEY_SIZE    16
#define GIFT64_BLOCK_SIZE  8
#define GIFT64_KEY_SCHEDULE_WORDS  4

typedef unsigned char u8;
typedef unsigned long u32;

extern void gift64_keyschedule(const u8* key, u32* rkey);
extern void gift64_encrypt_block(u8* out_block, const u32* rkey, const u8* in_block);
extern void gift64_decrypt_block(u8* out_block, const u32* rkey, const u8* in_block);

#endif  // GIFT64_H_
