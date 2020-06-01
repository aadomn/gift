/*******************************************************************************
* AVR bit-sliced implementation of GIFT-128.
* 
* @author	Rhys Weatherley, rhys.weatherley@gmail.com
*
* @date		January 2020
*******************************************************************************/
#include "gift128.h"

/*****************************************************************************
* Encryption of 128-bit blocks using GIFT-128 in ECB mode.
* Note that 'ptext_len' must be a mutliple of 16.
*****************************************************************************/
int gift128_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 rkey[GIFT128_KEY_SCHEDULE_WORDS];
	gift128_keyschedule(key, rkey);
	while(ptext_len > 0) {
		gift128_encrypt_block(ctext, rkey, ptext);
		ptext += GIFT128_BLOCK_SIZE;
		ctext += GIFT128_BLOCK_SIZE;
		ptext_len -= GIFT128_BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Decryption of 128-bit blocks using GIFT-128 in ECB mode.
* Note that 'ctext_len' must be a mutliple of 16.
*****************************************************************************/
int gift128_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 rkey[GIFT128_KEY_SCHEDULE_WORDS];
	gift128_keyschedule(key, rkey);
	while(ctext_len > 0) {
		gift128_decrypt_block(ptext, rkey, ctext);
		ptext += GIFT128_BLOCK_SIZE;
		ctext += GIFT128_BLOCK_SIZE;
		ctext_len -= GIFT128_BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Encryption of 128-bit blocks with GIFTb-128 (used in GIFT-COFB) in ECB mode.
* Note that 'ptext_len' must be a mutliple of 16.
*****************************************************************************/
int giftb128_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 rkey[GIFT128_KEY_SCHEDULE_WORDS];
	gift128_keyschedule(key, rkey);
	while(ptext_len > 0) {
		giftb128_encrypt_block(ctext, rkey, ptext);
		ptext += GIFT128_BLOCK_SIZE;
		ctext += GIFT128_BLOCK_SIZE;
		ptext_len -= GIFT128_BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Decryption of 128-bit blocks with GIFTb-128 (used in GIFT-COFB) in ECB mode.
* Note that 'ptext_len' must be a mutliple of 16.
*****************************************************************************/
int giftb128_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 rkey[GIFT128_KEY_SCHEDULE_WORDS];
	gift128_keyschedule(key, rkey);
	while(ctext_len > 0) {
		giftb128_decrypt_block(ptext, rkey, ctext);
		ptext += GIFT128_BLOCK_SIZE;
		ctext += GIFT128_BLOCK_SIZE;
		ctext_len -= GIFT128_BLOCK_SIZE;
	}
	return 0;
}
