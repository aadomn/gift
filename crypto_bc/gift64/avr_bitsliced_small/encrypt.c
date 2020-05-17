/*******************************************************************************
* AVR bit-sliced implementation of GIFT-64.
* 
* @author	Rhys Weatherley, rhys.weatherley@gmail.com
*
* @date		January 2020
*******************************************************************************/
#include "gift64.h"

/*****************************************************************************
* Encryption of 64-bit blocks using GIFT-64 in ECB mode.
* Note that 'ptext_len' must be a mutliple of 8.
*****************************************************************************/
int gift64_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 rkey[GIFT64_KEY_SCHEDULE_WORDS];
	gift64_keyschedule(key, rkey);
	while(ptext_len > 0) {
		gift64_encrypt_block(ctext, rkey, ptext);
		ptext += GIFT64_BLOCK_SIZE;
		ctext += GIFT64_BLOCK_SIZE;
		ptext_len -= GIFT64_BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Decryption of 64-bit blocks using GIFT-64 in ECB mode.
* Note that 'ctext_len' must be a mutliple of 8.
*****************************************************************************/
int gift64_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 rkey[GIFT64_KEY_SCHEDULE_WORDS];
	gift64_keyschedule(key, rkey);
	while(ctext_len > 0) {
		gift64_decrypt_block(ptext, rkey, ctext);
		ptext += GIFT64_BLOCK_SIZE;
		ctext += GIFT64_BLOCK_SIZE;
		ctext_len -= GIFT64_BLOCK_SIZE;
	}
	return 0;
}
