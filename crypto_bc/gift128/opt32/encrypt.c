/*******************************************************************************
* Constant-time 32-bit implementation of the GIFT-128 block cipher.
*
* See "Fixslicing: A New GIFT Representation" paper available at 
* https://eprint.iacr.org/2020/412.pdf for more details on the fixsliced 
* representation.
* 
* @author	Alexandre Adomnicai, Nanyang Technological University,
*			alexandre.adomnicai@ntu.edu.sg
*
* @date		January 2020
*******************************************************************************/
#include "endian.h"
#include "encrypt.h"
#include "gift128.h"
#include "key_schedule.h"

/****************************************************************************
* The round constants according to the fixsliced representation.
****************************************************************************/
const u32 rconst[40] = {
	0x10000008, 0x80018000, 0x54000002, 0x01010181,
	0x8000001f, 0x10888880, 0x6001e000, 0x51500002,
	0x03030180, 0x8000002f, 0x10088880, 0x60016000,
	0x41500002, 0x03030080, 0x80000027, 0x10008880,
	0x4001e000, 0x11500002, 0x03020180, 0x8000002b,
	0x10080880, 0x60014000, 0x01400002, 0x02020080,
	0x80000021, 0x10000080, 0x0001c000, 0x51000002,
	0x03010180, 0x8000002e, 0x10088800, 0x60012000,
	0x40500002, 0x01030080, 0x80000006, 0x10008808,
	0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};

/*****************************************************************************
* The first 20 rkeys are computed using the classical representation before
* being rearranged into fixsliced representations depending on round numbers.
* The 60 remaining rkeys are directly computed in fixsliced representations.
*****************************************************************************/
void precompute_rkeys(u32* rkey, const u8* key) {
	u32 tmp;
    //classical initialization
    rkey[0] = U32BIG(((u32*)key)[3]);
    rkey[1] = U32BIG(((u32*)key)[1]);
    rkey[2] = U32BIG(((u32*)key)[2]);
    rkey[3] = U32BIG(((u32*)key)[0]);
	// classical keyschedule
	for(int i = 0; i < 16; i+=2) {
		rkey[i+4] = rkey[i+1];
		rkey[i+5] = KEY_UPDATE(rkey[i]);
	}
	// transposition to fixsliced representations
	for(int i = 0; i < 20; i+=10) {
		rkey[i]	= REARRANGE_RKEY_0(rkey[i]);
		rkey[i + 1]	= REARRANGE_RKEY_0(rkey[i + 1]);
		rkey[i + 2]	= REARRANGE_RKEY_1(rkey[i + 2]);
		rkey[i + 3]	= REARRANGE_RKEY_1(rkey[i + 3]);
		rkey[i + 4]	= REARRANGE_RKEY_2(rkey[i + 4]);
		rkey[i + 5]	= REARRANGE_RKEY_2(rkey[i + 5]);
		rkey[i + 6]	= REARRANGE_RKEY_3(rkey[i + 6]);
		rkey[i + 7]	= REARRANGE_RKEY_3(rkey[i + 7]);
	}
	// keyschedule according to fixsliced representations
	for(int i = 20; i < 80; i+=10) {
		rkey[i] = rkey[i-19];
		rkey[i+1] = KEY_TRIPLE_UPDATE_0(rkey[i-20]);
		rkey[i+2] = KEY_DOUBLE_UPDATE_1(rkey[i-17]);
		rkey[i+3] = KEY_TRIPLE_UPDATE_1(rkey[i-18]);
		rkey[i+4] = KEY_DOUBLE_UPDATE_2(rkey[i-15]);
		rkey[i+5] = KEY_TRIPLE_UPDATE_2(rkey[i-16]);
		rkey[i+6] = KEY_DOUBLE_UPDATE_3(rkey[i-13]);
		rkey[i+7] = KEY_TRIPLE_UPDATE_3(rkey[i-14]);
		rkey[i+8] = KEY_DOUBLE_UPDATE_4(rkey[i-11]);
		rkey[i+9] = KEY_TRIPLE_UPDATE_4(rkey[i-12]);
		SWAPMOVE(rkey[i], rkey[i], 0x00003333, 16);
		SWAPMOVE(rkey[i], rkey[i], 0x55554444, 1);
		SWAPMOVE(rkey[i+1], rkey[i+1], 0x55551100, 1);
	}
}

/*****************************************************************************
* Rearranges the input in a row-wise bitsliced manner.
*****************************************************************************/
void packing(u32* state, const u8* input) {
	u32 tmp;
	state[0] =	(input[6] << 24)	| (input[7] << 16)	|
				(input[14] << 8)	| input[15];
	state[1] =	(input[4] << 24)	| (input[5] << 16)	|
				(input[12] << 8)	| input[13];
	state[2] =	(input[2] << 24)	| (input[3] << 16)	|
				(input[10] << 8)	| input[11];
	state[3] =	(input[0] << 24)	| (input[1] << 16)	|
				(input[8] << 8)		| input[9];
    SWAPMOVE(state[0], state[0], 0x0a0a0a0a, 3);
    SWAPMOVE(state[0], state[0], 0x00cc00cc, 6);
    SWAPMOVE(state[1], state[1], 0x0a0a0a0a, 3);
    SWAPMOVE(state[1], state[1], 0x00cc00cc, 6);
    SWAPMOVE(state[2], state[2], 0x0a0a0a0a, 3);
    SWAPMOVE(state[2], state[2], 0x00cc00cc, 6);
    SWAPMOVE(state[3], state[3], 0x0a0a0a0a, 3);
    SWAPMOVE(state[3], state[3], 0x00cc00cc, 6);
    SWAPMOVE(state[0], state[1], 0x000f000f, 4);
    SWAPMOVE(state[0], state[2], 0x000f000f, 8);
    SWAPMOVE(state[0], state[3], 0x000f000f, 12);
    SWAPMOVE(state[1], state[2], 0x00f000f0, 4);
    SWAPMOVE(state[1], state[3], 0x00f000f0, 8);
    SWAPMOVE(state[2], state[3], 0x0f000f00, 4);
}

/*****************************************************************************
* Fills the output from the internal state.
*****************************************************************************/
void unpacking(u8* output, u32* state) {
	u32 tmp;
    SWAPMOVE(state[2], state[3], 0x0f000f00, 4);
    SWAPMOVE(state[1], state[3], 0x00f000f0, 8);
    SWAPMOVE(state[1], state[2], 0x00f000f0, 4);
    SWAPMOVE(state[0], state[3], 0x000f000f, 12);
    SWAPMOVE(state[0], state[2], 0x000f000f, 8);
    SWAPMOVE(state[0], state[1], 0x000f000f, 4);
    SWAPMOVE(state[3], state[3], 0x00cc00cc, 6);
    SWAPMOVE(state[3], state[3], 0x0a0a0a0a, 3);
    SWAPMOVE(state[2], state[2], 0x00cc00cc, 6);
    SWAPMOVE(state[2], state[2], 0x0a0a0a0a, 3);
    SWAPMOVE(state[1], state[1], 0x00cc00cc, 6);
    SWAPMOVE(state[1], state[1], 0x0a0a0a0a, 3);
    SWAPMOVE(state[0], state[0], 0x00cc00cc, 6);
    SWAPMOVE(state[0], state[0], 0x0a0a0a0a, 3);
	output[0] = state[3] >> 24; output[1] = (state[3] >> 16) & 0xff;
	output[2] = state[2] >> 24; output[3] = (state[2] >> 16) & 0xff;
	output[4] = state[1] >> 24; output[5] = (state[1] >> 16) & 0xff;
	output[6] = state[0] >> 24; output[7] = (state[0] >> 16) & 0xff;
	output[8] = (state[3] >> 8) & 0xff; output[9] = state[3] & 0xff;
	output[10] = (state[2] >> 8) & 0xff; output[11] = state[2] & 0xff;
	output[12] = (state[1] >> 8) & 0xff; output[13] = state[1] & 0xff;
	output[14] = (state[0] >> 8) & 0xff; output[15] = state[0] & 0xff;
}

/*****************************************************************************
* Encryption of 128-bit blocks using GIFT-128 in ECB mode.
* Note that 'ptext_len' must be a mutliple of 16.
*****************************************************************************/
int gift128_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 tmp, state[4], rkey[80];
	precompute_rkeys(rkey, key);
	while(ptext_len > 0) {
		packing(state, ptext);
		for(int i = 0; i < 40; i+=5)
			QUINTUPLE_ROUND(state, rkey + i*2, rconst + i);
		unpacking(ctext, state);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ptext_len -= BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Decryption of 128-bit blocks using GIFT-128 in ECB mode.
* Note that 'ctext_len' must be a mutliple of 16.
*****************************************************************************/
int gift128_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 tmp, state[4], rkey[80];
	precompute_rkeys(rkey, key);
	while(ctext_len > 0) {
		packing(state, ctext);
		for(int i = 35; i >= 0; i-=5)
			INV_QUINTUPLE_ROUND(state, rkey + i*2, rconst + i);
		unpacking(ptext, state);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ctext_len -= BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Encryption of 128-bit blocks with GIFTb-128 (used in GIFT-COFB) in ECB mode.
* Note that 'ptext_len' must be a mutliple of 16.
*****************************************************************************/
int giftb128_encrypt_ecb(u8* ctext, const u8* ptext, u32 ptext_len, const u8* key) {
	u32 tmp, state[4], rkey[80];
	precompute_rkeys(rkey, key);
	while(ptext_len > 0) {
    	state[0] = U32BIG(((u32*)ptext)[0]);
    	state[1] = U32BIG(((u32*)ptext)[1]);
   		state[2] = U32BIG(((u32*)ptext)[2]);
    	state[3] = U32BIG(((u32*)ptext)[3]);
		for(int i = 0; i < 40; i+=5)
			QUINTUPLE_ROUND(state, rkey + i*2, rconst + i);
		U8BIG(ctext, state[0]);
		U8BIG(ctext + 4, state[1]);
		U8BIG(ctext + 8, state[2]);
		U8BIG(ctext + 12, state[3]);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ptext_len -= BLOCK_SIZE;
	}
	return 0;
}

/*****************************************************************************
* Decryption of 128-bit blocks with GIFTb-128 (used in GIFT-COFB) in ECB mode.
* Note that 'ptext_len' must be a mutliple of 16.
*****************************************************************************/
int giftb128_decrypt_ecb(u8* ptext, const u8* ctext, u32 ctext_len, const u8* key) {
	u32 tmp, state[4], rkey[80];
	precompute_rkeys(rkey, key);
	while(ctext_len > 0) {
    	state[0] = U32BIG(((u32*)ctext)[0]);
    	state[1] = U32BIG(((u32*)ctext)[1]);
   		state[2] = U32BIG(((u32*)ctext)[2]);
    	state[3] = U32BIG(((u32*)ctext)[3]);
		for(int i = 35; i >= 0; i-=5)
			INV_QUINTUPLE_ROUND(state, rkey + i*2, rconst + i);
		U8BIG(ptext, state[0]);
		U8BIG(ptext + 4, state[1]);
		U8BIG(ptext + 8, state[2]);
		U8BIG(ptext + 12, state[3]);
		ptext += BLOCK_SIZE;
		ctext += BLOCK_SIZE;
		ctext_len -= BLOCK_SIZE;
	}
	return 0;
}
