/*******************************************************************************
* Constant-time 32-bit implementation of the GIFT-COFB authenticated cipher.
* 
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
* @date     January 2020
*******************************************************************************/
#include <string.h>
#include "giftb128.h"
#include "giftcofb128v1.h"

static inline void padding(u32* dest, const u32* src, const u32 no_of_bytes) {
    u32 i;
    if (no_of_bytes == 0) {
        dest[0] = 0x00000080; // little-endian
        dest[1] = 0x00000000;
        dest[2] = 0x00000000;
        dest[3] = 0x00000000;
    }
    else if (no_of_bytes < GIFT128_BLOCK_SIZE) {
        for (i = 0; i < no_of_bytes/4+1; i++)
            dest[i] = src[i];
        dest[i-1] &= ~(0xffffffffL << (no_of_bytes % 4)*8);
        dest[i-1] |= 0x00000080L << (no_of_bytes % 4)*8;
        for (; i < 4; i++)
            dest[i] = 0x00000000;
    }
    else {
        dest[0] = src[0];
        dest[1] = src[1];
        dest[2] = src[2];
        dest[3] = src[3];
    }
}

/****************************************************************************
* Constant-time implementation of the GIFT-COFB authenticated cipher based on
* fixsliced GIFTb-128. Encryption/decryption is handled by the same function,
* depending on the 'mode' parameter (1/0).
****************************************************************************/
int giftcofb_crypt(u8* out, const u8* key, const u8* nonce, const u8* ad,
                u32 ad_len, const u8* in, u32 in_len, const int encrypting) {

    u32 tmp0, tmp1, emptyA, emptyM, offset[2];
    u32 input[4], rkey[80];
    u8 Y[GIFT128_BLOCK_SIZE];

    if (!encrypting) {
        if (in_len < TAG_SIZE)
            return -1;
        in_len -= TAG_SIZE;
    }

    if(ad_len == 0)
        emptyA = 1;
    else
        emptyA = 0;

    if(in_len == 0)
        emptyM =1;
    else
        emptyM = 0;

    gift128_keyschedule(key, rkey);
    giftb128_encrypt_block(Y, rkey, nonce);
    offset[0] = ((u32*)Y)[0];
    offset[1] = ((u32*)Y)[1];

    while(ad_len > GIFT128_BLOCK_SIZE){
        RHO1(input, (u32*)Y, (u32*)ad, GIFT128_BLOCK_SIZE);
        DOUBLE_HALF_BLOCK(offset);
        XOR_TOP_BAR_BLOCK(input, offset);
        giftb128_encrypt_block(Y, rkey, (u8*)input);
        ad += GIFT128_BLOCK_SIZE;
        ad_len -= GIFT128_BLOCK_SIZE;
    }
    
    TRIPLE_HALF_BLOCK(offset);
    if((ad_len % GIFT128_BLOCK_SIZE != 0) || (emptyA))
        TRIPLE_HALF_BLOCK(offset);
    if(emptyM) {
        TRIPLE_HALF_BLOCK(offset);
        TRIPLE_HALF_BLOCK(offset);
    }

    RHO1(input, (u32*)Y, (u32*)ad, ad_len);
    XOR_TOP_BAR_BLOCK(input, offset);
    giftb128_encrypt_block(Y, rkey, (u8*)input);

    while (in_len > GIFT128_BLOCK_SIZE){
        DOUBLE_HALF_BLOCK(offset);
        if (encrypting)
            RHO((u32*)Y, (u32*)in, input, (u32*)out, GIFT128_BLOCK_SIZE);
        else
            RHO_PRIME((u32*)Y, (u32*)in, input, (u32*)out, GIFT128_BLOCK_SIZE);
        XOR_TOP_BAR_BLOCK(input, offset);
        giftb128_encrypt_block(Y, rkey, (u8*)input);
        in += GIFT128_BLOCK_SIZE;
        out += GIFT128_BLOCK_SIZE;
        in_len -= GIFT128_BLOCK_SIZE;
    }
    
    if(!emptyM){
        TRIPLE_HALF_BLOCK(offset);
        if(in_len % GIFT128_BLOCK_SIZE != 0)
            TRIPLE_HALF_BLOCK(offset);
        if (encrypting) {
            RHO((u32*)Y, (u32*)in, input, (u32*)out, in_len);
            out += in_len;
        }
        else {
            RHO_PRIME((u32*)Y, (u32*)in, input, (u32*)out, in_len);
            in += in_len;
        }
        XOR_TOP_BAR_BLOCK(input, offset);
        giftb128_encrypt_block(Y, rkey, (u8*)input);
    }
    
    if (encrypting) { // encryption mode
        memcpy(out, Y, TAG_SIZE);
        return 0;
    }
    // decrypting
    tmp0 = 0;
    for(tmp1 = 0; tmp1 < TAG_SIZE; tmp1++)
        tmp0 |= in[tmp1] ^ Y[tmp1];
    return tmp0;
}

/****************************************************************************
* API required by the NIST for the LWC competition.
****************************************************************************/
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                    const unsigned char* m, unsigned long long mlen,
                    const unsigned char* ad, unsigned long long adlen,
                    const unsigned char* nsec, const unsigned char* npub,
                    const unsigned char* k) {
    (void)nsec;
    *clen = mlen + TAG_SIZE;
    return giftcofb_crypt(c, k, npub, ad, adlen, m, mlen, COFB_ENCRYPT);
}

/****************************************************************************
* API required by the NIST for the LWC competition.
****************************************************************************/
int crypto_aead_decrypt(unsigned char* m, unsigned long long *mlen,
                    unsigned char* nsec, const unsigned char* c,
                    unsigned long long clen, const unsigned char* ad,
                    unsigned long long adlen, const unsigned char* npub,
                    const unsigned char *k) {
    (void)nsec;
    *mlen = clen - TAG_SIZE;
    return giftcofb_crypt(m, k, npub, ad, adlen, c, clen, COFB_DECRYPT);
}
