#ifndef GIFT_COFB_H_
#define GIFT_COFB_H_

#define TAG_SIZE        16
#define COFB_ENCRYPT    1
#define COFB_DECRYPT    0

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct masked_rkey {
    u32 rkey[80];
    u32 rkey_mask[80];
} masked_rkey;

#define XOR_BLOCK(x, y, z) ({       \
    (x)[0] = (y)[0] ^ (z)[0];       \
    (x)[1] = (y)[1] ^ (z)[1];       \
    (x)[2] = (y)[2] ^ (z)[2];       \
    (x)[3] = (y)[3] ^ (z)[3];       \
})

#define XOR_TOP_BAR_BLOCK(x, y) ({  \
    (x)[0] ^= (y)[0];               \
    (x)[1] ^= (y)[1];               \
})

#endif // GIFT_COFB_H_