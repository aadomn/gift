/****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFT-64 block cipher.
* This implementation focuses on speed, at the cost of a large code size.
*
* See "Fixslicing: A New GIFT Representation" paper available at 
* https://eprint.iacr.org/2020/412.pdf for more details.
*
* @author   Alexandre Adomnicai, Nanyang Technological University
*
* @date     June 2021
****************************************************************************/

.syntax unified
.thumb

/******************************************************************************
* Macro to compute the SWAPMOVE technique.
*   - out0-out1     output registers
*   - in0-in1       input registers
*   - m             mask
*   - n             shift value
*   - tmp           temporary register
******************************************************************************/
.macro swpmv    out0, out1, in0, in1, m, n, tmp
    eor     \tmp, \in1, \in0, lsr \n
    and     \tmp, \m
    eor     \out1, \in1, \tmp
    eor     \out0, \in0, \tmp, lsl \n
.endm

/******************************************************************************
* Macro to compute a nibble-wise rotation to the right.
*   - out           output register
*   - in            input register
*   - m0-m1         masks
*   - n0-n1         shift value
*   - tmp           temporary register
******************************************************************************/
.macro nibror   out, in, m0, m1, n0, n1, tmp
    and     \tmp, \m0, \in, lsr \n0
    and     \out, \in, \m1
    orr     \out, \tmp, \out, lsl \n1
.endm

/******************************************************************************
* Macro to compute the SBox (the NOT operation is included in the round keys).
*   - in0-in3       input/output registers
*   - n             ror value to math fixslicing
*   - tmp           temporary register
******************************************************************************/
.macro sbox     in0, in1, in2, in3, tmp, n
    and     \tmp, \in0, \in2, ror \n
    eor     \in1, \in1, \tmp
    and     \tmp, \in1, \in3
    eor     \in0, \in0, \tmp
    orr     \tmp, \in0, \in1
    eor     \in2, \tmp, \in2, ror \n
    eor     \in3, \in3, \in2
    eor     \in1, \in1, \in3
    and     \tmp, \in0, \in1
    eor     \in2, \in2, \tmp
.endm

/******************************************************************************
* Macro to compute the first round within a quadruple round routine.
*   - const0-const1 round constants
*   - idx           ror index to be used in the sbox (to match fixslicing)
******************************************************************************/
.macro round_0  const0, const1, idx
    movw    r9, \const0
    movt    r9, \const1                 // load rconst
    ldrd    r2, r3, [r1], #8            // load rkey
    sbox    r4, r5, r6, r7, r8, \idx    // sbox layer
    nibror  r5, r5, r12, r10, 1, 3, r8
    nibror  r6, r6, r11, r11, 2, 2, r8
    nibror  r4, r4, r10, r12, 3, 1, r8
    eor     r7, r7, r2                  // add 1st keyword
    eor     r5, r5, r3                  // add 2nd keyword
    eor     r4, r4, r9                  // add rconst
.endm

/******************************************************************************
* Macro to compute the second round within a quadruple round routine.
*   - const0-const1 round constants
******************************************************************************/
.macro round_1  const0, const1
    movw    r9, \const0
    movt    r9, \const1                 // load rconst
    ldrd    r2, r3, [r1], #8            // load rkey
    sbox    r7, r5, r6, r4, r8, 0       // sbox layer
    eor     r4, r4, r2                  // add 1st keyword
    eor     r5, r3, r5, ror #8          // add 2nd keyword
    eor     r7, r9, r7, ror #24         // add rconst
.endm

/******************************************************************************
* Macro to compute the third round within a quadruple round routine.
*   - const0-const1 round constants
******************************************************************************/
.macro round_2  const0, const1
    movw    r9, \const0
    movt    r9, \const1                 // load rconst
    ldrd    r2, r3, [r1], #8            // load rkey
    sbox    r4, r5, r6, r7, r8, 16      // sbox layer
    nibror  r5, r5, r10, r12, 3, 1, r8
    nibror  r6, r6, r11, r11, 2, 2, r8
    nibror  r4, r4, r12, r10, 1, 3, r8
    eor     r7, r7, r2                  // add 1st keyword
    eor     r5, r5, r3                  // add 2nd keyword
    eor     r4, r4, r9                  // add rconst
.endm

/******************************************************************************
* Macro to compute the fourth round within a quadruple round routine.
*   - const0-const1 round constants
******************************************************************************/
.macro round_3  const0, const1
    movw    r9, \const0
    movt    r9, \const1                 // load rconst
    ldrd    r2, r3, [r1], #8            // load rkey
    sbox    r7, r5, r6, r4, r8, 0       // sbox layer
    eor     r4, r4, r2                  // add 1st keyword
    eor     r5, r3, r5, ror #24         // add 2nd keyword
    eor     r7, r9, r7, ror #8          // add rconst
.endm

/******************************************************************************
* Macro to rearrange the input key to match the fixsliced representation.
*   - out           output register
*   - in            input register
*   - tmp           temporary register
******************************************************************************/
.macro rear_0   out, in, tmp
    and     \out, \in,  #0x000f
    and     \tmp, \in,  #0xf000
    orr     \out, \out, \tmp,   lsr #4
    and     \tmp, \in,  #0x0f00
    orr     \out, \out, \tmp,   lsl #8
    and     \tmp, \in,  #0x00f0
    orr     \out, \out, \tmp,   lsl #20
.endm

/******************************************************************************
* Macro to rearrange the input key to match the fixsliced representation.
*   - out           output register
*   - in            input register
*   - tmp           temporary register
******************************************************************************/
.macro rear_1   out, in, tmp
    and     \out, \in,  #0x000f
    and     \tmp, \in,  #0x00f0
    orr     \out, \out, \tmp,   lsl #4
    and     \tmp, \in,  #0x0f00
    orr     \out, \out, \tmp,   lsl #8
    and     \tmp, \in,  #0xf000
    orr     \out, \out, \tmp,   lsl #12
.endm

/******************************************************************************
* Macro to transpose a 32-bit word.
* b31 b30 b29 b28 b27 b26 b25  b24 ... b7  b6  b5  b4 b3  b2  b1 b0
* becomes
* b31 b23 b15 b7  b27 b19 b11  b3  ... b28 b20 b12 b4 b24 b16 b8 b0
*   - out           output register
*   - in            input register
*   - mask          32-bit bitmask
*   - tmp0-tmp1     temporary register
******************************************************************************/
.macro trps     out, in, mask, tmp0, tmp1
    and     \tmp0,  \in,    \mask
    and     \tmp1,  \in,    \mask, lsr #24
    orr     \tmp0,  \tmp0,  \tmp1, lsl #21
    and     \tmp1,  \in,    \mask, lsr #16
    orr     \tmp0,  \tmp0,  \tmp1, lsl #14
    and     \tmp1,  \in,    \mask, lsr #8
    orr     \tmp0,  \tmp0,  \tmp1, lsl #7
    and     \tmp1,  \in,    \mask, lsl #24
    orr     \tmp0,  \tmp0,  \tmp1, lsr #21
    and     \tmp1,  \in,    \mask, lsl #16
    orr     \tmp0,  \tmp0,  \tmp1, lsr #14
    and     \tmp1,  \in,    \mask, lsl #8
    orr     \in,    \tmp0,  \tmp1, lsr #7
.endm

/****************************************************************************
* Updates the round keys according to the fixsliced representation.
* Round key words are supposed to be in r5-r12.
****************************************************************************/
.macro key_update
    mvn     r4, r2, lsl #3              // 0x77777777
    and     r14, r4, r5, lsr #1
    and     r5, r5, r2
    orr     r5, r14, r5, lsl #3         // 1st word rk4
    nibror  r1, r6, r2, r4, 3, 1, r14
    uxth    r1, r1
    uxth    r6, r6, ror #16
    orr     r6, r6, r1, lsl #16         // 2nd word rk4
    ror     r7, r7, #8                  // 1st word rk5
    nibror  r8, r8, r3, r3, 2, 2, r14
    orr     r4, r2, r2, lsl #3          // 0x99999999
    and     r1, r4, r8
    mvn     r4, r4                      // 0x66666666
    and     r8, r8, r4
    orr     r8, r1, r8, ror #24         // 2nd word rk5
    mvn     r4, r2, lsl #3              // 0x77777777
    nibror  r9, r9, r2, r4, 3, 1, r14
    ror     r10, r10, #16
    nibror  r1, r10, r4, r2, 1, 3, r14
    uxth    r1, r1, ror #8
    uxth    r10, r10, ror #24
    ror     r10, r10, #8
    orr     r10, r10, r1, lsl #8        // 2nd word rk6
    ror     r11, r11, #24               // 1st word rk7
    nibror  r12, r12, r3, r3, 2, 2, r14
    and     r1, r12, r3
    mvn     r4, r3                      // 0xcccccccc
    and     r12, r12, r4
    orr     r12, r1, r12, ror #8        // 2nd world rk7
    stmia   r0!, {r5-r12}
.endm

/*****************************************************************************
* Tranpose a 128-bit key from its classical representation to 8 32-bit words 
* W0,...,W12 according to the new GIFT representation.
* Note that if in the GIFT specification, W0,...,W12 refer to 16-bit words, 
* here we consider 32-bit ones as each 16-bit word is interleaved with itself.
*****************************************************************************/
@ void  gift64_rearrange_key(u32* rkey, const u8* key)
.global gift64_rearrange_key
.type   gift64_rearrange_key,%function
gift64_rearrange_key:
    push    {r2-r12,r14}
    ldm     r1, {r9-r12}                // load key words
    movw    r14, 0x0201
    movt    r14, 0x0804                 // r14<-0x08040201 (to transpose words)
    rev     r12, r12                    // endianness
    rear_0  r1, r12, r2                 // rearrange key word W7 in r1
    trps    r1, r1, r14, r2, r8
    orr     r1, r1, r1, lsl #4          // interleave r1 with itself
    mvn     r1, r1                      // remove NOT in sbox computations
    lsr     r12, r12, #16               // now consider the 16 MSBs
    rear_0  r2, r12, r3                 // rearrange key word W6 in r2
    trps    r2, r2, r14, r3, r8
    orr     r2, r2, r2, lsl #4          // interleave r2 with itself
    rev     r11, r11
    rear_0  r3, r11, r4                 // rearrange key word W5 in r3
    orr     r3, r3, r3, lsl #4          // interleave with itself
    mvn     r3, r3                      // remove NOT in sbox computations
    lsr     r11, r11, #16               // now consider the 16 MSBs
    rear_0  r4, r11, r5                 // rearrange key word W4 in r4
    orr     r4, r4, r4, lsl #4          // interleave with itself
    movw    r12, #0x2222
    movt    r12, #0x2222
    swpmv   r3, r3, r3, r3, r12, #2, r5
    swpmv   r4, r4, r4, r4, r12, #2, r5
    rev     r10, r10                    // endianness
    rear_1  r5, r10, r6                 // rearrange key word W3 in r5
    trps    r5, r5, r14, r6, r8
    swpmv   r5, r5, r5, r5, #0x0f00, 16, r11
    orr     r5, r5, r5, lsl #4          // interleave r5 with itself
    mvn     r5, r5                      // remove NOT in sbox computations
    lsr     r10, r10, #16               // now consider the 16 MSBs
    rear_1  r6, r10, r7                 // rearrange key word W2 in r6
    trps    r6, r6, r14, r7, r8
    swpmv   r6, r6, r6, r6, #0x0f00, 16, r11
    orr     r6, r6, r6, lsl #4          // interleave r6 with itself
    rev     r9, r9                      // endianness
    rear_1  r7, r9, r8                  // rearrange key word W1 in r7
    orr     r7, r7, r7, lsl #4          // interleave r7 with itself
    mvn     r7, r7                      // remove NOT in Sbox computations
    lsr     r9, r9, #16                 // now consider the 16 MSBs
    rear_1  r8, r9, r10                 // rearrange key word W0 in r8
    orr     r8, r8, r8, lsl #4          // interleave r8 with itself
    stm     r0, {r1-r8}                 // store the 4 first rkeys
    pop     {r2-r12, r14}
    bx      lr

/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-64 key schedule.
*****************************************************************************/
@ void giftb64_keyschedule(u32 *rkey) {
.global giftb64_keyschedule
.type   giftb64_keyschedule,%function
giftb64_keyschedule:
    push    {r1-r12, r14}
    ldmia   r0!, {r5-r12}
    movw    r2, 0x1111
    movt    r2, 0x1111          // mask for nibror (0x11111111)
    eor     r3, r2, r2, lsl #1  // mask for nibror (0x33333333)
    key_update                  // rkeys for 2nd quadruple round
    key_update                  // rkeys for 3rd quadruple round
    key_update                  // rkeys for 4th quadruple round
    key_update                  // rkeys for 5th quadruple round
    key_update                  // rkeys for 6th quadruple round
    key_update                  // rkeys for 7th quadruple round
    pop     {r1-r12,r14}
    bx      lr

/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFT-64 block cipher.
* This function encrypts 2 64-bit blocks in parallel to take advantage of the 
* 32-bit architecture. 
*****************************************************************************/
@ void gift64_encrypt_block(u8 *out, const u32* rkey,
@       const u8 *block0, const u8* block1) {
.global gift64_encrypt_block
.type   gift64_encrypt_block,%function
gift64_encrypt_block:
    push    {r2-r12,r14}
    // ---------------------------- PACKING ------------------------------ 
    // load plaintext blocks
    ldrd    r6, r4, [r2]
    ldrd    r7, r5, [r3]
    // endianness
    rev     r4, r4                  // slice0 in r4
    rev     r5, r5                  // slice1 in r5
    rev     r6, r6                  // slice2 in r6
    rev     r7, r7                  // slice3 in r7
    
    movw    r9, #0x0a0a
    movt    r9, #0x0a0a             // masks for SWAPMOVE
    movw    r10, #0x00cc
    movt    r10, #0x00cc            // masks for SWAPMOVE routines
    movw    r11, #0x0f0f
    movt    r11, #0x0f0f            // masks for SWAPMOVE routines
    movw    r12, #0xffff            // mask for SWAPMOVE routines
    swpmv   r4, r4, r4, r4, r9, #3, r3
    swpmv   r5, r5, r5, r5, r9, #3, r3
    swpmv   r6, r6, r6, r6, r9, #3, r3
    swpmv   r7, r7, r7, r7, r9, #3, r3
    swpmv   r4, r4, r4, r4, r10, #6, r3
    swpmv   r5, r5, r5, r5, r10, #6, r3
    swpmv   r6, r6, r6, r6, r10, #6, r3
    swpmv   r7, r7, r7, r7, r10, #6, r3
    swpmv   r4, r4, r4, r4, #0xff00, #8, r3
    swpmv   r5, r5, r5, r5, #0xff00, #8, r3
    swpmv   r6, r6, r6, r6, #0xff00, #8, r3
    swpmv   r7, r7, r7, r7, #0xff00, #8, r3
    swpmv   r4, r5, r4, r5, r11, #4, r3
    swpmv   r6, r7, r6, r7, r11, #4, r3
    swpmv   r4, r6, r4, r6, r12, #16, r3
    swpmv   r5, r7, r5, r7, r12, #16, r3
    // ----------------------- GIFTb-CORE ROUTINE ------------------------
    movw    r10, #0x1111
    movt    r10, #0x1111
    orr     r11, r10, r10, lsl #1   // 0x33333333 for NIBBLE_ROR
    mvn     r12, r10, lsl #3        // 0x77777777 for NIBBLE_ROR
    round_0 #0x0011, #0x2200, 0
    round_1 #0x2299, #0x0000
    round_2 #0x8811, #0x1111
    round_3 #0x00ff, #0x8800
    round_0 #0x1199, #0x3311, 16
    round_1 #0x22ee, #0x9900
    round_2 #0x9933, #0x2211
    round_3 #0x33bb, #0x8800
    round_0 #0x9999, #0x2211, 16
    round_1 #0x22ff, #0x8800
    round_2 #0x9922, #0x1111
    round_3 #0x33cc, #0x8800
    round_0 #0x8899, #0x3300, 16
    round_1 #0x2299, #0x9900
    round_2 #0x8811, #0x3311
    round_3 #0x00ee, #0x8800
    round_0 #0x0099, #0x3311, 16
    round_1 #0x22aa, #0x9900
    round_2 #0x8833, #0x2211
    round_3 #0x22bb, #0x8800
    round_0 #0x1188, #0x2211, 16
    round_1 #0x2266, #0x8800
    round_2 #0x9922, #0x0000
    round_3 #0x3300, #0x8800
    round_0 #0x8811, #0x2200, 16
    round_1 #0x2288, #0x0000
    round_2 #0x8811, #0x0011
    round_3 #0x00bb, #0x8800
    // ---------------------------- UNPACKING ----------------------------
    movw    r9, #0x0a0a
    movt    r9, #0x0a0a             // mask for swpmv
    movw    r10, #0x00cc 
    movt    r10, #0x00cc            // mask for swpmv
    movw    r11, #0x0f0f
    movt    r11, #0x0f0f            // mask for swpmv
    movw    r12, #0xffff            // mask for swpmv
    swpmv   r4, r6, r4, r6, r12, #16, r3
    swpmv   r5, r7, r5, r7, r12, #16, r3
    swpmv   r4, r5, r4, r5, r11, #4, r3
    swpmv   r6, r7, r6, r7, r11, #4, r3
    swpmv   r4, r4, r4, r4, #0xff00, #8, r3
    swpmv   r5, r5, r5, r5, #0xff00, #8, r3
    swpmv   r6, r6, r6, r6, #0xff00, #8, r3
    swpmv   r7, r7, r7, r7, #0xff00, #8, r3
    swpmv   r4, r4, r4, r4, r10, #6, r3
    swpmv   r5, r5, r5, r5, r10, #6, r3
    swpmv   r6, r6, r6, r6, r10, #6, r3
    swpmv   r7, r7, r7, r7, r10, #6, r3
    swpmv   r4, r4, r4, r4, r9, #3, r3
    swpmv   r5, r5, r5, r5, r9, #3, r3
    swpmv   r6, r6, r6, r6, r9, #3, r3
    swpmv   r7, r7, r7, r7, r9, #3, r3
    //endianness
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    strd    r6, r4, [r0]
    strd    r7, r5, [r0, #8]
    pop     {r2-r12,r14}
    bx      lr

/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-64 block cipher.
* This function encrypts 2 64-bit blocks in parallel to take advantage of the 
* 32-bit architecture. 
*****************************************************************************/
@ void giftb64_encrypt_block(u8 *out, const u32* rkey,
@       const u8 *block0, const u8* block1) {
.global giftb64_encrypt_block
.type   giftb64_encrypt_block,%function
giftb64_encrypt_block:
    push    {r2-r12,r14}
    // load plaintext blocks
    ldrd    r6, r4, [r2]
    ldrd    r7, r5, [r3]
    rev     r4, r4                  // slice0 in r4
    rev     r5, r5                  // slice1 in r5
    rev     r6, r6                  // slice2 in r6
    rev     r7, r7                  // slice3 in r7
    // ------------------ PACKING INTERLEAVE ------------------
    movw    r9, #0x0f0f             // mask for swpmv
    orr     r10, r9, r9, lsl #4     // mask for swpmv
    swpmv   r4, r5, r4, r5, r9, #4, r3
    swpmv   r6, r7, r6, r7, r9, #4, r3
    swpmv   r4, r5, r4, r5, r10, #16, r3
    swpmv   r6, r7, r6, r7, r10, #16, r3
    swpmv   r4, r4, r4, r4, #0xff00, #8, r3
    swpmv   r5, r5, r5, r5, #0xff00, #8, r3
    swpmv   r6, r6, r6, r6, #0xff00, #8, r3
    swpmv   r7, r7, r7, r7, #0xff00, #8, r3
    // ------------------ GIFTb-CORE ROUTINE ------------------
    movw    r10, #0x1111
    movt    r10, #0x1111
    orr     r11, r10, r10, lsl #1   // 0x33333333 for NIBBLE_ROR
    mvn     r12, r10, lsl #3        // 0x77777777 for NIBBLE_ROR
    round_0 #0x0011, #0x2200, 0
    round_1 #0x2299, #0x0000
    round_2 #0x8811, #0x1111
    round_3 #0x00ff, #0x8800
    round_0 #0x1199, #0x3311, 16
    round_1 #0x22ee, #0x9900
    round_2 #0x9933, #0x2211
    round_3 #0x33bb, #0x8800
    round_0 #0x9999, #0x2211, 16
    round_1 #0x22ff, #0x8800
    round_2 #0x9922, #0x1111
    round_3 #0x33cc, #0x8800
    round_0 #0x8899, #0x3300, 16
    round_1 #0x2299, #0x9900
    round_2 #0x8811, #0x3311
    round_3 #0x00ee, #0x8800
    round_0 #0x0099, #0x3311, 16
    round_1 #0x22aa, #0x9900
    round_2 #0x8833, #0x2211
    round_3 #0x22bb, #0x8800
    round_0 #0x1188, #0x2211, 16
    round_1 #0x2266, #0x8800
    round_2 #0x9922, #0x0000
    round_3 #0x3300, #0x8800
    round_0 #0x8811, #0x2200, 16
    round_1 #0x2288, #0x0000
    round_2 #0x8811, #0x0011
    round_3 #0x00bb, #0x8800
    // ------------------ UNPACKING INTERLEAVE ------------------
    movw    r9, #0x0f0f             // mask for swpmv
    orr     r10, r9, r9, lsl #4     // mask for swpmv
    swpmv   r4, r4, r4, r4, #0xff00, #8, r3
    swpmv   r5, r5, r5, r5, #0xff00, #8, r3
    swpmv   r6, r6, r6, r6, #0xff00, #8, r3
    swpmv   r7, r7, r7, r7, #0xff00, #8, r3
    swpmv   r4, r5, r4, r5, r10, #16, r3
    swpmv   r6, r7, r6, r7, r10, #16, r3
    swpmv   r4, r5, r4, r5, r9, #4, r3
    swpmv   r6, r7, r6, r7, r9, #4, r3
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    stm     r0, {r4-r7}
    pop     {r2-r12,r14}
    bx      lr
