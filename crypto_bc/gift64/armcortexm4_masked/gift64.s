/****************************************************************************
* 1st order masked ARM assembly implementation of the GIFT-64 block cipher.
* For more details, see "Fixslicing: A New GIFT Representation" paper at
* https://eprint.iacr.org/2020/412.
* Nonlinear gates (AND/OR) are implemented using the techniques introduced in
* 'Optimal First-Order Boolean Masking for Embedded IoT Devices' published at
* CARDIS 2017.
*
* @author   Alexandre Adomnicai, Nanyang Technological University
*
* @date     June 2021
****************************************************************************/

.syntax unified
.thumb

/*****************************************************************************
* Round constants look-up table according to the fixsliced representation.
*****************************************************************************/
.type rconst,%object
rconst:
.word 0x22000011, 0x00002299, 0x11118811, 0x880000ff
.word 0x33111199, 0x990022ee, 0x22119933, 0x880033bb
.word 0x22119999, 0x880022ff, 0x11119922, 0x880033cc
.word 0x33008899, 0x99002299, 0x33118811, 0x880000ee
.word 0x33110099, 0x990022aa, 0x22118833, 0x880022bb
.word 0x22111188, 0x88002266, 0x00009922, 0x88003300
.word 0x22008811, 0x00002288, 0x00118811, 0x880000bb

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

/*****************************************************************************
* Subroutine to rearrange the encryption key according to the fixsliced
* representation. This is done before the key expansion to speed up the
* calculations.
*****************************************************************************/
rearrange_key:
    str.w   r14, [sp]
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
    ldr.w   r14, [sp]                   // restore stack pointer
    rear_1  r8, r9, r10                 // rearrange key word W0 in r8
    orr     r8, r8, r8, lsl #4          // interleave r8 with itself
    bx      lr

/*****************************************************************************
* Subroutine to update the round keys from round i to i+1, according to the
* fixsliced representation.
*****************************************************************************/
update_rkey:
    str.w   r14, [sp]               	//store the return address
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
    ldr.w   lr, [sp]                    // load the return address
    stmia   r0!, {r5-r12}
    bx      lr

/*****************************************************************************
* Quadruple round subroutine according to the fixsliced representation.
*****************************************************************************/
quadruple_round_masked:
    str.w   r14, [sp]
    movw    r14, #0x1111
    movt    r14, #0x1111                // r14<-0x11111111
    orn     r2, r4, r10, ror #16
    and     r3, r4, r6, ror #16
    eor     r2, r2, r3                  // s0&s2
    orn     r3, r8, r10, ror #16
    and     r12, r8, r6, ror #16
    eor     r3, r3, r12                 // (s0&s2)_mask
    eor     r5, r5, r2
    eor     r9, r9, r3
    orn     r2, r5, r11, ror #8
    and     r3, r5, r7
    eor     r2, r2, r3                  // s1&s3
    orn     r3, r9, r11, ror #8
    and     r12, r9, r7
    eor     r3, r3, r12                 // (s1&s3)_mask
    eor     r4, r4, r2
    eor     r8, r8, r3
    orr     r2, r4, r9
    and     r3, r4, r5
    eor     r2, r2, r3                  // s0|s1
    and     r3, r8, r9
    orr     r12, r8, r5
    eor     r3, r3, r12                 // (s0|s1)_mask
    eor     r6, r2, r6, ror #16
    eor     r10, r3, r10, ror #16
    eor     r7, r7, r6
    eor     r11, r10, r11, ror #8
    eor     r5, r5, r7
    eor     r9, r9, r11
    orn     r2, r4, r9
    and     r3, r4, r5
    eor     r2, r2, r3                  // s0&s1
    orn     r3, r8, r9
    and     r12, r8, r5
    eor     r3, r3, r12                 // (s0&s1)_mask
    eor     r6, r6, r2
    eor     r10, r10, r3
    //linear layer
    mvn     r12, r14, lsl #3            // 0x77777777 for NIBBLE_ROR
    nibror  r5, r5, r12, r14, 1, 3, r2
    nibror  r9, r9, r12, r14, 1, 3, r2
    nibror  r4, r4, r14, r12, 3, 1, r2
    nibror  r8, r8, r14, r12, 3, 1, r2
    orr     r12, r14, r14, lsl #1       // 0x33333333 for NIBBLE_ROR
    nibror  r6, r6, r12, r12, 2, 2, r2
    nibror  r10, r10, r12, r12, 2, 2, r2
    ldrd    r2, r3, [r1], #8            // load rkey
    eor     r7, r7, r2                  // add 1st keyword
    eor     r5, r5, r3                  // add 2nd keyword
    ldrd    r2, r3, [r1, #216]          // load rkey_mask
    eor     r11, r11, r2                // add 1st keyword_mask
    eor     r9, r9, r3                  // add 2nd keyword_mask
    ldr.w   r2, [r0], #4                // load rconst
    eor     r4, r4, r2                  // add rconst
    //2nd round
    //sbox layer
    orn     r2, r7, r10
    and     r3, r7, r6
    eor     r2, r2, r3                  // s0&s2
    orn     r3, r11, r10
    and     r12, r11, r6
    eor     r3, r3, r12                 // (s0&s2)_mask
    eor     r5, r5, r2
    eor     r9, r9, r3
    orn     r2, r5, r8
    and     r3, r5, r4
    eor     r2, r2, r3                  // s1&s3
    orn     r3, r9, r8
    and     r12, r9, r4
    eor     r3, r3, r12                 // (s1&s3)_mask
    eor     r7, r7, r2
    eor     r11, r11, r3
    orr     r2, r7, r9
    and     r3, r7, r5
    eor     r2, r2, r3                  // s0|s1
    and     r3, r11, r9
    orr     r12, r11, r5
    eor     r3, r3, r12                 // (s0|s1)_mask
    eor     r6, r6, r2
    eor     r10, r10, r3
    eor     r4, r4, r6
    eor     r8, r8, r10
    eor     r5, r5, r4
    eor     r9, r9, r8
    orn     r2, r7, r9
    and     r3, r7, r5
    eor     r2, r2, r3                  // s0&s1
    orn     r3, r11, r9
    and     r12, r11, r5
    eor     r3, r3, r12                 // (s0&s1)_mask
    eor     r6, r6, r2
    eor     r10, r10, r3
    ldrd    r2, r3, [r1], #8            // load rkey
    eor     r4, r4, r2                  // add 1st keyword
    eor     r5, r3, r5, ror #8          // add 2nd keyword
    ldrd    r2, r3, [r1, #216]          // load rkey_mask
    eor     r8, r8, r2                  // add 1st keyword_mask
    eor     r9, r3, r9, ror #8          // add 2nd keyword_mask
    ldr.w   r2, [r0], #4                // load rconst
    eor     r7, r2, r7, ror #24         // add rconst
    //3rd round
    //sbox layer
    orn     r2, r4, r10, ror #16
    and     r3, r4, r6, ror #16
    eor     r2, r2, r3                  // s0&s2
    orn     r3, r8, r10, ror #16
    and     r12, r8, r6, ror #16
    eor     r3, r3, r12                 // (s0&s2)_mask
    eor     r5, r5, r2
    eor     r9, r9, r3
    orn     r2, r5, r11, ror #24
    and     r3, r5, r7
    eor     r2, r2, r3                  // s1&s3
    orn     r3, r9, r11, ror #24
    and     r12, r9, r7
    eor     r3, r3, r12                 // (s1&s3)_mask
    eor     r4, r4, r2
    eor     r8, r8, r3
    orr     r2, r4, r9
    and     r3, r4, r5
    eor     r2, r2, r3                  // s0|s1
    and     r3, r8, r9
    orr     r12, r8, r5
    eor     r3, r3, r12                 // (s0|s1)_mask
    eor     r6, r2, r6, ror #16
    eor     r10, r3, r10, ror #16
    eor     r7, r7, r6
    eor     r11, r10, r11, ror #24
    eor     r5, r5, r7
    eor     r9, r9, r11
    orn     r2, r4, r9
    and     r3, r4, r5
    eor     r2, r2, r3                  // s0&s1
    orn     r3, r8, r9
    and     r12, r8, r5
    eor     r3, r3, r12                 // (s0&s1)_mask
    eor     r6, r6, r2
    eor     r10, r10, r3
    //linear layer
    mvn     r12, r14, lsl #3            // 0x77777777 for NIBBLE_ROR
    nibror  r4, r4, r12, r14, 1, 3, r2
    nibror  r8, r8, r12, r14, 1, 3, r2
    nibror  r5, r5, r14, r12, 3, 1, r2
    nibror  r9, r9, r14, r12, 3, 1, r2
    orr     r12, r14, r14, lsl #1       // 0x33333333 for NIBBLE_ROR
    nibror  r6, r6, r12, r12, 2, 2, r2
    nibror  r10, r10, r12, r12, 2, 2, r2
    ldrd    r2, r3, [r1], #8            // load rkey
    eor     r7, r7, r2                  // add 1st keyword
    eor     r5, r5, r3                  // add 2nd keyword
    ldrd    r2, r3, [r1, #216]          // load rkey_mask
    eor     r11, r11, r2                // add 1st keyword_mask
    eor     r9, r9, r3                  // add 2nd keyword_mask
    ldr.w   r2, [r0], #4                // load rconst
    eor     r4, r4, r2                  // add rconst
    //4th round
    //sbox layer
    orn     r2, r7, r10
    and     r3, r7, r6
    eor     r2, r2, r3                  // s0&s2
    orn     r3, r11, r10
    and     r12, r11, r6
    eor     r3, r3, r12                 // (s0&s2)_mask
    eor     r5, r5, r2
    eor     r9, r9, r3
    orn     r2, r5, r8
    and     r3, r5, r4
    eor     r2, r2, r3                  // s1&s3
    orn     r3, r9, r8
    and     r12, r9, r4
    eor     r3, r3, r12                 // (s1&s3)_mask
    eor     r7, r7, r2
    eor     r11, r11, r3
    orr     r2, r7, r9
    and     r3, r7, r5
    eor     r2, r2, r3                  // s0|s1
    and     r3, r11, r9
    orr     r12, r11, r5
    eor     r3, r3, r12                 // (s0|s1)_mask
    eor     r6, r6, r2
    eor     r10, r10, r3
    eor     r4, r4, r6
    eor     r8, r8, r10
    eor     r5, r5, r4
    eor     r9, r9, r8
    orn     r2, r7, r9
    and     r3, r7, r5
    eor     r2, r2, r3                  // s0&s1
    orn     r3, r11, r9
    and     r12, r11, r5
    eor     r3, r3, r12                 // (s0&s1)_mask
    eor     r6, r6, r2
    eor     r10, r10, r3
    ldrd    r2, r3, [r1], #8            // load rkey
    eor     r4, r4, r2                  // add 1st keyword
    eor     r5, r3, r5, ror #24         // add 2nd keyword
    ldrd    r2, r3, [r1, #216]          // load rkey_mask
    eor     r8, r8, r2                  // add 1st keyword_mask
    eor     r9, r3, r9, ror #24         // add 2nd keyword_mask
    ldr.w   r14, [sp]
    ldr.w   r2, [r0], #4                // load rconst
    eor     r7, r2, r7, ror #8          // add rconst
    bx      lr

/*****************************************************************************
* Tranpose a 128-bit key from its classical representation to 8 32-bit words 
* W0,...,W12 according to the new GIFT representation.
* Contrary to the GIFT specification, W0,...,W12 do not refer to 16-bit but
* 32-bit words, since each 16-bit word is interleaved with itself.
*****************************************************************************/
@ void gift64_rearrange_key(u32 rkey[112], const u8 key[8])
.global gift64_rearrange_key
.type   gift64_rearrange_key,%function
gift64_rearrange_key:
    push    {r1-r12,r14}
    ldm     r1, {r2-r5}             // load key words
    movw    r11, 0x0804
    movt    r11, 0x5006             // r11<- RNG_SR = 0x50060804
    mov     r8, #4                  // r8 <- 4 (nb of random words to generate)
    add     r9, r11, #4             // r9 <- RNG_DR = 0x50060808
gift64_key_get_random: 				// ---- generation of 4 random words
    ldr.w   r10, [r11]
    cmp     r10, #1                 // check if RNG_SR == RNG_SR_DRDY
    bne     gift64_key_get_random   // wait until RNG_SR == RNG_SR_DRDY
    ldr.w   r10, [r9]               // put the random number in r10
    push    {r10}                   // store r10 on the stack
    subs    r8, #1                  // decrement the counter
    bne     gift64_key_get_random	// generation of 4 random words ----
    pop     {r6-r8,r14}             // load the masks from the stack
    eor     r9, r2, r6              // apply mask to key word
    eor     r10, r3, r7             // apply mask to key word
    eor     r11, r4, r8             // apply mask to key word
    eor     r12, r5, r14            // apply mask to key word
    strd    r6, r7, [r0, #224]      // store the masks in RAM
    strd    r8, r14, [r0, #232]     // store the masks in RAM
    sub.w   sp, #4                  // to store 'lr' when calling 'rearrange_key'
    bl      rearrange_key           // rearrange the key words
    mvn     r1, r1                  // to remove the NOT in sbox computations
    mvn     r3, r3                  // to remove the NOT in sbox computations
    mvn     r5, r5                  // to remove the NOT in sbox computations
    mvn     r7, r7                  // to remove the NOT in sbox computations
    stm     r0, {r1-r8}
    add.w   r0, r0, #224            // now points to the masks
    ldm     r0, {r9-r12}            // load the masks
    bl      rearrange_key           // rearrange the masks
    stm     r0, {r1-r8}
    add.w   sp, #4                  // restore the stack pointer
    pop     {r1-r12, r14}           // restore context
    bx      lr

/*****************************************************************************
* Compact ARM assembly implementation of the GIFTb-64 key schedule.
*****************************************************************************/
@ void giftb64_keyschedule(u32 rkey[112]) {
.global giftb64_keyschedule
.type   giftb64_keyschedule,%function
giftb64_keyschedule:
    push {r1-r12, r14}
    sub.w   sp, #4              // to store 'lr' when calling 'update_rkey'
    ldmia   r0!, {r5-r12}       // load 1st rkey words
    movw    r2, 0x1111          // masks for 'NIBBLE_ROR'
    movt    r2, 0x1111          // r2 <- 0x11111111
    eor     r3, r2, r2, lsl #1  // r3 <- 0x33333333
    bl      update_rkey         // rkeys for 2nd quad round
    bl      update_rkey         // rkeys for 3rd quad round
    bl      update_rkey         // rkeys for 4th quad round
    bl      update_rkey         // rkeys for 5th quad round
    bl      update_rkey         // rkeys for 6th quad round
    bl      update_rkey         // rkeys for 7th quad round
    ldmia   r0!, {r5-r12}       // load the masks
    bl      update_rkey         // masks for 2nd quad round
    bl      update_rkey         // masks for 3rd quad round
    bl      update_rkey         // masks for 4th quad round
    bl      update_rkey         // masks for 5th quad round
    bl      update_rkey         // masks for 6th quad round
    bl      update_rkey         // masks for 7th quad round
    add.w   sp, #4              // restore the stack pointer
    pop     {r1-r12,r14}
    bx      lr

/*****************************************************************************
* 1st order masked implementations of the GIFT-64 block cipher. This function
* encrypts two 64-bit blocks in parallel to take advantage of 32-bit words. 
*****************************************************************************/
@ void gift64_encrypt_block(u8 out[16], u32 rkey[112], u8 block0[8], u8 block1[8])
.global gift64_encrypt_block
.type   gift64_encrypt_block,%function
gift64_encrypt_block:
    push    {r0-r12,r14}            //save context
    // ---------------------------- PACKING ------------------------------ 
    ldrd    r6, r4, [r2]            // load plaintext blocks
    ldrd    r7, r5, [r3]            // load plaintext blocks
    rev     r4, r4                  // slice0 in r4
    rev     r5, r5                  // slice1 in r5
    rev     r6, r6                  // slice2 in r6
    rev     r7, r7                  // slice3 in r7
    movw    r9, #0x0a0a
    movt    r9, #0x0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc
    movw    r11, #0x0f0f
    movt    r11, #0x0f0f
    movw    r12, #0xffff
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
    mov     r2, r4
    mov     r4, #0                      // clear r4 to avoid HD leakage
    mov     r3, r5
    mov     r5, #0                      // clear r5 to avoid HD leakage
    mov     r12, r6
    mov     r6, #0                      // clear r6 to avoid HD leakage
    mov     r14, r7
    mov     r7, #0                      // clear r7 to avoid HD leakage
    // ---------------------------- MASKING -----------------------------
    // generation of 4 random words
    movw    r11, 0x0804
    movt    r11, 0x5006             // r11<- RNG_SR = 0x50060804
    mov     r8, #4                  // r8 <- 4 (nb of rnd words to generate)
    add.w   r9, r11, #4             // r9 <- RNG_DR = 0x50060808
gift64_block_get_random:
    ldr.w   r10, [r11]
    cmp     r10, #1                 // check if RNG_SR == RNG_SR_DRDY
    bne     gift64_block_get_random
    ldr.w   r10, [r9]               // put the randomn nb in r10
    push    {r10}                   // store r10 on the stack
    subs    r8, #1                  // decrement the counter
    bne     gift64_block_get_random
    pop     {r8-r11}                // pop the random numbers from the stack
    eor     r4, r2, r8              // apply masks
    eor     r5, r3, r9              // apply masks
    eor     r6, r12, r10            // apply masks
    eor     r7, r14, r11            // apply masks
    // ----------------------- GIFTb-CORE ROUTINE ------------------------
    adr     r0, rconst              // load the rconst address in 'r0'
    sub.w   sp, #4                  // to store 'lr' when calling 'quadruple_round_masked'
    ror     r6, r6, #16             // to match the 'quadruple_round_masked' routine
    ror     r10, r10, #16           // to match the 'quadruple_round_masked' routine
    ror     r11, r11, #24           // to match the 'quadruple_round_masked' routine
    bl      quadruple_round_masked  // 1st quadruple round
    bl      quadruple_round_masked  // 2nd quadruple round
    bl      quadruple_round_masked  // 3rd quadruple round
    bl      quadruple_round_masked  // 4th quadruple round
    bl      quadruple_round_masked  // 5th quadruple round
    bl      quadruple_round_masked  // 6th quadruple round
    bl      quadruple_round_masked  // 7th quadruple round
    ldr.w   r0, [sp, #4]            // restore 'ctext' address
    // ---------------------------- UNMASKING -----------------------------
    mov     r2, r4                  // move the state
    mov     r4, #0                  // clear register (to avoid HD leakage)
    mov     r3, r5                  // move the state
    mov     r5, #0                  // clear register (to avoid HD leakage)
    mov     r12, r6, ror #16        // move the state
    mov     r6, #0                  // clear register (to avoid HD leakage)
    mov     r14, r7                 // move the state
    mov     r7, #0                  // clear register (to avoid HD leakage)
    eor     r4, r2, r8              // unmasking
    eor     r5, r3, r9              // unmasking
    eor     r6, r12, r10, ror #16   // unmasking
    eor     r7, r14, r11, ror #8    // unmasking
    // ---------------------------- UNPACKING ----------------------------
    movw    r9, #0x0a0a
    movt    r9, #0x0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc
    movw    r11, #0x0f0f
    movt    r11, #0x0f0f
    movw    r12, #0xffff
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
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    strd    r6, r4, [r0]
    strd    r7, r5, [r0, #8]
    add.w   sp, #4                  // restore 'sp'
    pop     {r0-r12,r14}
    bx      lr

/*****************************************************************************
* 1st order masked implementation of the GIFTb-64 block cipher. This function
* encrypts two 64-bit blocks in parallel to take advantage of 32-bit words. 
*****************************************************************************/
@ void giftb64_encrypt_block(u8 out[16], u32 rkey[112], u8 block0[8], u8 block1[8])
.global giftb64_encrypt_block_compact
.type   giftb64_encrypt_block_compact,%function
giftb64_encrypt_block_compact:
    push    {r0-r12,r14}            // save context
    ldrd    r6, r4, [r2]            // load plaintext blocks
    ldrd    r7, r5, [r3]            // load plaintext blocks
    rev     r4, r4                  // slice0 in r4
    rev     r5, r5                  // slice1 in r5
    rev     r6, r6                  // slice2 in r6
    rev     r7, r7                  // slice3 in r7
    // ------------------ PACKING INTERLEAVE ------------------
    movw    r9, #0x0f0f
    orr     r10, r9, r9, lsl #4
    swpmv   r4, r5, r4, r5, r9, #4, r3
    swpmv   r6, r7, r6, r7, r9, #4, r3
    swpmv   r4, r5, r4, r5, r10, #16, r3
    swpmv   r6, r7, r6, r7, r10, #16, r3
    swpmv   r4, r4, r4, r4, #0xff00, #8, r3
    swpmv   r5, r5, r5, r5, #0xff00, #8, r3
    swpmv   r6, r6, r6, r6, #0xff00, #8, r3
    swpmv   r7, r7, r7, r7, #0xff00, #8, r3
    mov     r4, #0                  // clear r4 to avoid HD leakage
    mov     r3, r5
    mov     r5, #0                  // clear r5 to avoid HD leakage
    mov     r12, r6
    mov     r6, #0                  // clear r6 to avoid HD leakage
    mov     r14, r7
    mov     r7, #0                  // clear r7 to avoid HD leakage
    // ------------------ MASKING ------------------
    // generation of 4 random words
    movw    r11, 0x0804
    movt    r11, 0x5006             // r11<- RNG_SR = 0x50060804
    mov     r8, #4                  // r8 <- 4 (nb of rnd words to generate)
    add.w   r9, r11, #4             // r9 <- RNG_DR = 0x50060808
giftb64_block_get_random:
    ldr.w   r10, [r11]
    cmp     r10, #1                 // check if RNG_SR == RNG_SR_DRDY
    bne     giftb64_block_get_random
    ldr.w   r10, [r9]               // put the randomn nb in r10
    push    {r10}                   // store r10 on the stack
    subs    r8, #1                  // decrement the counter
    bne     giftb64_block_get_random
    pop     {r8-r11}                // pop the masks from the stack
    eor     r4, r2, r8              // apply masks
    eor     r5, r3, r9              // apply masks
    eor     r6, r12, r10            // apply masks
    eor     r7, r14, r11            // apply masks
    // ------------------ GIFTb-CORE ROUTINE ------------------
    adr     r0, rconst              // load the rconst address in 'r0'
    sub.w   sp, #4                  // to store 'lr' when calling 'quadruple_round_masked'
    ror     r6, r6, #16             // to match the 'quadruple_round_masked' routine
    ror     r10, r10, #16           // to match the 'quadruple_round_masked' routine
    ror     r11, r11, #24           // to match the 'quadruple_round_masked' routine
    bl      quadruple_round_masked  // 1st quadruple round
    bl      quadruple_round_masked  // 2nd quadruple round
    bl      quadruple_round_masked  // 3rd quadruple round
    bl      quadruple_round_masked  // 4th quadruple round
    bl      quadruple_round_masked  // 5th quadruple round
    bl      quadruple_round_masked  // 6th quadruple round
    bl      quadruple_round_masked  // 7th quadruple round
    ldr.w   r0, [sp, #4]            // restore 'ctext' address
    // ------------------ UNMASKING ------------------
    mov     r2, r4                  // move the state
    mov     r4, #0                  // clear register (to avoid HD leakage)
    mov     r3, r5                  // move the state
    mov     r5, #0                  // clear register (to avoid HD leakage)
    mov     r12, r6, ror #16        // move the state
    mov     r6, #0                  // clear register (to avoid HD leakage)
    mov     r14, r7                 // move the state
    mov     r7, #0                  // clear register (to avoid HD leakage)
    eor     r4, r2, r8              // unmasking
    eor     r5, r3, r9              // unmasking
    eor     r6, r12, r10, ror #16   // unmasking
    eor     r7, r14, r11, ror #8    // unmasking
    // ------------------ UNPACKING ------------------
    movw    r9, #0x0f0f
    orr     r10, r9, r9, lsl #4
    orr     r10, r9, r9, lsl #4
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
    stm     r0, {r4-r7}             // store the result in RAM
    add.w   sp, #4                  // restore stack pointer
    pop     {r0-r12,r14}            // restore context
    bx      lr
