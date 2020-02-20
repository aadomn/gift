/****************************************************************************
* Constant-time ARM assembly implementation of the GIFT-64 block cipher.
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     January 2020
****************************************************************************/

.syntax unified
.thumb

/*****************************************************************************
* Tranpose a 128-bit key from its classical representation to 8 32-bit words 
* W0,...,W12 according to the new GIFT representation.
* Note that if in the GIFT specification, W0,...,W12 refer to 16-bit words, 
* here we consider 32-bit ones as each 16-bit word is interleaved with itself.
*****************************************************************************/
@ void gift64_rearrange_key(u32* rkey, const u8* key)
.global gift64_rearrange_key
.type   gift64_rearrange_key,%function
gift64_rearrange_key:
    push {r2-r12,r14}
    // load key
    ldm r1, {r9-r12}
    // mask to transpose words
    movw r14, 0x0201
    movt r14, 0x0804

    // rearrange key word W7 in r1
    rev r12, r12
    and r1, r12, #0x000f
    and r2, r12, #0xf000
    orr r1, r1, r2, lsr #4
    and r2, r12, #0x0f00
    orr r1, r1, r2, lsl #8
    and r2, r12, #0x00f0
    orr r1, r1, r2, lsl #20
    // transpose key word W7
    and r2, r1, r14
    and r8, r1, r14, lsr #24
    orr r2, r2, r8, lsl #21
    and r8, r1, r14, lsr #16
    orr r2, r2, r8, lsl #14
    and r8, r1, r14, lsr #8
    orr r2, r2, r8, lsl #7
    and r8, r1, r14, lsl #24
    orr r2, r2, r8, lsr #21
    and r8, r1, r14, lsl #16
    orr r2, r2, r8, lsr #14
    and r8, r1, r14, lsl #8
    orr r1, r2, r8, lsr #7
    // interleave with itself
    orr r1, r1, r1, lsl #4
    // negation to save 1 instruction in sbox computations
    mvn r1, r1
    // rearrange key word W6 in r2
    lsr r12, r12, #16
    and r2, r12, #0x000f
    and r3, r12, #0xf000
    orr r2, r2, r3, lsr #4
    and r3, r12, #0x0f00
    orr r2, r2, r3, lsl #8
    and r3, r12, #0x00f0
    orr r2, r2, r3, lsl #20
    // transpose key word W6
    and r3, r2, r14
    and r8, r2, r14, lsr #24
    orr r3, r3, r8, lsl #21
    and r8, r2, r14, lsr #16
    orr r3, r3, r8, lsl #14
    and r8, r2, r14, lsr #8
    orr r3, r3, r8, lsl #7
    and r8, r2, r14, lsl #24
    orr r3, r3, r8, lsr #21
    and r8, r2, r14, lsl #16
    orr r3, r3, r8, lsr #14
    and r8, r2, r14, lsl #8
    orr r2, r3, r8, lsr #7
    // interleave with itself
    orr r2, r2, r2, lsl #4
    // rearrange key word W5 in r3
    rev r11, r11
    and r3, r11, #0x000f
    and r4, r11, #0xf000
    orr r3, r3, r4, lsr #4
    and r4, r11, #0x0f00
    orr r3, r3, r4, lsl #8
    and r4, r11, #0x00f0
    orr r3, r3, r4, lsl #20
    // interleave with itself
    orr r3, r3, r3, lsl #4
    // negation to save 1 instruction in sbox computations
    mvn r3, r3
    // rearrange key word W4 in r4
    lsr r11, r11, #16
    and r4, r11, #0x000f
    and r5, r11, #0xf000
    orr r4, r4, r5, lsr #4
    and r5, r11, #0x0f00
    orr r4, r4, r5, lsl #8
    and r5, r11, #0x00f0
    orr r4, r4, r5, lsl #20
    // interleave with itself
    orr r4, r4, r4, lsl #4
    // SWAPMOVE
    movw r12, #0x2222
    movt r12, #0x2222
    eor r5, r3, r3, lsr #2
    and r5, r5, r12
    eor r3, r3, r5
    eor r3, r3, r5, lsl #2 //SWAPMOVE(r3, r3, 0x22222222, 2)
    eor r5, r4, r4, lsr #2
    and r5, r5, r12
    eor r4, r4, r5
    eor r4, r4, r5, lsl #2 //SWAPMOVE(r4, r4, 0x22222222, 2)
    // rearrange key word W3 in r5
    rev r10, r10
    and r5, r10, #0x000f
    and r6, r10, #0x00f0
    orr r5, r5, r6, lsl #4
    and r6, r10, #0x0f00
    orr r5, r5, r6, lsl #8
    and r6, r10, #0xf000
    orr r5, r5, r6, lsl #12
    // transpose W3
    and r6, r5, r14
    and r8, r5, r14, lsr #24
    orr r6, r6, r8, lsl #21
    and r8, r5, r14, lsr #16
    orr r6, r6, r8, lsl #14
    and r8, r5, r14, lsr #8
    orr r6, r6, r8, lsl #7
    and r8, r5, r14, lsl #24
    orr r6, r6, r8, lsr #21
    and r8, r5, r14, lsl #16
    orr r6, r6, r8, lsr #14
    and r8, r5, r14, lsl #8
    orr r5, r6, r8, lsr #7
    // SWAPMOVE
    eor r11, r5, r5, lsr #16
    and r11, r11, #0x0f00
    eor r5, r5, r11
    eor r5, r5, r11, lsl #16 //SWAPMOVE(r5, r5, 0x00000f00, 16)
    // interleave with itself
    orr r5, r5, r5, lsl #4
    // negation to save 1 instruction in sbox computations
    mvn r5, r5
    // rearrange key word W2 in r6
    lsr r10, r10, #16
    and r6, r10, #0x000f
    and r7, r10, #0x00f0
    orr r6, r6, r7, lsl #4
    and r7, r10, #0x0f00
    orr r6, r6, r7, lsl #8
    and r7, r10, #0xf000
    orr r6, r6, r7, lsl #12
    // transpose W2
    and r7, r6, r14
    and r8, r6, r14, lsr #24
    orr r7, r7, r8, lsl #21
    and r8, r6, r14, lsr #16
    orr r7, r7, r8, lsl #14
    and r8, r6, r14, lsr #8
    orr r7, r7, r8, lsl #7
    and r8, r6, r14, lsl #24
    orr r7, r7, r8, lsr #21
    and r8, r6, r14, lsl #16
    orr r7, r7, r8, lsr #14
    and r8, r6, r14, lsl #8
    orr r6, r7, r8, lsr #7
    // SWAPMOVE
    eor r11, r6, r6, lsr #16
    and r11, r11, #0x0f00
    eor r6, r6, r11
    eor r6, r6, r11, lsl #16 //SWAPMOVE(r6, r6, 0x00000f00, 16)
    // interleave with itself
    orr r6, r6, r6, lsl #4
    // rearrange key word W1 in r7
    rev r9, r9
    and r7, r9, #0x000f
    and r8, r9, #0x00f0
    orr r7, r7, r8, lsl #4
    and r8, r9, #0x0f00
    orr r7, r7, r8, lsl #8
    and r8, r9, #0xf000
    orr r7, r7, r8, lsl #12
    // interleave with itself
    orr r7, r7, r7, lsl #4
    // negation to save 1 instruction in sbox computations
    mvn r7, r7
    // rearrange key word W0 in r8
    lsr r9, r9, #16
    and r8, r9, #0x000f
    and r10, r9, #0x00f0
    orr r8, r8, r10, lsl #4
    and r10, r9, #0x0f00
    orr r8, r8, r10, lsl #8
    and r10, r9, #0xf000
    orr r8, r8, r10, lsl #12
    // interleave with itself
    orr r8, r8, r8, lsl #4
    // store the 4 first rkeys
    stm r0, {r1-r8}

    pop {r2-r12, r14}
    bx lr


/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-64 key schedule.
*****************************************************************************/
@ void giftb64_keyschedule(u32 *rkey)
.global giftb64_keyschedule
.type   giftb64_keyschedule,%function
giftb64_keyschedule:

    push {r1-r12, r14}
    // load key
    ldmia r0!, {r5-r12}
    // masks for the NIBBLE_ROR routines
    movw r2, 0x1111
    movt r2, 0x1111
    eor r3, r2, r2, lsl #1 //0x33333333

    // ------------------ RKEYS FOR 2ND QUADRUPLE_ROUND ------------------ 
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r4, r5, lsr #1
    and r5, r5, r2
    orr r5, r14, r5, lsl #3 //1st word rk4
    and r14, r2, r6, lsr #3
    and r1, r6, r4
    orr r1, r14, r1, lsl #1 //NIBBLE_ROR(r6, 3)
    uxth r1, r1
    uxth r6, r6, ror #16
    orr r6, r6, r1, lsl #16 //2nd word rk4
    ror r7, r7, #8 //1st word rk5
    and r14, r3, r8, lsr #2
    and r8, r8, r3
    orr r8, r14, r8, lsl #2 //NIBBLE_ROR(r7,2)
    orr r4, r2, r2, lsl #3 //0x99999999
    and r1, r4, r8
    mvn r4, r4 //0x66666666
    and r8, r8, r4
    orr r8, r1, r8, ror #24 //2nd word rk5
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r2, r9, lsr #3
    and r9, r9, r4
    orr r9, r14, r9, lsl #1 //NIBBLE_ROR(r9, 3) //1st word rk6
    ror r10, r10, #16
    and r14, r4, r10, lsr #1
    and r1, r10, r2
    orr r1, r14, r1, lsl #3 //NIBBLE_ROR(r10, 1)
    uxth r1, r1, ror #8
    uxth r10, r10, ror #24
    ror r10, r10, #8
    orr r10, r10, r1, lsl #8 //2nd word rk6
    ror r11, r11, #24 //1st word rk7
    and r14, r3, r12, lsr #2
    and r12, r12, r3
    orr r12, r14, r12, lsl #2 //NIBBLE_ROR(r12, 2)
    and r1, r12, r3
    mvn r4, r3 //0xcccccccc
    and r12, r12, r4
    orr r12, r1, r12, ror #8 //2nd world rk7
    stmia r0!, {r5-r12}
    // ------------------ RKEYS FOR 3RD QUADRUPLE_ROUND ------------------ 
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r4, r5, lsr #1
    and r5, r5, r2
    orr r5, r14, r5, lsl #3 //1st word rk8
    and r14, r2, r6, lsr #3
    and r1, r6, r4
    orr r1, r14, r1, lsl #1 //NIBBLE_ROR(r6, 3)
    uxth r1, r1
    uxth r6, r6, ror #16
    orr r6, r6, r1, lsl #16 //2nd word rk8
    ror r7, r7, #8 //1st word rk9
    and r14, r3, r8, lsr #2
    and r8, r8, r3
    orr r8, r14, r8, lsl #2 //NIBBLE_ROR(r7,2)
    orr r4, r2, r2, lsl #3 //0x99999999
    and r1, r4, r8
    mvn r4, r4 //0x66666666
    and r8, r8, r4
    orr r8, r1, r8, ror #24 //2nd word rk9
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r2, r9, lsr #3
    and r9, r9, r4
    orr r9, r14, r9, lsl #1 //NIBBLE_ROR(r9, 3) //1st word rk10
    ror r10, r10, #16
    and r14, r4, r10, lsr #1
    and r1, r10, r2
    orr r1, r14, r1, lsl #3 //NIBBLE_ROR(r10, 1)
    uxth r1, r1, ror #8
    uxth r10, r10, ror #24
    ror r10, r10, #8
    orr r10, r10, r1, lsl #8 //2nd word rk10
    ror r11, r11, #24 //1st word rk11
    and r14, r3, r12, lsr #2
    and r12, r12, r3
    orr r12, r14, r12, lsl #2 //NIBBLE_ROR(r12, 2)
    and r1, r12, r3
    mvn r4, r3 //0xcccccccc
    and r12, r12, r4
    orr r12, r1, r12, ror #8 //2nd world rk11
    stmia r0!, {r5-r12}
    // ------------------ RKEYS FOR 4th QUADRUPLE_ROUND ------------------ 
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r4, r5, lsr #1
    and r5, r5, r2
    orr r5, r14, r5, lsl #3 //1st word rk12
    and r14, r2, r6, lsr #3
    and r1, r6, r4
    orr r1, r14, r1, lsl #1 //NIBBLE_ROR(r6, 3)
    uxth r1, r1
    uxth r6, r6, ror #16
    orr r6, r6, r1, lsl #16 //2nd word rk12
    ror r7, r7, #8 //1st word rk13
    and r14, r3, r8, lsr #2
    and r8, r8, r3
    orr r8, r14, r8, lsl #2 //NIBBLE_ROR(r7,2)
    orr r4, r2, r2, lsl #3 //0x99999999
    and r1, r4, r8
    mvn r4, r4 //0x66666666
    and r8, r8, r4
    orr r8, r1, r8, ror #24 //2nd word rk13
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r2, r9, lsr #3
    and r9, r9, r4
    orr r9, r14, r9, lsl #1 //NIBBLE_ROR(r9, 3) //1st word rk14
    ror r10, r10, #16
    and r14, r4, r10, lsr #1
    and r1, r10, r2
    orr r1, r14, r1, lsl #3 //NIBBLE_ROR(r10, 1)
    uxth r1, r1, ror #8
    uxth r10, r10, ror #24
    ror r10, r10, #8
    orr r10, r10, r1, lsl #8 //2nd word rk14
    ror r11, r11, #24 //1st word rk15
    and r14, r3, r12, lsr #2
    and r12, r12, r3
    orr r12, r14, r12, lsl #2 //NIBBLE_ROR(r12, 2)
    and r1, r12, r3
    mvn r4, r3 //0xcccccccc
    and r12, r12, r4
    orr r12, r1, r12, ror #8 //2nd world rk15
    stmia r0!, {r5-r12}
    // ------------------ RKEYS FOR 5th QUADRUPLE_ROUND ------------------ 
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r4, r5, lsr #1
    and r5, r5, r2
    orr r5, r14, r5, lsl #3 //1st word rk16
    and r14, r2, r6, lsr #3
    and r1, r6, r4
    orr r1, r14, r1, lsl #1 //NIBBLE_ROR(r6, 3)
    uxth r1, r1
    uxth r6, r6, ror #16
    orr r6, r6, r1, lsl #16 //2nd word rk16
    ror r7, r7, #8 //1st word rk17
    and r14, r3, r8, lsr #2
    and r8, r8, r3
    orr r8, r14, r8, lsl #2 //NIBBLE_ROR(r7,2)
    orr r4, r2, r2, lsl #3 //0x99999999
    and r1, r4, r8
    mvn r4, r4 //0x66666666
    and r8, r8, r4
    orr r8, r1, r8, ror #24 //2nd word rk17
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r2, r9, lsr #3
    and r9, r9, r4
    orr r9, r14, r9, lsl #1 //NIBBLE_ROR(r9, 3) //1st word rk18
    ror r10, r10, #16
    and r14, r4, r10, lsr #1
    and r1, r10, r2
    orr r1, r14, r1, lsl #3 //NIBBLE_ROR(r10, 1)
    uxth r1, r1, ror #8
    uxth r10, r10, ror #24
    ror r10, r10, #8
    orr r10, r10, r1, lsl #8 //2nd word rk18
    ror r11, r11, #24 //1st word rk19
    and r14, r3, r12, lsr #2
    and r12, r12, r3
    orr r12, r14, r12, lsl #2 //NIBBLE_ROR(r12, 2)
    and r1, r12, r3
    mvn r4, r3 //0xcccccccc
    and r12, r12, r4
    orr r12, r1, r12, ror #8 //2nd world rk19
    stmia r0!, {r5-r12}
    // ------------------ RKEYS FOR 6th QUADRUPLE_ROUND ------------------ 
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r4, r5, lsr #1
    and r5, r5, r2
    orr r5, r14, r5, lsl #3 //1st word rk20
    and r14, r2, r6, lsr #3
    and r1, r6, r4
    orr r1, r14, r1, lsl #1 //NIBBLE_ROR(r6, 3)
    uxth r1, r1
    uxth r6, r6, ror #16
    orr r6, r6, r1, lsl #16 //2nd word rk20
    ror r7, r7, #8 //1st word rk21
    and r14, r3, r8, lsr #2
    and r8, r8, r3
    orr r8, r14, r8, lsl #2 //NIBBLE_ROR(r7,2)
    orr r4, r2, r2, lsl #3 //0x99999999
    and r1, r4, r8
    mvn r4, r4 //0x66666666
    and r8, r8, r4
    orr r8, r1, r8, ror #24 //2nd word rk21
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r2, r9, lsr #3
    and r9, r9, r4
    orr r9, r14, r9, lsl #1 //NIBBLE_ROR(r9, 3) //1st word rk22
    ror r10, r10, #16
    and r14, r4, r10, lsr #1
    and r1, r10, r2
    orr r1, r14, r1, lsl #3 //NIBBLE_ROR(r10, 1)
    uxth r1, r1, ror #8
    uxth r10, r10, ror #24
    ror r10, r10, #8
    orr r10, r10, r1, lsl #8 //2nd word rk22
    ror r11, r11, #24 //1st word rk23
    and r14, r3, r12, lsr #2
    and r12, r12, r3
    orr r12, r14, r12, lsl #2 //NIBBLE_ROR(r12, 2)
    and r1, r12, r3
    mvn r4, r3 //0xcccccccc
    and r12, r12, r4
    orr r12, r1, r12, ror #8 //2nd world rk23
    stmia r0!, {r5-r12}
    // ------------------ RKEYS FOR 7th QUADRUPLE_ROUND ------------------ 
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r4, r5, lsr #1
    and r5, r5, r2
    orr r5, r14, r5, lsl #3 //1st word rk24
    and r14, r2, r6, lsr #3
    and r1, r6, r4
    orr r1, r14, r1, lsl #1 //NIBBLE_ROR(r6, 3)
    uxth r1, r1
    uxth r6, r6, ror #16
    orr r6, r6, r1, lsl #16 //2nd word rk24
    ror r7, r7, #8 //1st word rk25
    and r14, r3, r8, lsr #2
    and r8, r8, r3
    orr r8, r14, r8, lsl #2 //NIBBLE_ROR(r7,2)
    orr r4, r2, r2, lsl #3 //0x99999999
    and r1, r4, r8
    mvn r4, r4 //0x66666666
    and r8, r8, r4
    orr r8, r1, r8, ror #24 //2nd word rk25
    mvn r4, r2, lsl #3 //0x77777777
    and r14, r2, r9, lsr #3
    and r9, r9, r4
    orr r9, r14, r9, lsl #1 //NIBBLE_ROR(r9, 3) //1st word rk26
    ror r10, r10, #16
    and r14, r4, r10, lsr #1
    and r1, r10, r2
    orr r1, r14, r1, lsl #3 //NIBBLE_ROR(r10, 1)
    uxth r1, r1, ror #8
    uxth r10, r10, ror #24
    ror r10, r10, #8
    orr r10, r10, r1, lsl #8 //2nd word rk26
    ror r11, r11, #24 //1st word rk27
    and r14, r3, r12, lsr #2
    and r12, r12, r3
    orr r12, r14, r12, lsl #2 //NIBBLE_ROR(r12, 2)
    and r1, r12, r3
    mvn r4, r3 //0xcccccccc
    and r12, r12, r4
    orr r12, r1, r12, ror #8 //2nd world rk27
    stmia r0!, {r5-r12}

    pop {r1-r12,r14}
    bx lr


/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFT-64 block cipher.
* This function encrypts 2 64-bit blocks in parallel to take advantage of the 
* 32-bit architecture. 
*****************************************************************************/
@ void gift64_encrypt_block(u8 *out, const u32* rkey, const u8 *block0, const u8* block1)
.global gift64_encrypt_block
.type   gift64_encrypt_block,%function
gift64_encrypt_block:

    push {r2-r12,r14}

    // ------------------ PACKING ------------------ 
    // load plaintext blocks
    ldrd r6, r4, [r2]
    ldrd r7, r5, [r3]
    // endianness
    rev r4, r4  //slice0 in r4
    rev r5, r5  //slice1 in r5
    rev r6, r6  //slice2 in r6
    rev r7, r7  //slice3 in r7
    // masks for SWAPMOVE routines
    movw r9, #0x0a0a
    movt r9, #0x0a0a
    movw r10, #0x00cc
    movt r10, #0x00cc
    movw r11, #0x0f0f
    movt r11, #0x0f0f
    movw r12, #0xffff

    eor r3, r4, r4, lsr #3
    and r3, r3, r9
    eor r4, r4, r3
    eor r4, r4, r3, lsl #3 //SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
    eor r3, r5, r5, lsr #3
    and r3, r3, r9
    eor r5, r5, r3
    eor r5, r5, r3, lsl #3 //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
    eor r3, r6, r6, lsr #3
    and r3, r3, r9
    eor r6, r6, r3
    eor r6, r6, r3, lsl #3 //SWAPMOVE(r6, r6, 0x0a0a0a0a, 3)
    eor r3, r7, r7, lsr #3
    and r3, r3, r9
    eor r7, r7, r3
    eor r7, r7, r3, lsl #3 //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3)
    eor r3, r4, r4, lsr #6
    and r3, r3, r10
    eor r4, r4, r3
    eor r4, r4, r3, lsl #6 //SWAPMOVE(r4, r4, 0x00cc00cc, 6)
    eor r3, r5, r5, lsr #6
    and r3, r3, r10
    eor r5, r5, r3
    eor r5, r5, r3, lsl #6 //SWAPMOVE(r5, r5, 0x00cc00cc, 6)
    eor r3, r6, r6, lsr #6
    and r3, r3, r10
    eor r6, r6, r3
    eor r6, r6, r3, lsl #6 //SWAPMOVE(r6, r6, 0x00cc00cc, 6)
    eor r3, r7, r7, lsr #6
    and r3, r3, r10
    eor r7, r7, r3
    eor r7, r7, r3, lsl #6 //SWAPMOVE(r7, r7, 0x00cc00cc, 6)
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    eor r3, r5, r4, lsr #4
    and r3, r3, r11
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x0f0f0f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r11
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x0f0f0f0f, 4)
    eor r3, r6, r4, lsr #16
    and r3, r3, r12
    eor r6, r6, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r6, 0x0000ffff, 16)
    eor r3, r7, r5, lsr #16
    and r3, r3, r12
    eor r7, r7, r3
    eor r5, r5, r3, lsl #16 //SWAPMOVE(r5, r7, 0x0000ffff, 16)

    
    // ------------------ GIFTb-CORE ROUTINE ------------------
    movw r10, #0x1111
    movt r10, #0x1111
    orr r11, r10, r10, lsl #1 //0x33333333 for NIBBLE_ROR
    mvn r12, r10, lsl #3 //0x77777777 for NIBBLE_ROR

    // ------------------ 1st QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0011
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1] //load rkey
    and r8, r4, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r6, r8
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299 //load rconst
    ldrd r2, r3, [r1, #8] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #16] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 1)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #24] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst
    
    // ------------------ 2nd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1199
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #32] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ee
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #40] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9933
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #48] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #56] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 3rd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x9999
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #64] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #72] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #80] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33cc
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #88] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 4th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8899
    movt r9, #0x3300 //load rconst
    ldrd r2, r3, [r1, #96] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #104] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #112] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ee
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #120] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 5th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0099
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #128] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22aa
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #136] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8833
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #144] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x22bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #152] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 6th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1188
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #160] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2266
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #168] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    ldrd r2, r3, [r1, #176] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x3300
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #184] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 7th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8811
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1, #192] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2288
    ldrd r2, r3, [r1, #200] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x0011 //load rconst
    ldrd r2, r3, [r1, #208] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #216] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    ror r6, r6, #16
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    //masks for SWAPMOVE routines
    movw r9, #0x0a0a
    movt r9, #0x0a0a
    movw r10, #0x00cc
    movt r10, #0x00cc
    movw r11, #0x0f0f
    movt r11, #0x0f0f
    movw r12, #0xffff
    eor r3, r6, r4, lsr #16
    and r3, r3, r12
    eor r6, r6, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r6, 0x0000ffff, 16)
    eor r3, r7, r5, lsr #16
    and r3, r3, r12
    eor r7, r7, r3
    eor r5, r5, r3, lsl #16 //SWAPMOVE(r5, r7, 0x0000ffff, 16)
    eor r3, r5, r4, lsr #4
    and r3, r3, r11
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x0f0f0f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r11
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x0f0f0f0f, 4)
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    eor r3, r4, r4, lsr #6
    and r3, r3, r10
    eor r4, r4, r3
    eor r4, r4, r3, lsl #6 //SWAPMOVE(r4, r4, 0x00cc00cc, 6)
    eor r3, r5, r5, lsr #6
    and r3, r3, r10
    eor r5, r5, r3
    eor r5, r5, r3, lsl #6 //SWAPMOVE(r5, r5, 0x00cc00cc, 6)
    eor r3, r6, r6, lsr #6
    and r3, r3, r10
    eor r6, r6, r3
    eor r6, r6, r3, lsl #6 //SWAPMOVE(r6, r6, 0x00cc00cc, 6)
    eor r3, r7, r7, lsr #6
    and r3, r3, r10
    eor r7, r7, r3
    eor r7, r7, r3, lsl #6 //SWAPMOVE(r7, r7, 0x00cc00cc, 6)
    eor r3, r4, r4, lsr #3
    and r3, r3, r9
    eor r4, r4, r3
    eor r4, r4, r3, lsl #3 //SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
    eor r3, r5, r5, lsr #3
    and r3, r3, r9
    eor r5, r5, r3
    eor r5, r5, r3, lsl #3 //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
    eor r3, r6, r6, lsr #3
    and r3, r3, r9
    eor r6, r6, r3
    eor r6, r6, r3, lsl #3 //SWAPMOVE(r6, r6, 0x0a0a0a0a, 3)
    eor r3, r7, r7, lsr #3
    and r3, r3, r9
    eor r7, r7, r3
    eor r7, r7, r3, lsl #3 //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3)
    //endianness
    rev r4, r4
    rev r5, r5
    rev r6, r6
    rev r7, r7
    strd r6, r4, [r0]
    strd r7, r5, [r0, #8]

    pop {r2-r12,r14}
    bx lr


/*****************************************************************************
* Fully unrolled assembly implementation of the GIFT-64 block cipher in 
* CTR mode. The keystream is generated from a 64-bit counter which is incre-
* mented for each block.
* /!\/!\/!\             FOR BENCHMARK PURPOSES ONLY                  /!\/!\/!\
* /!\/!\/!\ THE WAY THE COUNTER IS HANDLED IS NOT SAFE ACCROSS CALLS /!\/!\/!\
*****************************************************************************/
@ void gift64_encrypt_ctr(u8 *ctext, param const* p, const u8* ptext, const u32 ptext_len)
.global gift64_encrypt_ctr
.type   gift64_encrypt_ctr,%function
gift64_encrypt_ctr:
    push {r2-r12,r14}

gift_ctr_encrypt_block:
// ------------------ PACKING ------------------ 
    // load 64-bit counter
    ldrd r6, r4, [r1]
    //increment the ctr for the 2nd block treated in parallel
    adds r5, r4, #1
    adc r7, r6, #0 
    // masks for SWAPMOVE routines
    movw r9, #0x0a0a
    movt r9, #0x0a0a
    movw r10, #0x00cc
    movt r10, #0x00cc
    movw r11, #0x0f0f
    movt r11, #0x0f0f
    movw r12, #0xffff
    eor r3, r4, r4, lsr #3
    and r3, r3, r9
    eor r4, r4, r3
    eor r4, r4, r3, lsl #3 //SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
    eor r3, r5, r5, lsr #3
    and r3, r3, r9
    eor r5, r5, r3
    eor r5, r5, r3, lsl #3 //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
    eor r3, r6, r6, lsr #3
    and r3, r3, r9
    eor r6, r6, r3
    eor r6, r6, r3, lsl #3 //SWAPMOVE(r6, r6, 0x0a0a0a0a, 3)
    eor r3, r7, r7, lsr #3
    and r3, r3, r9
    eor r7, r7, r3
    eor r7, r7, r3, lsl #3 //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3)
    eor r3, r4, r4, lsr #6
    and r3, r3, r10
    eor r4, r4, r3
    eor r4, r4, r3, lsl #6 //SWAPMOVE(r4, r4, 0x00cc00cc, 6)
    eor r3, r5, r5, lsr #6
    and r3, r3, r10
    eor r5, r5, r3
    eor r5, r5, r3, lsl #6 //SWAPMOVE(r5, r5, 0x00cc00cc, 6)
    eor r3, r6, r6, lsr #6
    and r3, r3, r10
    eor r6, r6, r3
    eor r6, r6, r3, lsl #6 //SWAPMOVE(r6, r6, 0x00cc00cc, 6)
    eor r3, r7, r7, lsr #6
    and r3, r3, r10
    eor r7, r7, r3
    eor r7, r7, r3, lsl #6 //SWAPMOVE(r7, r7, 0x00cc00cc, 6)
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    eor r3, r5, r4, lsr #4
    and r3, r3, r11
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x0f0f0f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r11
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x0f0f0f0f, 4)
    eor r3, r6, r4, lsr #16
    and r3, r3, r12
    eor r6, r6, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r6, 0x0000ffff, 16)
    eor r3, r7, r5, lsr #16
    and r3, r3, r12
    eor r7, r7, r3
    eor r5, r5, r3, lsl #16 //SWAPMOVE(r5, r7, 0x0000ffff, 16)

    // ------------------ GIFTb-CORE ROUTINE ------------------
    movw r10, #0x1111
    movt r10, #0x1111
    orr r11, r10, r10, lsl #1 //0x33333333 for NIBBLE_ROR
    mvn r12, r10, lsl #3 //0x77777777 for NIBBLE_ROR

    // ------------------ 1st QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0011
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1, #8] //load rkey
    and r8, r4, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r6, r8
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299 //load rconst
    ldrd r2, r3, [r1, #16] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #24] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #32] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 2nd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1199
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #40] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ee
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #48] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9933
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #56] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #64] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 3rd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x9999
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #72] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #80] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #88] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33cc
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #96] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 4th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8899
    movt r9, #0x3300 //load rconst
    ldrd r2, r3, [r1, #104] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #112] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #120] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ee
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #128] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 5th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0099
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #136] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22aa
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #144] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8833
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #152] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x22bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #160] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 6th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1188
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #168] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2266
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #176] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    ldrd r2, r3, [r1, #184] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x3300
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #192] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 7th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8811
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1, #200] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2288
    ldrd r2, r3, [r1, #208] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x0011 //load rconst
    ldrd r2, r3, [r1, #216] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #224] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    ror r6, r6, #16
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    //masks for SWAPMOVE routines
    movw r9, #0x0a0a
    movt r9, #0x0a0a
    movw r10, #0x00cc
    movt r10, #0x00cc
    movw r11, #0x0f0f
    movt r11, #0x0f0f
    movw r12, #0xffff
    eor r3, r6, r4, lsr #16
    and r3, r3, r12
    eor r6, r6, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r6, 0x0000ffff, 16)
    eor r3, r7, r5, lsr #16
    and r3, r3, r12
    eor r7, r7, r3
    eor r5, r5, r3, lsl #16 //SWAPMOVE(r5, r7, 0x0000ffff, 16)
    eor r3, r5, r4, lsr #4
    and r3, r3, r11
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x0f0f0f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r11
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x0f0f0f0f, 4)
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    eor r3, r4, r4, lsr #6
    and r3, r3, r10
    eor r4, r4, r3
    eor r4, r4, r3, lsl #6 //SWAPMOVE(r4, r4, 0x00cc00cc, 6)
    eor r3, r5, r5, lsr #6
    and r3, r3, r10
    eor r5, r5, r3
    eor r5, r5, r3, lsl #6 //SWAPMOVE(r5, r5, 0x00cc00cc, 6)
    eor r3, r6, r6, lsr #6
    and r3, r3, r10
    eor r6, r6, r3
    eor r6, r6, r3, lsl #6 //SWAPMOVE(r6, r6, 0x00cc00cc, 6)
    eor r3, r7, r7, lsr #6
    and r3, r3, r10
    eor r7, r7, r3
    eor r7, r7, r3, lsl #6 //SWAPMOVE(r7, r7, 0x00cc00cc, 6)
    eor r3, r4, r4, lsr #3
    and r3, r3, r9
    eor r4, r4, r3
    eor r4, r4, r3, lsl #3 //SWAPMOVE(r4, r4, 0x0a0a0a0a, 3)
    eor r3, r5, r5, lsr #3
    and r3, r3, r9
    eor r5, r5, r3
    eor r5, r5, r3, lsl #3 //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3)
    eor r3, r6, r6, lsr #3
    and r3, r3, r9
    eor r6, r6, r3
    eor r6, r6, r3, lsl #3 //SWAPMOVE(r6, r6, 0x0a0a0a0a, 3)
    eor r3, r7, r7, lsr #3
    and r3, r3, r9
    eor r7, r7, r3
    eor r7, r7, r3, lsl #3 //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3)
    //endianness
    rev r4, r4
    rev r5, r5
    rev r6, r6
    rev r7, r7

    // ------------------ ENCRYPT PTEXT WITH KEYSTREAM ------------------
    //load 'ptext' and XOR it with the keystream
    ldr.w r12, [sp]
    ldmia r12!, {r8-r11}
    eor r8, r8, r6
    eor r9, r9, r4
    eor r10, r10, r7
    eor r11, r11, r5
    stmia r0!, {r8-r11} //r0 now points to the next ctext block
    ldr.w r12, [sp] //now points to the next ptext block
    // ------------------ UPDATE COUNTERS AND ADRESSES ------------------
    //decrement 'ptext_len' by 16 (2*block size)
    ldr.w r4, [sp, #4]
    subs r4, #16
    ble gift_ctr_exit
    str.w r4, [sp, #4]
    //increment 'p.ctr' by 2
    ldrd r4, r5, [r1]
    adds r5, #2
    adc r4, #0
    strd r4, r5, [r1]
    b gift_ctr_encrypt_block

gift_ctr_exit:
    pop {r2-r12,r14}
    bx lr


/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-64 block cipher.
* This function encrypts 2 64-bit blocks in parallel to take advantage of the 
* 32-bit architecture. 
*****************************************************************************/
@ void giftb64_encrypt_block(u8 *out, const u32* rkey, const u8 *block0, const u8* block1)
.global giftb64_encrypt_block
.type   giftb64_encrypt_block,%function
giftb64_encrypt_block:

    push {r2-r12,r14}

    // load plaintext blocks
    ldrd r6, r4, [r2]
    ldrd r7, r5, [r3]
    // endianness
    rev r4, r4  //slice0 in r4
    rev r5, r5  //slice1 in r5
    rev r6, r6  //slice2 in r6
    rev r7, r7  //slice3 in r7

    // ------------------ PACKING INTERLEAVE ------------------
    // masks for SWAPMOVE routines
    movw r9, #0x0f0f
    orr r10, r9, r9, lsl #4
    eor r3, r5, r4, lsr #4
    and r3, r3, r9
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x00000f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r9
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x00000f0f, 4)
    eor r3, r5, r4, lsr #16
    and r3, r3, r10
    eor r5, r5, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r5, 0x0000ffff, 16)
    eor r3, r7, r6, lsr #16
    and r3, r3, r10
    eor r7, r7, r3
    eor r6, r6, r3, lsl #16 //SWAPMOVE(r6, r7, 0x0000ffff, 16)
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    
    // ------------------ GIFTb-CORE ROUTINE ------------------
    movw r10, #0x1111
    movt r10, #0x1111
    orr r11, r10, r10, lsl #1 //0x33333333 for NIBBLE_ROR
    mvn r12, r10, lsl #3 //0x77777777 for NIBBLE_ROR

    // ------------------ 1st QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0011
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1] //load rkey
    and r8, r4, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r6, r8
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299 //load rconst
    ldrd r2, r3, [r1, #8] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #16] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #24] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 2nd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1199
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #32] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ee
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #40] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9933
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #48] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #56] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 3rd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x9999
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #64] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #72] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #80] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33cc
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #88] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 4th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8899
    movt r9, #0x3300 //load rconst
    ldrd r2, r3, [r1, #96] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #104] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #112] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ee
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #120] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 5th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0099
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #128] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22aa
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #136] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8833
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #144] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x22bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #152] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 6th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1188
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #160] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2266
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #168] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    ldrd r2, r3, [r1, #176] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x3300
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #184] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 7th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8811
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1, #192] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2288
    ldrd r2, r3, [r1, #200] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x0011 //load rconst
    ldrd r2, r3, [r1, #208] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #216] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    ror r6, r6, #16
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ UNPACKING INTERLEAVE ------------------/
    // masks for SWAPMOVE routines
    movw r9, #0x0f0f
    orr r10, r9, r9, lsl #4
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    eor r3, r5, r4, lsr #16
    and r3, r3, r10
    eor r5, r5, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r5, 0x0000ffff, 16)
    eor r3, r7, r6, lsr #16
    and r3, r3, r10
    eor r7, r7, r3
    eor r6, r6, r3, lsl #16 //SWAPMOVE(r6, r7, 0x0000ffff, 16)
    eor r3, r5, r4, lsr #4
    and r3, r3, r9
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x00000f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r9
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x00000f0f, 4)

    rev r4, r4
    rev r5, r5
    rev r6, r6
    rev r7, r7
    stm r0, {r4-r7}
    pop {r2-r12,r14}
    bx lr

/*****************************************************************************
* Fully unrolled assembly implementation of the GIFTb-64 block cipher in 
* CTR mode. The keystream is generated from a 64-bit counter which is incre-
* mented for each block.
* /!\/!\/!\             FOR BENCHMARK PURPOSES ONLY                  /!\/!\/!\
* /!\/!\/!\ THE WAY THE COUNTER IS HANDLED IS NOT SAFE ACCROSS CALLS /!\/!\/!\
*****************************************************************************/
@ void giftb64_encrypt_ctr(u8 *ctext, param const* p, const u8* ptext, const u32 ptext_len)
.global giftb64_encrypt_ctr
.type   giftb64_encrypt_ctr,%function
giftb64_encrypt_ctr:
    push {r2-r12,r14}

giftb_ctr_encrypt_block:
    // ------------------ PACKING INTERLEAVE ------------------
    // load 64-bit counter
    ldrd r6, r4, [r1]
    //increment the ctr for the 2nd block treated in parallel
    adds r5, r4, #1
    adc r7, r6, #0 
    // masks for SWAPMOVE routines
    movw r9, #0x0f0f
    orr r10, r9, r9, lsl #4
    eor r3, r5, r4, lsr #4
    and r3, r3, r9
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x00000f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r9
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x00000f0f, 4)
    eor r3, r5, r4, lsr #16
    and r3, r3, r10
    eor r5, r5, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r5, 0x0000ffff, 16)
    eor r3, r7, r6, lsr #16
    and r3, r3, r10
    eor r7, r7, r3
    eor r6, r6, r3, lsl #16 //SWAPMOVE(r6, r7, 0x0000ffff, 16)
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)

    // ------------------ GIFTb-CORE ROUTINE ------------------
    movw r10, #0x1111
    movt r10, #0x1111
    orr r11, r10, r10, lsl #1 //0x33333333 for NIBBLE_ROR
    mvn r12, r10, lsl #3 //0x77777777 for NIBBLE_ROR

    // ------------------ 1st QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0011
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1, #8] //load rkey
    and r8, r4, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r6, r8
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299 //load rconst
    ldrd r2, r3, [r1, #16] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #24] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #32] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 2nd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1199
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #40] //load rkey
    //and r8, r4, r6 //sbox layer
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ee
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #48] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9933
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #56] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #64] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 3rd QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x9999
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #72] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22ff
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #80] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    movt r9, #0x1111 //load rconst
    ldrd r2, r3, [r1, #88] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x33cc
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #96] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 4th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8899
    movt r9, #0x3300 //load rconst
    ldrd r2, r3, [r1, #104] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2299
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #112] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #120] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00ee
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #128] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 5th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x0099
    movt r9, #0x3311 //load rconst
    ldrd r2, r3, [r1, #136] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x22aa
    movt r9, #0x9900 //load rconst
    ldrd r2, r3, [r1, #144] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8833
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #152] //load rkey
    //and r8, r4, r6 //sbox layer
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x22bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #160] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 6th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x1188
    movt r9, #0x2211 //load rconst
    ldrd r2, r3, [r1, #168] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2266
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #176] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x9922
    ldrd r2, r3, [r1, #184] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x3300
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #192] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ 7th QUADRUPLE ROUND ------------------
    //1st round
    movw r9, #0x8811
    movt r9, #0x2200 //load rconst
    ldrd r2, r3, [r1, #200] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r12, r5, lsr #1
    and r5, r5, r10
    orr r5, r8, r5, lsl #3 //NIBBLE_ROR(r5, 1)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r10, r4, lsr #3
    and r4, r12, r4
    orr r4, r8, r4, lsl #1 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //2nd round
    movw r9, #0x2288
    ldrd r2, r3, [r1, #208] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #8 //add 2nd keyword
    eor r7, r9, r7, ror #24 //add rconst
    //3rd round
    movw r9, #0x8811
    movt r9, #0x0011 //load rconst
    ldrd r2, r3, [r1, #216] //load rkey
    and r8, r4, r6, ror #16 //sbox layer
    eor r5, r5, r8
    and r8, r5, r7
    eor r4, r4, r8
    orr r8, r4, r5
    eor r6, r8, r6, ror #16
    eor r7, r7, r6
    eor r5, r5, r7
    and r8, r4, r5
    eor r6, r6, r8
    and r8, r10, r5, lsr #3
    and r5, r5, r12
    orr r5, r8, r5, lsl #1 //NIBBLE_ROR(r5, 3)
    and r8, r11, r6, lsr #2
    and r6, r6, r11
    orr r6, r8, r6, lsl #2 //NIBBLE_ROR(r6, 2)
    and r8, r12, r4, lsr #1
    and r4, r10, r4
    orr r4, r8, r4, lsl #3 //NIBBLE_ROR(r4, 3)
    eor r7, r7, r2 //add 1st keyword
    eor r5, r5, r3 //add 2nd keyword
    eor r4, r4, r9 //add rconst
    //4th round
    movw r9, #0x00bb
    movt r9, #0x8800 //load rconst
    ldrd r2, r3, [r1, #224] //load rkey
    and r8, r7, r6 //sbox layer
    eor r5, r5, r8
    and r8, r5, r4
    eor r7, r7, r8
    orr r8, r7, r5
    eor r6, r6, r8
    eor r4, r4, r6
    eor r5, r5, r4
    and r8, r7, r5
    eor r6, r6, r8
    ror r6, r6, #16
    eor r4, r4, r2 //add 1st keyword
    eor r5, r3, r5, ror #24 //add 2nd keyword
    eor r7, r9, r7, ror #8 //add rconst

    // ------------------ UNPACKING INTERLEAVE ------------------/
    // masks for SWAPMOVE routines
    movw r9, #0x0f0f
    orr r10, r9, r9, lsl #4
    eor r3, r4, r4, lsr #8
    and r3, r3, #0xff00
    eor r4, r4, r3
    eor r4, r4, r3, lsl #8 //SWAPMOVE(r4, r4, 0x0000ff00, 8)
    eor r3, r5, r5, lsr #8
    and r3, r3, #0xff00
    eor r5, r5, r3
    eor r5, r5, r3, lsl #8 //SWAPMOVE(r5, r5, 0x0000ff00, 8)
    eor r3, r6, r6, lsr #8
    and r3, r3, #0xff00
    eor r6, r6, r3
    eor r6, r6, r3, lsl #8 //SWAPMOVE(r6, r6, 0x0000ff00, 8)
    eor r3, r7, r7, lsr #8
    and r3, r3, #0xff00
    eor r7, r7, r3
    eor r7, r7, r3, lsl #8 //SWAPMOVE(r7, r7, 0x0000ff00, 8)
    eor r3, r5, r4, lsr #16
    and r3, r3, r10
    eor r5, r5, r3
    eor r4, r4, r3, lsl #16 //SWAPMOVE(r4, r5, 0x0000ffff, 16)
    eor r3, r7, r6, lsr #16
    and r3, r3, r10
    eor r7, r7, r3
    eor r6, r6, r3, lsl #16 //SWAPMOVE(r6, r7, 0x0000ffff, 16)
    eor r3, r5, r4, lsr #4
    and r3, r3, r9
    eor r5, r5, r3
    eor r4, r4, r3, lsl #4 //SWAPMOVE(r4, r5, 0x00000f0f, 4)
    eor r3, r7, r6, lsr #4
    and r3, r3, r9
    eor r7, r7, r3
    eor r6, r6, r3, lsl #4 //SWAPMOVE(r6, r7, 0x00000f0f, 4)
    //endianness
    rev r4, r4
    rev r5, r5
    rev r6, r6
    rev r7, r7

    // ------------------ ENCRYPT PTEXT WITH KEYSTREAM ------------------
    //load 'ptext' and XOR it with the keystream
    ldr.w r12, [sp]
    ldmia r12!, {r8-r11}
    eor r8, r8, r6
    eor r9, r9, r4
    eor r10, r10, r7
    eor r11, r11, r5
    stmia r0!, {r8-r11} //r0 now points to the next ctext block
    ldr.w r12, [sp] //now points to the next ptext block
    // ------------------ UPDATE COUNTERS AND ADRESSES ------------------
    //decrement 'ptext_len' by 16 (2*block size)
    ldr.w r4, [sp, #4]
    subs r4, #16
    ble giftb_ctr_exit
    str.w r4, [sp, #4]
    //increment 'p.ctr' by 2
    ldrd r4, r5, [r1]
    adds r5, #2
    adc r4, #0
    strd r4, r5, [r1]
    b giftb_ctr_encrypt_block

giftb_ctr_exit:
    pop {r2-r12,r14}
    bx lr
