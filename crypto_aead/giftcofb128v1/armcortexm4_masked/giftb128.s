/****************************************************************************
* 1st order masked ARM assembly implementation of the GIFT-128 block cipher.
* See 'Fixslicing: A New GIFT Representation' paper available at
* https://eprint.iacr.org/2020/412 for more details.
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     July 2021
****************************************************************************/

.syntax unified
.thumb

.type rconst,%object
rconst:
.word 0x10000008, 0x80018000, 0x54000002, 0x01010181
.word 0x8000001f, 0x10888880, 0x6001e000, 0x51500002
.word 0x03030180, 0x8000002f, 0x10088880, 0x60016000
.word 0x41500002, 0x03030080, 0x80000027, 0x10008880
.word 0x4001e000, 0x11500002, 0x03020180, 0x8000002b
.word 0x10080880, 0x60014000, 0x01400002, 0x02020080
.word 0x80000021, 0x10000080, 0x0001c000, 0x51000002
.word 0x03010180, 0x8000002e, 0x10088800, 0x60012000
.word 0x40500002, 0x01030080, 0x80000006, 0x10008808
.word 0xc001a000, 0x14500002, 0x01020181, 0x8000001a

/******************************************************************************
* Macro to compute the SWAPMOVE technique.
*   - out0,out1     output registers
*   - in0,in1       input registers
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
*   - m0,m1         masks
*   - n0,n1         shift value
*   - tmp           temporary register
******************************************************************************/
.macro nibror   out, in, m0, m1, n0, n1, tmp
    and     \tmp, \m0, \in, lsr \n0
    and     \out, \in, \m1
    orr     \out, \tmp, \out, lsl \n1
.endm

/******************************************************************************
* 1st-order secure AND between two masked values. Technique from the paper
* 'Optimal First-Order Boolean Masking for Embedded IoT Devices' available at
* https://orbilu.uni.lu/bitstream/10993/37740/1/Optimal_Masking.pdf.
*   - z1,z2         output shares
*   - x1,x2         1st input shares
*   - y1,y2         2nd input shares
*   - tmp           temporary register
******************************************************************************/
.macro secand   z1, z2, x1, x2, y1, y2, tmp
    orn     \tmp, \x1, \y2
    and     \z1, \x1, \y1
    eor     \z1, \tmp, \z1
    orn     \tmp, \x2, \y2
    and     \z2, \x2, \y1
    eor     \z2, \z2, \tmp
.endm

/******************************************************************************
* 1st-order secure OR between two masked values. Technique from the paper
* 'Optimal First-Order Boolean Masking for Embedded IoT Devices' available at
* https://orbilu.uni.lu/bitstream/10993/37740/1/Optimal_Masking.pdf.
*   - z1,z2         output shares
*   - x1,x2         1st input shares
*   - y1,y2         2nd input shares
*   - tmp           temporary register
******************************************************************************/
.macro secor    z1, z2, x1, x2, y1, y2, tmp
    orr     \tmp, \x1, \y2
    and     \z1, \x1, \y1
    eor     \z1, \tmp, \z1
    and     \tmp, \x2, \y2
    orr     \z2, \x2, \y1
    eor     \z2, \z2, \tmp
.endm

/******************************************************************************
* 1st-order secure XOR between two masked values.
*   - z1,z2         output shares
*   - x1,x2         1st input shares
*   - y1,y2         2nd input shares
******************************************************************************/
.macro secxor   z1, z2, x1, x2, y1, y2
    eor     \z1, \x1, \y1
    eor     \z2, \x2, \y2
.endm

/******************************************************************************
* 1st-order masked S-box. Registers r10,r3 always refer to state[1] while 
* r11,r4 always refer to state[2].
*   - in0           1st input register (i.e. state[0])
*   - in3           4th input register (i.e. state[3])
******************************************************************************/
.macro sbox     in0, in0_m, in3, in3_m
    secand  r8, r7, \in0, \in0_m, r11, r4, r6
    secxor  r10, r3, r10, r3, r8, r7
    secand  r8, r7, r10, r3, \in3, \in3_m, r6
    secxor  \in0, \in0_m, \in0, \in0_m, r8, r7
    secor   r8, r7, \in0, \in0_m, r10, r3, r6
    secxor  r11, r4, r11, r4, r8, r7
    secxor  \in3, \in3_m, \in3, \in3_m, r11, r4
    secxor  r10, r3, r10, r3, \in3, \in3_m
    secand  r8, r7, \in0, \in0_m, r10, r3, r6
    secxor  r11, r4, r11, r4, r8, r7
    mvn     \in3, \in3
.endm

/******************************************************************************
* 1st-order masked linear layer for rounds i s.t. i % 5 = 0.
******************************************************************************/
.macro llayer0
    mvn     r6, r14, lsl #3                 // r6<- 0x77777777 for nibror
    nibror  r12, r12, r6, r14, 1, 3, r8     // nibror(r12,1)
    nibror  r5, r5, r6, r14, 1, 3, r8       // mask correction
    nibror  r11, r11, r14, r6, 3, 1, r8     // nibror(r11,3)
    nibror  r4, r4, r14, r6, 3, 1, r8       // mask correction
    orr     r6, r14, r14, lsl #1            // r6 <- 0x33333333 for nibror
    nibror  r10, r10, r6, r6, 2, 2, r8      // nibror(r10, 2)
    nibror  r3, r3, r6, r6, 2, 2, r8        // mask correction
.endm

/******************************************************************************
* 1st-order masked linear layer for rounds i s.t. i % 5 = 1.
******************************************************************************/
.macro llayer1
    movw    r6, #0x000f
    movt    r6, #0x000f                     // r6 <- 0x000f000f for halfror
    mvn     r7, r6, lsl #12                 // r7 <- 0x0fff0fff for halfror
    nibror  r9, r9, r7, r6,  4,  12, r8     // halfror(r9,4)
    nibror  r2, r2, r7, r6,  4,  12, r8     // mask correction
    nibror  r11, r11, r6, r7,  12,  4, r8   // halfror(r11,12)
    nibror  r4, r4, r6, r7,  12,  4, r8     // mask correction
    rev16   r10, r10                        // halfror(r10,8)
    rev16   r3, r3                          // mask correction
.endm

/******************************************************************************
* 1st-order masked linear layer for rounds i s.t. i % 5 = 2.
******************************************************************************/
.macro llayer2
    movw    r6, #0x5555
    movt    r6, #0x5555                     // r6 <- 0x55555555 for swpmv
    swpmv   r10, r10, r10, r10, r6, #1, r8  // swpmv(r10, r10, 0x55..55, 1)
    swpmv   r3, r3, r3, r3, r6, #1, r8      // mask correction
    eor     r8, r12, r12, lsr #1
    and     r8, r8, r6, lsr #16
    eor     r12, r12, r8
    eor     r12, r12, r8, lsl #1            // swpmv(r12, r12, 0x55550000, 1)
    eor     r8, r5, r5, lsr #1
    and     r8, r8, r6, lsr #16
    eor     r5, r5, r8
    eor     r5, r5, r8, lsl #1              // mask correction
    eor     r8, r11, r11, lsr #1
    and     r8, r8, r6, lsl #16
    eor     r11, r11, r8
    eor     r11, r11, r8, lsl #1            // swpmv(r11, r11, 0x00005555, 1)
    eor     r8, r4, r4, lsr #1
    and     r8, r8, r6, lsl #16
    eor     r4, r4, r8
    eor     r4, r4, r8, lsl #1              // mask correction
.endm

/******************************************************************************
* 1st-order masked linear layer for rounds i s.t. i % 5 = 3.
******************************************************************************/
.macro llayer3
    movw    r6, #0x0f0f
    movt    r6, #0x0f0f                     // r6 <- 0x0f0f0f0f for byteror
    nibror  r10, r10, r6, r6, #4, #4, r8    // byteror(r10,4)
    nibror  r3, r3, r6, r6, #4, #4, r8      // mask correction
    orr     r6, r6, r6, lsl #2              // r6 <- 0x3f3f3f3f for byteror
    mvn     r8, r6
    and     r7, r8, r11, lsl #6
    and     r11, r6, r11, lsr #2
    orr     r11, r11, r7                    // byteror(r11,2)
    and     r7, r8, r4, lsl #6
    and     r4, r6, r4, lsr #2
    orr     r4, r4, r7                      // mask correction
    mvn     r8, r6, lsr #6                  // r8 <- 0xc0c0c0c0 for byteror
    nibror  r9, r9, r8, r6, #6, #2, r7      // byteror(r9, 6)
    nibror  r2, r2, r8, r6, #6, #2, r7      // mask correction
.endm

/******************************************************************************
* 1st-order masked add round key.
******************************************************************************/
.macro ark  in0, ror_idx0, ror_idx1
    ldr.w   r6, [r1], #4                    // load 1st rkey word
    ldr.w   r7, [r1], #4                    // load 2nd rkey word
    eor     r10, r6, r10, ror \ror_idx0     // add 1st rkey word
    eor     r11, r7, r11, ror \ror_idx1     // add 2nd rkey word
    ldr.w   r6, [r1, #312]                  // load 1st rkey_mask
    ldr.w   r7, [r1, #316]                  // load 2nd rkey_mask
    ldr.w   r14, [r0], #4                   // load rconst
    eor     r3, r6, r3, ror \ror_idx0       // mask correction
    eor     r4, r7, r4, ror \ror_idx1       // mask correction
    eor     \in0, \in0, r14                 // add rconst
.endm

/******************************************************************************
* 1st-order masked quintuple round.
******************************************************************************/
quintuple_round_masked:
    str.w   r14, [sp]
    movw r14, #0x1111
    movt r14, #0x1111                       // r14<- 0x11111111
    sbox    r9, r2, r12, r5                 // 1st round
    llayer0
    ark     r9, #0, #0
    sbox    r12, r5, r9, r2                 // 2nd round
    llayer1
    ark     r12, #0, #0
    sbox    r9, r2, r12, r5                 // 3rd round
    llayer2
    ark     r9, #0, #16
    ror     r5, #16
    ror     r12, #16
    sbox    r12, r5, r9, r2                 // 4th round
    llayer3 
    ark     r12, #0, #0
    sbox    r9, r2, r12, r5                 // 5th round
    ark     r9, #16, #8
    ldr.w   r14, [sp]
    eor     r9, r9, r12, ror #24
    eor     r12, r9, r12, ror #24
    eor     r9, r9, r12                     // swap r9 with r12 >>> 24
    eor     r2, r2, r5, ror #24
    eor     r5, r2, r5, ror #24
    eor     r2, r2, r5                      // swap r2 with r5 >>> 24
    bx      lr

/*****************************************************************************
* 1st order masked implementation of the GIFTb-128 block cipher. This function
* simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void giftb128_encrypt_block(u8 *out, const u32* rkey, const u8 *block)
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push    {r0-r12,r14}
    ldm     r2, {r6-r8,r14}         // load plaintext blocks
    rev     r6, r6
    rev     r7, r7
    rev     r8, r8
    rev     r14, r14
    // ------------------ MASKING ------------------
    // generation of 4 random words
    movw    r11, 0x0804
    movt    r11, 0x5006             // r11<- RNG_SR = 0x50060804
    mov     r12, #4
    add     r9, r11, #4             // r9 <- RNG_DR = 0x50060808
giftb128_block_get_random:
    ldr     r10, [r11]
    cmp     r10, #1                 // check if RNG_SR == RNG_SR_DRDY
    bne     giftb128_block_get_random
    ldr     r10, [r9]               // put the random number in r10
    push    {r10}                   // push r10 on the stack
    subs    r12, #1
    bne     giftb128_block_get_random
    pop     {r2-r5}                 // pop the randomn numbers from the stack
    eor     r9, r2, r6              // apply masks to the internal state
    eor     r10, r3, r7             // apply masks to the internal state
    eor     r11, r4, r8             // apply masks to the internal state
    eor     r12, r5, r14            // apply masks to the internal state
    // ------------------ GIFTb-CORE ROUTINE ------------------
    adr     r0, rconst              // put 'rconst' address in r0
    sub.w   sp, #4                  // allocate space on stack to store 'lr'
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    bl      quintuple_round_masked
    add.w   sp, #4
    ldr.w   r0, [sp]                // restore 'ctext' address
    // ------------------ UNMASKING ------------------
    mov     r6, r9
    mov     r9, #0                  // clear r9 before unmasking to avoid HD leakages
    mov     r7, r10
    mov     r10, #0                 // clear r10 before unmasking to avoid HD leakages
    mov     r8, r11
    mov     r11, #0                 // clear r11 before unmasking to avoid HD leakages
    mov     r14, r12
    mov     r12, #0                 // clear r12 before unmasking to avoid HD leakages
    eor     r9, r6, r2              // unmask the internal state
    eor     r10, r7, r3             // unmask the internal state
    eor     r11, r8, r4             // unmask the internal state
    eor     r12, r14, r5            // unmask the internal state
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    stm     r0, {r9-r12}           // store output in RAM
    pop     {r0-r12,r14}           // restore context
    bx      lr

/******************************************************************************
* Macro to compute the GIFT-128 key update (in its classical representation).
* Two 16-bit rotations are computed on the 32-bit word 'v' given as input.
*   - u     1st round key word as defined in the specification (U <- W2||W3)
*   - v     2nd round key word as defined in the specification (V <- W6||W7)
******************************************************************************/
.macro k_upd  u, v
    and     r2, r10, \v, lsr #12
    and     r3, \v, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, \v, lsr #2
    orr     r2, r2, r3
    and     \v, \v, #0x00030000
    orr     \v, r2, \v, lsl #14
    str.w   \u, [r1], #4
    str.w   \v, [r1], #4
.endm

/******************************************************************************
* Macro to rearrange round key words from their classical to fixsliced
* representations.
*   - rk0   1st round key word
*   - rk1   2nd round key word
*   - idx0  index for SWAPMOVE
*   - idx1  index for SWAPMOVE
*   - tmp   temporary register for SWAPMOVE
******************************************************************************/
.macro rearr_rk rk0, rk1, idx0, idx1, tmp
    swpmv   \rk1, \rk1, \rk1, \rk1, r3, \idx0, \tmp
    swpmv   \rk0, \rk0, \rk0, \rk0, r3, \idx0, \tmp
    swpmv   \rk1, \rk1, \rk1, \rk1, r10, \idx1, \tmp
    swpmv   \rk0, \rk0, \rk0, \rk0, r10, \idx1, \tmp
    swpmv   \rk1, \rk1, \rk1, \rk1, r11, #12, \tmp
    swpmv   \rk0, \rk0, \rk0, \rk0, r11, #12, \tmp
    swpmv   \rk1, \rk1, \rk1, \rk1, #0xff, #24, \tmp
    swpmv   \rk0, \rk0, \rk0, \rk0, #0xff, #24, \tmp
.endm

/******************************************************************************
* Macro to compute a triple key update on a round key word for a given round
* number s.t. round number % 5 = 0.
*   - rk0   the rkey word to be updated thrice
*   - rk1   the other rkey word for the given word (no update needed)
*   - idx0  index to store the 1st rkey word (= round number * 8)
*   - idx1  index to store the 2nd rkey word (= round number * 8 + 4)
******************************************************************************/
.macro tpl_upd_0 rk0, rk1, idx0, idx1
    and     r2, r12, \rk0, ror #24
    and     \rk0, \rk0, r11
    orr     \rk0, r2, \rk0, ror #16
    swpmv   \rk0, \rk0, \rk0, \rk0, r8, #1, r2
    swpmv   \rk1, \rk1, \rk1, \rk1, r10, #16, r2
    swpmv   \rk1, \rk1, \rk1, \rk1, r9, #1, r2
    str.w   \rk1, [r1, \idx0]
    str.w   \rk0, [r1, \idx1]
.endm

/******************************************************************************
* Macro to compute a triple key update on a round key word for a given round
* number s.t. round number % 5 = 1.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro tpl_upd_1 rk, idx
    and     r2, r9, \rk, lsr #6
    and     r3, \rk, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, \rk, lsr #5
    orr     r2, r2, r3
    and     \rk, \rk, r7
    orr     \rk, r2, \rk, lsl #3
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a double key update on a round key word for a given round
* number s.t. round number % 5 = 1.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro dbl_upd_1 rk, idx
    and     r2, r12, \rk, lsr #4
    and     r3, \rk, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, \rk, lsr #6
    orr     r2, r2, r3
    and     \rk, \rk, r10
    orr     \rk, r2, \rk, lsl #2
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a triple key update on a round key word for a given round
* number s.t. round number % 5 = 2.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro tpl_upd_2 rk, idx
    and     r2, r12, \rk, ror #24
    and     \rk, r11, \rk, ror #20
    orr     \rk, \rk, r2
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a double key update on a round key word for a given round
* number s.t. round number % 5 = 2.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro dbl_upd_2 rk, idx
    and     r2, r11, \rk, ror #24
    and     \rk, r12, \rk, ror #16
    orr     \rk, \rk, r2
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a triple key update on a round key word for a given round
* number s.t. round number % 5 = 3.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro tpl_upd_3 rk, idx
    and     r2, r10, \rk, lsr #18
    and     r3, \rk, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, \rk, lsr #14
    orr     r2, r2, r3
    and     r3, \rk, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, \rk, lsr #1
    orr     r2, r2, r3
    and     \rk, \rk, r7, lsr #16
    orr     \rk, r2, \rk, lsl #19
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a double key update on a round key word for a given round
* number s.t. round number % 5 = 3.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro dbl_upd_3 rk, idx
    and     r2, r9, \rk, lsr #2
    and     r3, r9, \rk
    orr     r2, r2, r3, lsl #2
    and     r3, r8, \rk, lsr #1
    orr     r2, r2, r3
    and     \rk, \rk, r7
    orr     \rk, r2, \rk, lsl #3
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a triple key update on a round key word for a given round
* number s.t. round number % 5 = 4.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro tpl_upd_4 rk, idx
    and     r2, r7, \rk, lsr #6
    and     r3, \rk, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, \rk, lsr #4
    orr     r2, r2, r3
    and     \rk, \rk, #0x000f
    orr     \rk, r2, \rk, lsl #12
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Macro to compute a double key update on a round key word for a given round
* number s.t. round number % 5 = 4.
*   - rk    the rkey word to be updated thrice
*   - idx   index to store the rkey word
******************************************************************************/
.macro dbl_upd_4 rk, idx
    and     r2, r10, \rk, lsr #4
    and     r3, \rk, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, \rk, lsr #8
    orr     r2, r2, r3
    and     \rk, \rk, r8
    orr     \rk, r2, \rk, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   \rk, [r1, \idx]
.endm

/******************************************************************************
* Soubroutine to update the rkeys according to the classical representation.
******************************************************************************/
.align 2
classical_key_update:
    k_upd   r5, r7                  // 1st classical key update
    k_upd   r4, r6                  // 2nd classical key update
    k_upd   r7, r5                  // 3rd classical key update
    k_upd   r6, r4                  // 4th classical key update
    bx      lr

/******************************************************************************
* Soubroutine to rearrange round key words from classical to fixsliced
* representation for round i s.t. i mod 5 = 0.
******************************************************************************/
.align 2
rearrange_rkey_0:
    ldr.w       r6, [r1]                // load 1st rkey word (classical rep)
    ldr.w       r4, [r1, #4]            // load 2nd rkey word (classical rep)
    rearr_rk    r4, r6, #9, #18, r12    // rearrange rkey words for round 1
    str.w       r4, [r1, #4]            // store 2nd rkey word (fixsliced rep)
    str.w       r6, [r1], #40           // store 1st rkey word (fixsliced rep)
    bx          lr

/******************************************************************************
* Soubroutine to rearrange round key words from classical to fixsliced
* representation for round i s.t. i mod 5 = 1 or 3.
******************************************************************************/
.align 2
rearrange_rkey_1:
    ldr.w       r5, [r1]                // load 3rd rkey word (classical rep)
    ldr.w       r7, [r1, #4]            // load 4th rkey word (classical rep)
    rearr_rk    r5, r7, #3, #6, r8      // rearrange rkey words for round 2
    str.w       r7, [r1, #4]            // store 4th rkey word (fixsliced rep)
    str.w       r5, [r1], #40           // store 3rd rkey word (fixsliced rep)
    bx          lr

/******************************************************************************
* Soubroutine to rearrange round key words from classical to fixsliced
* representation for round i s.t. i mod 5 = 2.
******************************************************************************/
.align 2
rearrange_rkey_2:
    ldr.w       r5, [r1]                // load 5th rkey word (classical rep)
    ldr.w       r7, [r1, #4]            // load 6th rkey word (classical rep)
    rearr_rk    r5, r7, #15, #18, r8    // rearrange rkey words for round 3
    str.w       r7, [r1, #4]            // store 6th rkey word (fixsliced rep)
    str.w       r5, [r1], #40           // store 5th rkey word (fixsliced rep)
    bx          lr

/******************************************************************************
* Soubroutine to update round key words according to fixslicing for round i
* s.t. i mod 5 = 0.
******************************************************************************/
.align 2
key_update_0:
    ldr.w       r4, [r1]                // load 1st rkey word for round i
    ldr.w       r5, [r1, #4]            // load 2nd rkey word for round i
    tpl_upd_0   r4, r5, #80, #84        // compute rkey words for round i+10
    tpl_upd_0   r5, r4, #160, #164      // compute rkey words for round i+20
    tpl_upd_0   r4, r5, #240, #244      // compute rkey words for round i+30
    bx          lr

/******************************************************************************
* Soubroutine to update round key words according to fixslicing for round i
* s.t. i mod 5 = 1.
******************************************************************************/
.align 2
key_update_1:
    ldr.w       r4, [r1, #8]            // load 1st rkey word for round i
    ldr.w       r5, [r1, #12]           // load 1st rkey word for round i
    tpl_upd_1   r4, #92                 // compute 2nd rkey word for round i+10
    dbl_upd_1   r5, #88                 // compute 1st rkey word for round i+10
    tpl_upd_1   r5, #172                // compute 2nd rkey word for round i+20
    dbl_upd_1   r4, #168                // compute 1st rkey word for round i+20
    tpl_upd_1   r4, #252                // compute 2nd rkey word for round i+30
    dbl_upd_1   r5, #248                // compute 1st rkey word for round i+30
    bx          lr

/******************************************************************************
* Soubroutine to update round key words according to fixslicing for round i
* s.t. i mod 5 = 2.
******************************************************************************/
.align 2
key_update_2:
    ldr.w       r4, [r1, #16]           // load 1st rkey word for round i
    ldr.w       r5, [r1, #20]           // load 2nd rkey word for round i
    tpl_upd_2   r4, #100                // compute 2nd rkey word for round i+10
    dbl_upd_2   r5, #96                 // compute 1st rkey word for round i+10
    tpl_upd_2   r5, #180                // compute 2nd rkey word for round i+20
    dbl_upd_2   r4, #176                // compute 1st rkey word for round i+20
    tpl_upd_2   r4, #260                // compute 2nd rkey word for round i+30
    dbl_upd_2   r5, #256                // compute 1st rkey word for round i+30
    bx          lr

/******************************************************************************
* Soubroutine to update round key words according to fixslicing for round i
* s.t. i mod 5 = 3.
******************************************************************************/
.align 2
key_update_3:
    ldr.w       r4, [r1, #24]           // load 1st rkey word for round i
    ldr.w       r5, [r1, #28]           // load 2nd rkey word for round i
    tpl_upd_3   r4, #108                // compute 2nd rkey word for round i+10
    dbl_upd_3   r5, #104                // compute 1st rkey word for round i+10
    tpl_upd_3   r5, #188                // compute 2nd rkey word for round i+20
    dbl_upd_3   r4, #184                // compute 1st rkey word for round i+20
    tpl_upd_3   r4, #268                // compute 2nd rkey word for round i+30
    dbl_upd_3   r5, #264                // compute 1st rkey word for round i+30
    bx          lr

/******************************************************************************
* Soubroutine to update round key words according to fixslicing for round i
* s.t. i mod 5 = 4.
******************************************************************************/
.align 2
key_update_4:
    ldr.w       r4, [r1, #32]           // load 1st rkey word for round i
    ldr.w       r5, [r1, #36]           // load 2nd rkey word for round i
    tpl_upd_4   r4, #116                // compute 2nd rkey word for round i+10
    dbl_upd_4   r5, #112                // compute 1st rkey word for round i+10
    tpl_upd_4   r5, #196                // compute 2nd rkey word for round i+20
    dbl_upd_4   r4, #192                // compute 1st rkey word for round i+20
    tpl_upd_4   r4, #276                // compute 2nd rkey word for round i+30
    dbl_upd_4   r5, #272                // compute 1st rkey word for round i+30
    bx          lr

/*****************************************************************************
* 1st order masked implementation of the GIFT-128 key schedule according to
* the fixsliced representation.
*****************************************************************************/
@ void gift128_keyschedule(const u8* key, u32* rkey) {
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push    {r0-r12, r14}
    ldm     r0, {r9-r12}            //load key words
    mov     r0, #2                  //r0 <- 2
    rev     r9, r9                  //endianness (could be skipped with another representation)
    rev     r10, r10                //endianness (could be skipped with another representation)
    rev     r11, r11                //endianness (could be skipped with another representation)
    rev     r12, r12                //endianness (could be skipped with another representation)
    // ------------------ MASKING ------------------
    // generation of 4 random words
    movw    r14, 0x0804
    movt    r14, 0x5006             // r14<- RNG_SR = 0x50060804
    mov     r2, #4
    add     r3, r14, #4             // r3 <- RNG_DR = 0x50060808
gift128_key_get_random:
    ldr.w   r4, [r14]
    cmp     r4, #1                  // check if RNG_SR == RNG_SR_DRDY
    bne     gift128_key_get_random
    ldr.w   r4, [r3]                // put the random number in r10
    push    {r4}                    // push r10 on the stack
    subs    r2, #1
    bne     gift128_key_get_random
    pop     {r2,r3,r8,r14}          // pop the randomn numbers from the stack
    eor     r4, r9, r2              // apply masks to the internal state
    eor     r5, r10, r3             // apply masks to the internal state
    eor     r6, r11, r8             // apply masks to the internal state
    eor     r7, r12, r14            // apply masks to the internal state
    strd    r7, r5, [r1], #8        // store the first rkeys
    strd    r14, r3, [r1, #312]     // store the corresponding masks
    strd    r6, r4, [r1], #8        // store the first rkeys
    strd    r8, r2, [r1, #312]      // store the corresponding masks
loop:
    // keyschedule using classical representation for the first 20 rounds
    movw    r12, #0x3fff
    lsl     r12, r12, #16           // r12<- 0x3fff0000
    movw    r10, #0x000f            // r10<- 0x0000000f
    movw    r9, #0x0fff             // r9 <- 0x00000fff
    bl      classical_key_update    // keyschedule using classical representation
    bl      classical_key_update    // keyschedule using classical representation
    sub.w   r1, r1, #80
    movw    r3, #0x0055
    movt    r3, #0x0055             // r3 <- 0x00550055
    movw    r10, #0x3333            // r10<- 0x00003333
    movw    r11, #0x000f
    movt    r11, #0x000f            // r11<- 0x000f000f
    bl      rearrange_rkey_0        // fixslice the rkeys
    bl      rearrange_rkey_0        // fixslice the rkeys
    sub.w   r1, r1, #72
    movw    r3, #0x1111
    movt    r3, #0x1111             // r3 <- 0x11111111
    movw    r10, #0x0303
    movt    r10, #0x0303            // r10<- 0x03030303
    bl      rearrange_rkey_1        // fixslice the rkeys
    bl      rearrange_rkey_1        // fixslice the rkeys
    sub.w   r1, r1, #72
    movw    r3, #0xaaaa             // r3 <- 0x0000aaaa
    movw    r10, #0x3333            // r10<- 0x00003333
    movw    r11, #0xf0f0            // r11<- 0x0000f0f0
    bl      rearrange_rkey_2        // fixslice the rkeys
    bl      rearrange_rkey_2        // fixslice the rkeys
    sub.w   r1, r1, #72
    movw    r3, #0x0a0a
    movt    r3, #0x0a0a             // r3 <- 0x0a0a0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc            // r10<- 0x00cc00cc
    bl      rearrange_rkey_1        // fixslice the rkeys
    bl      rearrange_rkey_1        // fixslice the rkeys
    sub.w   r1, r1, #104
    movw    r10, #0x3333            // r10<- 0x00003333
    eor     r12, r10, r10, lsl #16  // r12<- 0w33333333 
    mvn     r11, r12                // r11<- 0xcccccccc
    movw    r9, #0x4444
    movt    r9, #0x5555             // r9 <- 0x55554444
    movw    r8, #0x1100
    movt    r8, #0x5555             // r8 <- 0x55551100
    bl      key_update_0            // keyschedule according to fixslicing
    add.w   r1, r1, #40
    bl      key_update_0            // keyschedule according to fixslicing
    sub.w   r1, r1, #40
    movw    r12, #0x0f00
    movt    r12, #0x0f00            // r12<- 0x0f000f00
    movw    r11, #0x0003
    movt    r11, #0x0003            // r11<- 0x00030003
    movw    r10, #0x003f
    movt    r10, #0x003f            // r10<- 0x003f003f
    lsl     r9, r11, #8             // r9 <- 0x03000300
    and     r8, r10, r10, lsr #3    // r8 <- 0x00070007
    orr     r7, r8, r8, lsl #2      // r7 <- 0x001f001f
    bl      key_update_1            // keyschedule according to fixslicing
    add.w   r1, r1, #40
    bl      key_update_1            // keyschedule according to fixslicing
    sub.w   r1, r1, #40
    movw    r12, #0x5555
    movt    r12, #0x5555            // r12<- 0x55555555
    mvn     r11, r12                // r11<- 0xaaaaaaaa
    bl      key_update_2            // keyschedule according to fixslicing
    add.w   r1, r1, #40
    bl      key_update_2            // keyschedule according to fixslicing
    sub.w   r1, r1, #40
    orr     r12, r8, r8, lsl #8     // r12<- 0x07070707
    movw    r11, #0xc0c0            // r11<- 0x0000c0c0
    movw    r10, #0x3030            // r10<- 0x00003030
    and     r9, r12, r12, lsr #1    // r9 <- 0x03030303
    lsl     r8, r12, #4             // r8 <- 0x70707070
    eor     r7, r8, r9, lsl #5      // r7 <- 0x10101010
    movw    r6, #0xf0f0             // r6 <- 0x0000f0f0
    bl      key_update_3            // keyschedule according to fixslicing
    add.w   r1, r1, #40
    bl      key_update_3            // keyschedule according to fixslicing
    sub.w   r1, r1, #40
    movw    r12, #0x0fff
    lsl     r10, r12, #16
    movw    r8, #0x00ff             // r8 <- 0x000000ff
    movw    r7, #0x03ff             // r7 <- 0x000003ff
    lsl     r7, r7, #16
    bl      key_update_4            // keyschedule according to fixslicing
    add.w   r1, r1, #40
    bl      key_update_4            // keyschedule according to fixslicing
    add.w   r1, r1, #280            //r1 now points to the masks
    ldrd    r7, r5, [r1], #8
    ldrd    r6, r4, [r1], #8
    subs    r0, r0, #1              //r0 <- r0-1 
    bne     loop                    //go to 'loop' if r0=0
    pop     {r0-r12,r14}
    bx      lr
