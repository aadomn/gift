/****************************************************************************
* Compact ARM assembly implementation of the GIFT-128 block cipher. This
* implementation focuses on code size rather than speed.
*
* See "Fixslicing: A New GIFT Representation" paper available at 
* https://eprint.iacr.org/2020/412.pdf for more details.
*
* @author   Alexandre Adomnicai, Nanyang Technological University
*
* @date     July 2021
****************************************************************************/

.syntax unified
.thumb

/*****************************************************************************
* Round constants look-up table according to the fixsliced representation.
*****************************************************************************/
.align 2
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
*   - tmp           temporary register
*   - n             ror index value to math fixslicing
******************************************************************************/
.macro sbox     in0, in1, in2, in3, tmp, n
    and     \tmp, \in2, \in0, ror \n
    eor     \in1, \in1, \tmp
    and     \tmp, \in1, \in3
    eor     \in0, \tmp, \in0, ror \n
    orr     \tmp, \in0, \in1
    eor     \in2, \tmp, \in2
    eor     \in3, \in3, \in2
    eor     \in1, \in1, \in3
    and     \tmp, \in0, \in1
    eor     \in2, \in2, \tmp
    mvn     \in3, \in3
.endm

/******************************************************************************
* Macro to compute the first round within a quintuple round routine.
*   - in0-in3       input/output registers
******************************************************************************/
.macro round_0  in0, in1, in2, in3
    ldr.w   r5, [r0], #4                        // load rconst
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, #0      // sbox layer
    nibror  \in3, \in3, r4, r2, 1, 3, r8        // linear layer
    nibror  \in2, \in2, r2, r4, 3, 1, r8        // linear layer
    orr     r14, r2, r2, lsl #1                 // 0x33333333 for 'nibror'
    nibror  \in1, \in1, r14, r14, 2, 2, r8      // linear layer
    eor     \in1, \in1, r6                      // add 1st rkey word
    eor     \in2, \in2, r7                      // add 2nd rkey word
    eor     \in0, \in0, r5                      // add rconst
.endm

/******************************************************************************
* Macro to compute the second round within a quintuple round routine.
*   - in0-in3       input/output registers
******************************************************************************/
.macro round_1  in0, in1, in2, in3
    ldr.w   r5, [r0], #4                        // load rconst
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, #0      // sbox layer
    mvn     r14, r3, lsl #12                    // r14<-0x0fff0fff for HALF_ROR
    nibror  \in3, \in3, r14, r3,  4,  12, r8    // HALF_ROR(in3, 4)
    nibror  \in2, \in2, r3,  r14, 12,  4, r8    // HALF_ROR(in2, 12)
    rev16   \in1, \in1                          // HALF_ROR(in1, 8)
    eor     \in1, \in1, r6                      // add 1st rkey word
    eor     \in2, \in2, r7                      // add 2nd rkey word
    eor     \in0, \in0, r5                      // add rconst
.endm

/******************************************************************************
* Macro to compute the third round within a quintuple round routine.
*   - in0-in3       input/output registers
******************************************************************************/
.macro round_2  in0, in1, in2, in3
    ldr.w   r5, [r0], #4                        // load rconst
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, #0      // sbox layer
    orr     r14, r2, r2, lsl #2                 // r14<-0x55555555 for swpmv
    swpmv   \in1, \in1, \in1, \in1, r14, #1, r8
    eor     r8, \in3, \in3, lsr #1
    and     r8, r8, r14, lsr #16
    eor     \in3, \in3, r8
    eor     \in3, \in3, r8, lsl #1              //SWAPMOVE(r12,r12,0x55550000,1)
    eor     r8, \in2, \in2, lsr #1
    and     r8, r8, r14, lsl #16
    eor     \in2, \in2, r8
    eor     \in2, \in2, r8, lsl #1              //SWAPMOVE(r11,r11,0x00005555,1)
    eor     \in1, \in1, r6                      // add 1st rkey word
    eor     \in2, r7, \in2, ror #16             // add 2nd rkey word
    eor     \in0, \in0, r5                      // add rconst
.endm

/******************************************************************************
* Macro to compute the fourth round within a quintuple round routine.
*   - in0-in3       input/output registers
******************************************************************************/
.macro round_3  in0, in1, in2, in3
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, #16     // sbox layer
    eor     r14, r3, r3, lsl #8                 // r14<-0x0f0f0f0f for nibror
    nibror  \in1, \in1, r14, r14, #4, #4, r8
    orr     r14, r14, r14, lsl #2               // r14<-0x3f3f3f3f for nibror
    mvn     r8, r14, lsr #6                     // r8 <-0xc0c0c0c0 for nibror
    nibror  \in2, \in2, r14, r8, #2, #6, r5
    nibror  \in3, \in3, r8, r14, #6, #2, r8 
    ldr.w   r5, [r0], #4                        // load rconst
    eor     \in1, \in1, r6                      // add 1st rkey word
    eor     \in2, \in2, r7                      // add 2nd rkey word
    eor     \in0, \in0, r5                      // add rconst
.endm

/******************************************************************************
* Macro to compute the fifth round within a quintuple round routine.
*   - in0-in3       input/output registers
******************************************************************************/
.macro round_4  in0, in1, in2, in3
    ldr.w   r5, [r0], #4                        // load rconst
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, #0      // sbox layer
    eor     \in1, r6, \in1, ror #16             // add 1st keyword
    eor     \in2, r7, \in2, ror #8              // add 2nd keyword
    eor     \in0, \in0, r5                      // add rconst
.endm

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

.align 2
/*****************************************************************************
* Implementation of the GIFT-128 key schedule according to fixslicing.
* The entire round key material is first computed according to the classical
* representation before being rearranged according to fixslicing.
*****************************************************************************/
@ void gift128_keyschedule(const u8* key, u32* rkey) {
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push    {r1-r12, r14}
    ldm     r0, {r4-r7}             // load key words
    rev     r4, r4                  // endianness
    rev     r5, r5                  // endianness
    rev     r6, r6                  // endianness
    rev     r7, r7                  // endianness
    str.w   r5, [r1, #4]
    str.w   r7, [r1], #8            //the first rkeys are not updated  
    str.w   r4, [r1, #4]
    str.w   r6, [r1], #8            //the first rkeys are not updated
    movw    r12, #0x3fff
    lsl     r12, r12, #16           //r12<- 0x3fff0000
    movw    r10, #0x000f            //r10<- 0x0000000f
    movw    r9, #0x0fff             //r9 <- 0x00000fff
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    bl      classical_key_update
    sub.w   r1, r1, #336
    movw    r3, #0x0055
    movt    r3, #0x0055             //r3 <- 0x00550055
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0x000f
    movt    r11, #0x000f            //r11<- 0x000f000f
    bl      rearrange_rkey_0        // fixslice the rkey words for round 0
    bl      rearrange_rkey_0        // fixslice the rkey words for round 5
    bl      rearrange_rkey_0        // fixslice the rkey words for round 10
    bl      rearrange_rkey_0        // fixslice the rkey words for round 15
    bl      rearrange_rkey_0        // fixslice the rkey words for round 20
    bl      rearrange_rkey_0        // fixslice the rkey words for round 25
    bl      rearrange_rkey_0        // fixslice the rkey words for round 30
    bl      rearrange_rkey_0        // fixslice the rkey words for round 35
    sub.w   r1, r1, #312
    movw    r3, #0x1111
    movt    r3, #0x1111             // r3 <- 0x11111111
    movw    r10, #0x0303
    movt    r10, #0x0303            // r10<- 0x03030303
    bl      rearrange_rkey_1        // fixslice the rkey words for round 1
    bl      rearrange_rkey_1        // fixslice the rkey words for round 6
    bl      rearrange_rkey_1        // fixslice the rkey words for round 11
    bl      rearrange_rkey_1        // fixslice the rkey words for round 16
    bl      rearrange_rkey_1        // fixslice the rkey words for round 21
    bl      rearrange_rkey_1        // fixslice the rkey words for round 26
    bl      rearrange_rkey_1        // fixslice the rkey words for round 31
    bl      rearrange_rkey_1        // fixslice the rkey words for round 36
    sub.w   r1, r1, #312
    movw    r3, #0xaaaa             // r3 <- 0x0000aaaa
    movw    r10, #0x3333            // r10<- 0x00003333
    movw    r11, #0xf0f0            // r11<- 0x0000f0f0
    bl      rearrange_rkey_2        // fixslice the rkey words for round 2
    bl      rearrange_rkey_2        // fixslice the rkey words for round 7
    bl      rearrange_rkey_2        // fixslice the rkey words for round 12
    bl      rearrange_rkey_2        // fixslice the rkey words for round 17
    bl      rearrange_rkey_2        // fixslice the rkey words for round 22
    bl      rearrange_rkey_2        // fixslice the rkey words for round 27
    bl      rearrange_rkey_2        // fixslice the rkey words for round 32
    bl      rearrange_rkey_2        // fixslice the rkey words for round 37
    sub.w   r1, r1, #312
    movw    r3, #0x0a0a
    movt    r3, #0x0a0a             // r3 <- 0x0a0a0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc            // r10<- 0x00cc00cc
    bl      rearrange_rkey_1        // fixslice the rkey words for round 3
    bl      rearrange_rkey_1        // fixslice the rkey words for round 8
    bl      rearrange_rkey_1        // fixslice the rkey words for round 13
    bl      rearrange_rkey_1        // fixslice the rkey words for round 18
    bl      rearrange_rkey_1        // fixslice the rkey words for round 23
    bl      rearrange_rkey_1        // fixslice the rkey words for round 28
    bl      rearrange_rkey_1        // fixslice the rkey words for round 33
    bl      rearrange_rkey_1        // fixslice the rkey words for round 38
    pop     {r1-r12,r14}
    bx      lr

/*****************************************************************************
* Subroutine to implement a quintuple round of GIFT-128.
*****************************************************************************/
.align 2
quintuple_round:
    str.w   r14, [sp]
    round_0 r9, r10, r11, r12
    round_1 r12, r10, r11, r9
    round_2 r9, r10, r11, r12
    round_3 r12, r10, r11, r9
    round_4 r9, r10, r11, r12
    ldr.w   r14, [sp]
    eor     r9, r9, r12, ror #24
    eor     r12, r9, r12, ror #24
    eor     r9, r9, r12                 // swap r9 with r12
    bx      lr

/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void giftb128_encrypt_block(u8 *out, const u32* rkey, const u8 *block)
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push    {r0,r2-r12,r14}
    sub.w   sp, #4              // to store 'lr' when calling 'quintuple_round'
    ldm     r2, {r9-r12}        // load plaintext words
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    movw    r2, #0x1111
    movt    r2, #0x1111         // r2 <- 0x11111111 (for NIBBLE_ROR)
    movw    r3, #0x000f
    movt    r3, #0x000f         // r3 <- 0x000f000f (for HALF_ROR)
    mvn     r4, r2, lsl #3      // r4 <- 0x7777777 (for NIBBLE_ROR)
    adr     r0, rconst          // r0 <- 'rconst' address
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    bl      quintuple_round
    ldr.w   r0, [sp ,#4]        // restore 'ctext' address
    rev     r9, r9
    rev     r10, r10
    rev     r11, r11
    rev     r12, r12
    stm     r0, {r9-r12}
    add.w   sp, #4
    pop     {r0,r2-r12,r14}
    bx      lr
    