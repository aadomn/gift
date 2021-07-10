/****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFT-128 block cipher.
* This implementation focuses on speed, at the cost of a large code size.
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
*   - const0-const1 round constants
*   - idx           ror index to be used in the sbox (to match fixslicing)
******************************************************************************/
.macro round_0  in0, in1, in2, in3, const0, const1, idx
    movw    r5, \const0
    movt    r5, \const1                         // load rconst
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, \idx    // sbox layer
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
*   - const0-const1 round constants
******************************************************************************/
.macro round_1  in0, in1, in2, in3, const0, const1
    movw    r5, \const0
    movt    r5, \const1                         // load rconst
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
*   - const0-const1 round constants
******************************************************************************/
.macro round_2  in0, in1, in2, in3, const0, const1
    movw    r5, \const0
    movt    r5, \const1                         // load rconst
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
*   - const0-const1 round constants
******************************************************************************/
.macro round_3  in0, in1, in2, in3, const0, const1
    ldr.w   r6, [r1], #4                        // load 1st rkey word
    ldr.w   r7, [r1], #4                        // load 2nd rkey word
    sbox    \in0, \in1, \in2, \in3, r8, #16     // sbox layer
    eor     r14, r3, r3, lsl #8                 // r14<-0x0f0f0f0f for nibror
    nibror  \in1, \in1, r14, r14, #4, #4, r8
    orr     r14, r14, r14, lsl #2               // r14<-0x3f3f3f3f for nibror
    mvn     r8, r14, lsr #6                     // r8 <-0xc0c0c0c0 for nibror
    nibror  \in2, \in2, r14, r8, #2, #6, r5
    nibror  \in3, \in3, r8, r14, #6, #2, r8 
    eor     \in1, \in1, r6                      // add 1st rkey word
    eor     \in2, \in2, r7                      // add 2nd rkey word
    movw    r5, \const0
    movt    r5, \const1                         // load rconst
    eor     \in0, \in0, r5                      // add rconst
.endm

/******************************************************************************
* Macro to compute the fifth round within a quintuple round routine.
*   - in0-in3       input/output registers
*   - const0-const1 round constants
******************************************************************************/
.macro round_4  in0, in1, in2, in3, const0, const1
    movw    r5, \const0
    movt    r5, \const1                         // load rconst
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

/*****************************************************************************
* Fully unrolled implementation of the GIFT-128 key schedule according to the
* fixsliced representation.
*****************************************************************************/
@ void gift128_keyschedule(const u8* key, u32* rkey)
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push        {r2-r12, r14}
    ldr.w       r4, [r0]                // load 1st key word
    ldr.w       r5, [r0, #4]            // load 2nd key word
    ldr.w       r6, [r0, #8]            // load 3rd key word
    ldr.w       r7, [r0, #12]           // load 4th key word
    rev         r4, r4
    rev         r5, r5
    rev         r6, r6
    rev         r7, r7
    str.w       r7, [r1], #4            // store 1st rkey word (classical rep)
    str.w       r5, [r1], #4            // store 2nd rkey word (classical rep)
    str.w       r6, [r1], #4            // store 3rd rkey word (classical rep)
    str.w       r4, [r1], #4            // store 4th rkey word (classical rep)
    movw        r12, #0x3fff
    lsl         r12, r12, #16           // r12<- 0x3fff0000
    movw        r10, #0x000f            // r10<- 0x0000000f
    movw        r9, #0x0fff             // r9 <- 0x00000fff
    k_upd       r5, r7                  // 1st classical key update
    k_upd       r4, r6                  // 2nd classical key update
    k_upd       r7, r5                  // 3rd classical key update
    k_upd       r6, r4                  // 4th classical key update
    k_upd       r5, r7                  // 5th classical key update
    k_upd       r4, r6                  // 6th classical key update
    k_upd       r7, r5                  // 7th classical key update
    k_upd       r6, r4                  // 8th classical key update
    sub.w       r1, r1, #80             // r1 points to the 1st rkey word
    movw        r3, #0x0055
    movt        r3, #0x0055             // r3 <- 0x00550055
    movw        r10, #0x3333            // r10<- 0x00003333
    movw        r11, #0x000f
    movt        r11, #0x000f            // r11<- 0x000f000f
    ldr.w       r6, [r1]                // load 1st rkey word (classical rep)
    ldr.w       r4, [r1, #4]            // load 2nd rkey word (classical rep)
    rearr_rk    r4, r6, #9, #18, r12    // rearrange rkey words for round 1
    str.w       r6, [r1]                // store 1st rkey word (fixsliced rep)
    str.w       r4, [r1, #4]            // store 2nd rkey word (fixsliced rep)
    ldr.w       r6, [r1, #40]           // load 10th rkey word (classical rep)
    ldr.w       r4, [r1, #44]           // load 11th rkey word (classical rep)
    rearr_rk    r4, r6, #9, #18, r12    // rearrange rkey words for round 5
    str.w       r6, [r1, #40]           // store 10th rkey word (fixsliced rep)
    str.w       r4, [r1, #44]           // store 11th rkey word (fixsliced rep)
    movw        r3, #0x1111
    movt        r3, #0x1111             // r3 <- 0x11111111
    movw        r10, #0x0303
    movt        r10, #0x0303            // r10<- 0x03030303
    ldr.w       r5, [r1, #8]            // load 3rd rkey word (classical rep)
    ldr.w       r7, [r1, #12]           // load 4th rkey word (classical rep)
    rearr_rk    r5, r7, #3, #6, r8      // rearrange rkey words for round 2
    ldr.w       r12, [r1, #48]          // load 12th rkey word (classical rep)
    ldr.w       r14, [r1, #52]          // load 13th rkey word (classical rep)
    str.w       r5, [r1, #8]            // store 3rd rkey word (fixsliced rep)
    str.w       r7, [r1, #12]           // store 4th rkey word (fixsliced rep)
    rearr_rk    r12, r14, #3, #6, r8    // rearrange rkey words for round 6
    str.w       r12, [r1, #48]          // store 12th rkey word (fixsliced rep)
    str.w       r14, [r1, #52]          // store 13th rkey word (fixsliced rep)
    movw        r3, #0xaaaa             // r3 <- 0x0000aaaa
    movw        r10, #0x3333            // r10<- 0x00003333
    movw        r11, #0xf0f0            // r11<- 0x0000f0f0
    ldr.w       r5, [r1, #16]           // load 5th rkey word (classical rep)
    ldr.w       r7, [r1, #20]           // load 6th rkey word (classical rep)
    rearr_rk    r5, r7, #15, #18, r8    // rearrange rkey words for round 3
    str.w       r5, [r1, #16]           // store 5th rkey word (fixsliced rep)
    str.w       r7, [r1, #20]           // store 6th rkey word (fixsliced rep)
    ldr.w       r5, [r1, #56]           // load 14th rkey word (classical rep)
    ldr.w       r7, [r1, #60]           // load 15th rkey word (classical rep)
    rearr_rk    r5, r7, #15, #18, r8    // rearrange rkey words for round 7
    str.w       r5, [r1, #56]           // store 14th rkey word (fixsliced rep)
    str.w       r7, [r1, #60]           // store 15th rkey word (fixsliced rep)
    movw        r3, #0x0a0a
    movt        r3, #0x0a0a             //r3 <- 0x0a0a0a0a
    movw        r10, #0x00cc
    movt        r10, #0x00cc            //r10<- 0x00cc00cc
    ldr.w       r5, [r1, #24]           // load 7th rkey word (classical rep)
    ldr.w       r7, [r1, #28]           // load 8th rkey word (classical rep)
    rearr_rk    r5, r7, #3, #6, r8      // rearrange rkey words for round 4
    str.w       r5, [r1, #24]           // store 7th rkey word (fixsliced rep)
    str.w       r7, [r1, #28]           // store 8th rkey word (fixsliced rep)
    ldr.w       r5, [r1, #64]           // load 16th rkey word (classical rep)
    ldr.w       r7, [r1, #68]           // load 17th rkey word (classical rep)
    rearr_rk    r5, r7, #3, #6, r8      // rearrange rkey words for round 8
    str.w       r5, [r1, #64]           // store 16th rkey word (fixsliced rep)
    str.w       r7, [r1, #68]           // store 17th rkey word (fixsliced rep)
    movw        r10, #0x3333            // r10<- 0x00003333
    eor         r12, r10, r10, lsl #16  // r12<- 
    mvn         r11, r12                // r11<- 
    movw        r9, #0x4444
    movt        r9, #0x5555             // r9 <- 0x55554444
    movw        r8, #0x1100
    movt        r8, #0x5555             // r8 <- 0x55551100
    ldr.w       r4, [r1]                // load 1st rkey word for round 0
    ldr.w       r5, [r1, #4]            // load 2nd rkey word for round 0
    tpl_upd_0   r4, r5, #80, #84        // compute rkey words for round 10
    tpl_upd_0   r5, r4, #160, #164      // compute rkey words for round 20
    tpl_upd_0   r4, r5, #240, #244      // compute rkey words for round 30
    ldr.w       r4, [r1, #40]           // load 1st rkey word for round 5
    ldr.w       r5, [r1, #44]           // load 2nd rkey word for round 5
    tpl_upd_0   r4, r5, #120, #124      // compute rkey words for round 15
    tpl_upd_0   r5, r4, #200, #204      // compute rkey words for round 25
    tpl_upd_0   r4, r5, #280, #284      // compute rkey words for round 35
    movw        r12, #0x0f00
    movt        r12, #0x0f00            // r12<- 0x0f000f00
    movw        r11, #0x0003
    movt        r11, #0x0003            // r11<- 0x00030003
    movw        r10, #0x003f
    movt        r10, #0x003f            // r10<- 0x003f003f
    lsl         r9, r11, #8             // r9 <- 0x03000300
    and         r8, r10, r10, lsr #3    // r8 <- 0x00070007
    orr         r7, r8, r8, lsl #2      // r7 <- 0x001f001f
    ldr.w       r4, [r1, #8]            // load 1st rkey word for round 1
    ldr.w       r5, [r1, #12]           // load 1st rkey word for round 1
    tpl_upd_1   r4, #92                 // compute 2nd rkey word for round 11
    dbl_upd_1   r5, #88                 // compute 1st rkey word for round 11
    tpl_upd_1   r5, #172                // compute 2nd rkey word for round 21
    dbl_upd_1   r4, #168                // compute 1st rkey word for round 21
    tpl_upd_1   r4, #252                // compute 2nd rkey word for round 31
    dbl_upd_1   r5, #248                // compute 1st rkey word for round 31
    ldr.w       r4, [r1, #48]           // load 1st rkey word for round 6
    ldr.w       r5, [r1, #52]           // load 2nd rkey word for round 6
    tpl_upd_1   r4, #132                // compute 2nd rkey word for round 16
    dbl_upd_1   r5, #128                // compute 1st rkey word for round 16
    tpl_upd_1   r5, #212                // compute 2nd rkey word for round 26
    dbl_upd_1   r4, #208                // compute 1st rkey word for round 26
    tpl_upd_1   r4, #292                // compute 2nd rkey word for round 26
    dbl_upd_1   r5, #288                // compute 1st rkey word for round 36
    movw        r12, #0x5555
    movt        r12, #0x5555            // r12<- 0x55555555
    mvn         r11, r12                // r11<- 0xaaaaaaaa
    ldr.w       r4, [r1, #16]           // load 1st rkey word for round 2
    ldr.w       r5, [r1, #20]           // load 2nd rkey word for round 2
    tpl_upd_2   r4, #100                // compute 2nd rkey word for round 12
    dbl_upd_2   r5, #96                 // compute 1st rkey word for round 12
    tpl_upd_2   r5, #180                // compute 2nd rkey word for round 22
    dbl_upd_2   r4, #176                // compute 1st rkey word for round 22
    tpl_upd_2   r4, #260                // compute 2nd rkey word for round 32
    dbl_upd_2   r5, #256                // compute 1st rkey word for round 32
    ldr.w       r4, [r1, #56]           // load 1st rkey word for round 7
    ldr.w       r5, [r1, #60]           // load 2nd rkey word for round 7
    tpl_upd_2   r4, #140                // compute 2nd rkey word for round 17
    dbl_upd_2   r5, #136                // compute 1st rkey word for round 17
    tpl_upd_2   r5, #220                // compute 2nd rkey word for round 27
    dbl_upd_2   r4, #216                // compute 1st rkey word for round 27
    tpl_upd_2   r4, #300                // compute 2nd rkey word for round 37
    dbl_upd_2   r5, #296                // compute 1st rkey word for round 37
    orr         r12, r8, r8, lsl #8     // r12<- 0x07070707
    movw        r11, #0xc0c0            // r10<- 0x0000c0c0
    movw        r10, #0x3030            // r10<- 0x00003030
    and         r9, r12, r12, lsr #1    // r9 <- 0x03030303
    lsl         r8, r12, #4             // r8 <- 0x70707070
    eor         r7, r8, r9, lsl #5      // r7 <- 0x10101010
    movw        r6, #0xf0f0             // r6 <- 0x0000f0f0
    ldr.w       r4, [r1, #24]           // load 1st rkey word for round 3
    ldr.w       r5, [r1, #28]           // load 2nd rkey word for round 3
    tpl_upd_3   r4, #108                // compute 2nd rkey word for round 13
    dbl_upd_3   r5, #104                // compute 1st rkey word for round 13
    tpl_upd_3   r5, #188                // compute 2nd rkey word for round 23
    dbl_upd_3   r4, #184                // compute 1st rkey word for round 23
    tpl_upd_3   r4, #268                // compute 2nd rkey word for round 33
    dbl_upd_3   r5, #264                // compute 1st rkey word for round 33
    ldr.w       r4, [r1, #64]           // load 1st rkey word for round 8
    ldr.w       r5, [r1, #68]           // load 2nd rkey word for round 8          
    tpl_upd_3   r4, #148                // compute 2nd rkey word for round 18
    dbl_upd_3   r5, #144                // compute 1st rkey word for round 18
    tpl_upd_3   r5, #228                // compute 2nd rkey word for round 28
    dbl_upd_3   r4, #224                // compute 1st rkey word for round 28
    tpl_upd_3   r4, #308                // compute 2nd rkey word for round 38
    dbl_upd_3   r5, #304                // compute 1st rkey word for round 38
    movw        r12, #0x0fff            // r12<- 0x00000fff
    lsl         r10, r12, #16           // r10<- 0x0fff0000
    movw        r8, #0x00ff             // r8 <- 0x000000ff
    movw        r7, #0x03ff
    lsl         r7, r7, #16             // r7 <- 0x03ff0000
    ldr.w       r4, [r1, #32]           // load 1st rkey word for round 4          
    ldr.w       r5, [r1, #36]           // load 2nd rkey word for round 4
    tpl_upd_4   r4, #116                // compute 2nd rkey word for round 14
    dbl_upd_4   r5, #112                // compute 1st rkey word for round 14
    tpl_upd_4   r5, #196                // compute 2nd rkey word for round 24
    dbl_upd_4   r4, #192                // compute 1st rkey word for round 24
    tpl_upd_4   r4, #276                // compute 2nd rkey word for round 34
    dbl_upd_4   r5, #272                // compute 1st rkey word for round 34
    ldr.w       r4, [r1, #72]           // load 1st rkey word for round 9
    ldr.w       r5, [r1, #76]           // load 2nd rkey word for round 9
    tpl_upd_4   r4, #156                // compute 2nd rkey word for round 19
    dbl_upd_4   r5, #152                // compute 1st rkey word for round 19
    tpl_upd_4   r5, #236                // compute 2nd rkey word for round 29
    dbl_upd_4   r4, #232                // compute 1st rkey word for round 29
    tpl_upd_4   r4, #316                // compute 2nd rkey word for round 39
    dbl_upd_4   r5, #312                // compute 1st rkey word for round 39
    pop         {r2-r12,r14}
    bx          lr

/*****************************************************************************
* Fully unrolled implementation of the GIFT-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
.align 2
@ void gift128_encrypt_block(u8 *out, const u32* rkey, const u8 *block)
.global gift128_encrypt_block
.type   gift128_encrypt_block,%function
gift128_encrypt_block:
    push {r2-r12,r14}
    ldm         r2, {r4-r7}     // load plaintext blocks in r4-r7
    rev         r4, r4          // endianess to match the fixsliced representation
    rev         r5, r5          // endianess to match the fixsliced representation
    rev         r6, r6          // endianess to match the fixsliced representation
    rev         r7, r7          // endianess to match the fixsliced representation
    // ------------------ PACKING ------------------ 
    uxth        r8, r5
    uxth        r9, r7
    orr         r9, r9, r8, lsl #16             // r9 <- block[6-7] || block[14-15]
    uxth        r8, r5, ror #16
    uxth        r10, r7, ror #16
    orr         r10, r10, r8, lsl #16           // r10<- block[4-5] || block[12-13]
    uxth        r8, r4
    uxth        r11, r6
    orr         r11, r11, r8, lsl #16           // r11<- block[2-3] || block[10-11]
    uxth        r8, r4, ror #16
    uxth        r12, r6, ror #16
    orr         r12, r12, r8, lsl #16           // r12<- block[0-1] || block[8-9]
    movw        r2, #0x0a0a
    movt        r2, #0x0a0a                     // r2 <- 0x0a0a0a0a for SWAPMOVE
    swpmv       r9,  r9,  r9,  r9,  r2, #3, r3
    swpmv       r10, r10, r10, r10, r2, #3, r3
    swpmv       r11, r11, r11, r11, r2, #3, r3
    swpmv       r12, r12, r12, r12, r2, #3, r3
    movw        r2, #0x00cc
    movt        r2, #0x00cc                     // r2 <- 0x00cc00cc for SWAPMOVE
    swpmv       r9,  r9,  r9,  r9,  r2, #6, r3
    swpmv       r10, r10, r10, r10, r2, #6, r3
    swpmv       r11, r11, r11, r11, r2, #6, r3
    swpmv       r12, r12, r12, r12, r2, #6, r3
    movw        r2, #0x000f
    movt        r2, #0x000f                     // r2 <- 0x000f000f for SWAPMOVE
    swpmv       r9,  r10, r9,  r10, r2, #4,  r3
    swpmv       r9,  r11, r9,  r11, r2, #8,  r3
    swpmv       r9,  r12, r9,  r12, r2, #12, r3
    lsl         r2, r2, #4                      // r2 <- 0x00f000f0 for SWAPMOVE
    swpmv       r10, r11, r10, r11, r2, #4,  r3
    swpmv       r10, r12, r10, r12, r2, #8,  r3
    lsl         r2, r2, #4                      // r2 <- 0x0f000f00 for SWAPMOVE
    swpmv       r11, r12, r11, r12, r2, #4,  r3
    // ------------------ GIFTb-CORE ROUTINE ------------------
    mov         r3, r2, lsr #8              // r3 <- 0x000f000f
    movw        r2, #0x1111
    movt        r2, #0x1111                 // r12<- 0x11111111
    mvn         r4, r2, lsl #3              // r4 <- 0x77777777
    round_0     r9, r10, r11, r12, 0x0008, 0x1000, 0
    round_1     r12, r10, r11, r9, 0x8000, 0x8001
    round_2     r9, r10, r11, r12, 0x0002, 0x5400
    round_3     r12, r10, r11, r9, 0x0181, 0x0101
    round_4     r9, r10, r11, r12, 0x001f, 0x8000
    round_0     r12, r10, r11, r9, 0x8880, 0x1088, #24
    round_1     r9, r10, r11, r12, 0xe000, 0x6001
    round_2     r12, r10, r11, r9, 0x0002, 0x5150
    round_3     r9, r10, r11, r12, 0x0180, 0x0303
    round_4     r12, r10, r11, r9, 0x002f, 0x8000
    round_0     r9, r10, r11, r12, 0x8880, 0x1008, #24
    round_1     r12, r10, r11, r9, 0x6000, 0x6001
    round_2     r9, r10, r11, r12, 0x0002, 0x4150
    round_3     r12, r10, r11, r9, 0x0080, 0x0303
    round_4     r9, r10, r11, r12, 0x0027, 0x8000
    round_0     r12, r10, r11, r9, 0x8880, 0x1000, #24
    round_1     r9, r10, r11, r12, 0xe000, 0x4001
    round_2     r12, r10, r11, r9, 0x0002, 0x1150
    round_3     r9, r10, r11, r12, 0x0180, 0x0302
    round_4     r12, r10, r11, r9, 0x002b, 0x8000
    round_0     r9, r10, r11, r12, 0x0880, 0x1008, #24
    round_1     r12, r10, r11, r9, 0x4000, 0x6001
    round_2     r9, r10, r11, r12, 0x0002, 0x0140
    round_3     r12, r10, r11, r9, 0x0080, 0x0202
    round_4     r9, r10, r11, r12, 0x0021, 0x8000
    round_0     r12, r10, r11, r9, 0x0080, 0x1000, #24
    round_1     r9, r10, r11, r12, 0xc000, 0x0001
    round_2     r12, r10, r11, r9, 0x0002, 0x5100
    round_3     r9, r10, r11, r12, 0x0180, 0x0301
    round_4     r12, r10, r11, r9, 0x002e, 0x8000
    round_0     r9, r10, r11, r12, 0x8800, 0x1008, #24
    round_1     r12, r10, r11, r9, 0x2000, 0x6001
    round_2     r9, r10, r11, r12, 0x0002, 0x4050
    round_3     r12, r10, r11, r9, 0x0080, 0x0103
    round_4     r9, r10, r11, r12, 0x0006, 0x8000
    round_0     r12, r10, r11, r9, 0x8808, 0x1000, #24
    round_1     r9, r10, r11, r12, 0xa000, 0xc001
    round_2     r12, r10, r11, r9, 0x0002, 0x1450
    round_3     r9, r10, r11, r12, 0x0181, 0x0102
    round_4     r12, r10, r11, r9, 0x001a, 0x8000
    ror         r9, r9, #24
    // ------------------ UNPACKING ------------------ 
    movw        r2, #0x0f00
    movt        r2, #0x0f00                     // r2 <- 0x0f000f00 for SWAPMOVE
    swpmv       r11, r12, r11, r12, r2, #4,  r3
    lsr         r2, r2, #4                      // r2 <- 0x00f000f0 for SWAPMOVE
    swpmv       r10, r12, r10, r12, r2, #8,  r3
    swpmv       r10, r11, r10, r11, r2, #4,  r3
    lsr         r2, r2, #4                      // r2 <- 0x000f000f for SWAPMOVE
    swpmv       r9,  r12, r9,  r12, r2, #12, r3
    swpmv       r9,  r11, r9,  r11, r2, #8,  r3
    swpmv       r9,  r10, r9,  r10, r2, #4,  r3
    movw        r2, #0x00cc
    movt        r2, #0x00cc                     // r2 <- 0x00cc00cc for SWAPMOVE
    swpmv       r9,  r9,  r9,  r9,  r2, #6, r3
    swpmv       r10, r10, r10, r10, r2, #6, r3
    swpmv       r11, r11, r11, r11, r2, #6, r3
    swpmv       r12, r12, r12, r12, r2, #6, r3
    movw        r2, #0x0a0a
    movt        r2, #0x0a0a                     // r2 <- 0x0a0a0a0a for SWAPMOVE
    swpmv       r9,  r9,  r9,  r9,  r2, #3, r3
    swpmv       r10, r10, r10, r10, r2, #3, r3
    swpmv       r11, r11, r11, r11, r2, #3, r3
    swpmv       r12, r12, r12, r12, r2, #3, r3
    lsr         r4, r12, #16
    lsr         r5, r11, #16
    orr         r4, r5, r4, lsl #16             // r4 <- out[0]
    lsr         r5, r10, #16
    lsr         r6, r9, #16
    orr         r5, r6, r5, lsl #16             // r5 <- out[1]
    lsl         r6, r12, #16
    lsl         r7, r11, #16
    orr         r6, r6, r7, lsr #16             // r6 <- out[2]
    lsl         r7, r10, #16
    lsl         r8, r9, #16
    orr         r7, r7, r8, lsr #16             // r7 <- out[3]
    rev         r4, r4
    rev         r5, r5
    rev         r6, r6
    rev         r7, r7
    stm         r0, {r4-r7}
    pop         {r2-r12,r14}
    bx          lr

/*****************************************************************************
* Fully unrolled ARM assembly implementation of the GIFTb-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void giftb128_encrypt_block(u8 *out, const u32* rkey,
@       const u8 *block) {
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push        {r2-r12,r14}
    ldm         r2, {r9-r12}    // load plaintext blocks
    rev         r9, r9          // endianess to match fixsliced representation
    rev         r10, r10        // endianess to match fixsliced representation
    rev         r11, r11        // endianess to match fixsliced representation
    rev         r12, r12        // endianess to match fixsliced representation
    movw        r2, #0x1111
    movt        r2, #0x1111     // r12<- 0x11111111 for NIBBLE_ROR
    movw        r3, #0x000f
    movt        r3, #0x000f     // r3 <- 0x000f000f for HALF_ROR
    mvn         r4, r2, lsl #3  // r4 <- 0x77777777 for NIBBLE_ROR
    round_0     r9, r10, r11, r12, 0x0008, 0x1000, 0
    round_1     r12, r10, r11, r9, 0x8000, 0x8001
    round_2     r9, r10, r11, r12, 0x0002, 0x5400
    round_3     r12, r10, r11, r9, 0x0181, 0x0101
    round_4     r9, r10, r11, r12, 0x001f, 0x8000
    round_0     r12, r10, r11, r9, 0x8880, 0x1088, #24
    round_1     r9, r10, r11, r12, 0xe000, 0x6001
    round_2     r12, r10, r11, r9, 0x0002, 0x5150
    round_3     r9, r10, r11, r12, 0x0180, 0x0303
    round_4     r12, r10, r11, r9, 0x002f, 0x8000
    round_0     r9, r10, r11, r12, 0x8880, 0x1008, #24
    round_1     r12, r10, r11, r9, 0x6000, 0x6001
    round_2     r9, r10, r11, r12, 0x0002, 0x4150
    round_3     r12, r10, r11, r9, 0x0080, 0x0303
    round_4     r9, r10, r11, r12, 0x0027, 0x8000
    round_0     r12, r10, r11, r9, 0x8880, 0x1000, #24
    round_1     r9, r10, r11, r12, 0xe000, 0x4001
    round_2     r12, r10, r11, r9, 0x0002, 0x1150
    round_3     r9, r10, r11, r12, 0x0180, 0x0302
    round_4     r12, r10, r11, r9, 0x002b, 0x8000
    round_0     r9, r10, r11, r12, 0x0880, 0x1008, #24
    round_1     r12, r10, r11, r9, 0x4000, 0x6001
    round_2     r9, r10, r11, r12, 0x0002, 0x0140
    round_3     r12, r10, r11, r9, 0x0080, 0x0202
    round_4     r9, r10, r11, r12, 0x0021, 0x8000
    round_0     r12, r10, r11, r9, 0x0080, 0x1000, #24
    round_1     r9, r10, r11, r12, 0xc000, 0x0001
    round_2     r12, r10, r11, r9, 0x0002, 0x5100
    round_3     r9, r10, r11, r12, 0x0180, 0x0301
    round_4     r12, r10, r11, r9, 0x002e, 0x8000
    round_0     r9, r10, r11, r12, 0x8800, 0x1008, #24
    round_1     r12, r10, r11, r9, 0x2000, 0x6001
    round_2     r9, r10, r11, r12, 0x0002, 0x4050
    round_3     r12, r10, r11, r9, 0x0080, 0x0103
    round_4     r9, r10, r11, r12, 0x0006, 0x8000
    round_0     r12, r10, r11, r9, 0x8808, 0x1000, #24
    round_1     r9, r10, r11, r12, 0xa000, 0xc001
    round_2     r12, r10, r11, r9, 0x0002, 0x1450
    round_3     r9, r10, r11, r12, 0x0181, 0x0102
    round_4     r12, r10, r11, r9, 0x001a, 0x8000
    ror         r9, r9, #24
    rev         r9, r9
    rev         r10, r10
    rev         r11, r11
    rev         r12, r12
    stm         r0, {r9-r12}
    pop         {r2-r12,r14}
    bx          lr
