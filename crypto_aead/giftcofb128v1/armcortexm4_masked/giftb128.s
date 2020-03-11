/****************************************************************************
* 1st order masked ARM assembly implementation of the GIFT-128 block cipher.
* See 'Fixslicing: A New GIFT Representation' paper at https:// for more  
* details on the fixsliced representation.
* Nonlinear gates (AND/OR) are implemented using the techniques introduced in
* 'Optimal First-Order Boolean Masking for Embedded IoT Devices' published at
* CARDIS 2017.
*
* @author   Alexandre Adomnicai, Nanyang Technological University,
*           alexandre.adomnicai@ntu.edu.sg
*
* @date     March 2020
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

quintuple_round_masked:
	str.w 	r14, [sp] 				//store 'lr' on the stack
    movw r14, #0x1111
    movt r14, #0x1111 				//r14<- 0x11111111
	// sbox layer
    orn 	r6, r9, r4
    and 	r7, r9, r11
    eor 	r8, r6, r7
    orn 	r6, r2, r4
    and 	r7, r2, r11
    eor 	r7, r7, r6
    eor 	r10, r10, r8 			//s1 ^= s0 & s2
    eor 	r3, r3, r7 				//s1_m ^= s0_m & s2_m
    orn 	r6, r10, r5
    and 	r7, r10, r12
    eor 	r8, r6, r7
    orn 	r6, r3, r5
    and 	r7, r3, r12
    eor 	r7, r7, r6 				//s0 ^= s1 & s3;
    eor 	r9, r9, r8 				//s0_m ^= s1_m & s3_m;
    eor 	r2, r2, r7
    orr 	r6, r9, r3
    and 	r7, r9, r10
    eor 	r8, r6, r7
    and 	r6, r2, r3
    orr 	r7, r2, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 | s1;
    eor 	r4, r4, r7 				//s2_m ^= s0_m | s1_m;
    eor 	r12, r12, r11
    eor 	r5, r5, r4
    eor 	r10, r10, r12
    eor 	r3, r3, r5
    orn 	r6, r9, r3
    and 	r7, r9, r10
    eor 	r8, r6, r7
    orn 	r6, r2, r3
    and 	r7, r2, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 & s1;
    eor 	r4, r4, r7 				//s2_m ^= s0_m & s1_m;
    mvn 	r12, r12
    // linear layer
    mvn 	r6, r14, lsl #3			//0x77777777 for NIBBLE_ROR
    and 	r8, r6, r12, lsr #1
    and 	r12, r12, r14
    orr 	r12, r8, r12, lsl #3 	//NIBBLE_ROR(r12, 1)
    and 	r8, r6, r5, lsr #1
    and 	r5, r5, r14
    orr 	r5, r8, r5, lsl #3 		//NIBBLE_ROR(r5, 1)
    and 	r8, r6, r11
    and 	r11, r14, r11, lsr #3
    orr 	r11, r11, r8, lsl #1 	//NIBBLE_ROR(r11, 3)
    and 	r8, r6, r4
    and 	r4, r14, r4, lsr #3
    orr 	r4, r4, r8, lsl #1 		//NIBBLE_ROR(r4, 3)
    orr 	r6, r14, r14, lsl #1 	//0x33333333 for NIBBLE_ROR
    and 	r8, r6, r10, lsr #2
    and 	r10, r10, r6
    orr 	r10, r8, r10, lsl #2 	//NIBBLE_ROR(r10, 2)
    and 	r8, r6, r3, lsr #2
    and 	r3, r3, r6
    orr 	r3, r8, r3, lsl #2 		//NIBBLE_ROR(r3, 2)
    // ARK
    ldrd 	r6, r7, [r1], #8 		//load rkey
    eor 	r10, r10, r6
    eor 	r11, r11, r7
    ldrd 	r6, r7, [r1, #312] 		//load rkey_mask
    eor 	r3, r3, r6
    ldr.w   r6, [r0], #4 			//load rconst
    eor 	r4, r4, r7
    eor 	r9, r9, r6
    // 2nd round
    // sbox layer
    orn 	r6, r12, r4
    and 	r7, r12, r11
    eor 	r8, r6, r7
    orn 	r6, r5, r4
    and 	r7, r5, r11
    eor 	r7, r7, r6
    eor 	r10, r10, r8 			//s1 ^= s0 & s2
    eor 	r3, r3, r7 				//s1_m ^= s0_m & s2_m
    orn 	r6, r10, r2
    and 	r7, r10, r9
    eor 	r8, r6, r7
    orn 	r6, r3, r2
    and 	r7, r3, r9
    eor 	r7, r7, r6
    eor 	r12, r12, r8 			//s0 ^= s1 & s3;
    eor 	r5, r5, r7 				//s0_m ^= s1_m & s3_m;
    orr 	r6, r12, r3
    and 	r7, r12, r10
    eor 	r8, r6, r7
    and 	r6, r5, r3
    orr 	r7, r5, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 | s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m | s1_m
    eor 	r9, r9, r11
    eor 	r2, r2, r4
    eor 	r10, r10, r9
    eor 	r3, r3, r2
    orn 	r6, r12, r3
    and 	r7, r12, r10
    eor 	r8, r6, r7
    orn 	r6, r5, r3
    and 	r7, r5, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 & s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m & s1_m
    mvn 	r9, r9
    //linear layer
    movw 	r6, #0x000f
    movt 	r6, #0x000f
    mvn 	r7, r6, lsl #12 		//0x0fff0fff for HALF_ROR
    and 	r8, r7, r9, lsr #4
    and 	r9, r9, r6
    orr 	r9, r8, r9, lsl #12 	//HALF_ROR(r9, 4)
    and 	r8, r7, r2, lsr #4
    and 	r2, r2, r6
    orr 	r2, r8, r2, lsl #12 	//HALF_ROR(r2, 4)
    and 	r8, r6, r11, lsr #12
    and 	r11, r11, r7
    orr 	r11, r8, r11, lsl #4 	//HALF_ROR(r11, 12)
    and 	r8, r6, r4, lsr #12
    and 	r4, r4, r7
    orr 	r4, r8, r4, lsl #4 		//HALF_ROR(r4, 12)
    rev16 	r10, r10 				//HALF_ROR(r10, 8)
    rev16 	r3, r3 					//HALF_ROR(r3, 8)
    // ARK
    ldrd 	r6, r7, [r1], #8 		//load rkey
    eor 	r10, r10, r6
    eor 	r11, r11, r7
    ldrd 	r6, r7, [r1, #312] 		//load rkey_mask
    eor 	r3, r3, r6
    ldr.w   r6, [r0], #4 			//load rconst
    eor 	r4, r4, r7
    eor 	r12, r12, r6
    // 3rd round
    // sbox layer
    orn 	r6, r9, r4
    and 	r7, r9, r11
    eor 	r8, r6, r7
    orn 	r6, r2, r4
    and 	r7, r2, r11
    eor 	r7, r7, r6
    eor 	r10, r10, r8 			//s1 ^= s0 & s2
    eor 	r3, r3, r7 				//s1_m ^= s0_m & s2_m
    orn 	r6, r10, r5
    and 	r7, r10, r12
    eor 	r8, r6, r7
    orn 	r6, r3, r5
    and 	r7, r3, r12
    eor 	r7, r7, r6
    eor 	r9, r9, r8 				//s0 ^= s1 & s3
    eor 	r2, r2, r7 				//s0_m ^= s1_m & s3_m
    orr 	r6, r9, r3
    and 	r7, r9, r10
    eor 	r8, r6, r7
    and 	r6, r2, r3
    orr 	r7, r2, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 | s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m | s1_m
    eor 	r12, r12, r11
    eor 	r5, r5, r4
    eor 	r10, r10, r12
    eor 	r3, r3, r5
    orn 	r6, r9, r3
    and 	r7, r9, r10
    eor 	r8, r6, r7
    orn 	r6, r2, r3
    and 	r7, r2, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 & s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m & s1_m
    mvn 	r12, r12
    // linear layer
    orr 	r6, r14, r14, lsl #2
    eor 	r8, r10, r10, lsr #1
    and 	r8, r8, r6
    eor 	r10, r10, r8
    eor 	r10, r10, r8, lsl #1 	//SWAPMOVE(r10, r10, 0x55555555, 1)
    eor 	r8, r3, r3, lsr #1
    and 	r8, r8, r6
    eor 	r3, r3, r8
    eor 	r3, r3, r8, lsl #1 		//SWAPMOVE(r3, r3, 0x55555555, 1)
    eor 	r8, r12, r12, lsr #1
    and 	r8, r8, r6, lsr #16
    eor 	r12, r12, r8
    eor 	r12, r12, r8, lsl #1 	//SWAPMOVE(r12, r12, 0x55550000, 1)
    eor 	r8, r5, r5, lsr #1
    and 	r8, r8, r6, lsr #16
    eor 	r5, r5, r8
    eor 	r5, r5, r8, lsl #1 		//SWAPMOVE(r5, r5, 0x55550000, 1)
    eor 	r8, r11, r11, lsr #1
    and 	r8, r8, r6, lsl #16
    eor 	r11, r11, r8
    eor 	r11, r11, r8, lsl #1 	//SWAPMOVE(r11, r11, 0x00005555, 1)
    eor 	r8, r4, r4, lsr #1
    and 	r8, r8, r6, lsl #16
    eor 	r4, r4, r8
    eor 	r4, r4, r8, lsl #1 		//SWAPMOVE(r4, r4, 0x00005555, 1)
    ldrd 	r6, r7, [r1], #8 		//load rkey
    eor 	r10, r10, r6
    eor 	r11, r7, r11, ror #16
    ldrd 	r6, r7, [r1, #312] 		//load rkey_mask
    ldr.w   r14, [r0], #4 			//load rconst
    eor 	r3, r3, r6
    eor 	r4, r7, r4, ror #16
    eor 	r9, r9, r14
    // 4th round
    // sbox layer
    orn 	r6, r11, r5, ror #16
    and 	r7, r11, r12, ror #16
    eor 	r8, r6, r7
    orn 	r6, r4, r5, ror #16
    and 	r7, r4, r12, ror #16
    eor 	r7, r7, r6
    eor 	r10, r10, r8 			//s1 ^= s0 & s2
    eor 	r3, r3, r7 				//s1_m ^= s0_m & s2_m
    orn 	r6, r10, r2
    and 	r7, r10, r9
    eor 	r8, r6, r7
    orn 	r6, r3, r2
    and 	r7, r3, r9
    eor 	r7, r7, r6
    eor 	r12, r8, r12, ror #16 	//s0 ^= s1 & s3
    eor 	r5, r7, r5, ror #16 	//s0_m ^= s1 & s3
    orr 	r6, r12, r3
    and 	r7, r12, r10
    eor 	r8, r6, r7
    and 	r6, r5, r3
    orr 	r7, r5, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 | s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m | s1_m
    eor 	r9, r9, r11
    eor 	r2, r2, r4
    eor 	r10, r10, r9 
    eor 	r3, r3, r2 
    orn 	r6, r12, r3
    and 	r7, r12, r10
    eor 	r8, r6, r7
    orn 	r6, r5, r3
    and 	r7, r5, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 & s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m & s1_m
    mvn 	r9, r9
    //linear layer
    movw 	r6, #0x0f0f
    movt 	r6, #0x0f0f
    and 	r8, r6, r10, lsr #4
    and 	r10, r10, r6
    orr 	r10, r8, r10, lsl #4 	//BYTE_ROR(r10, 4)
    and 	r8, r6, r3, lsr #4
    and 	r3, r3, r6
    orr 	r3, r8, r3, lsl #4 		//BYTE_ROR(r3, 4)
    orr 	r6, r6, r6, lsl #2 		//0x3f3f3f3f for BYTE_ROR
    mvn 	r8, r6
    and 	r7, r8, r11, lsl #6
    and 	r11, r6, r11, lsr #2
    orr 	r11, r11, r7 			//BYTE_ROR(r11, 2)
    and 	r7, r8, r4, lsl #6
    and 	r4, r6, r4, lsr #2
    orr 	r4, r4, r7 				//BYTE_ROR(r4, 2)
    mvn 	r8, r6, lsr #6
    and 	r7, r8, r9, lsr #6
    and 	r9, r6, r9
    orr 	r9, r7, r9, lsl #2 		//BYTE_ROR(r9, 6)
    and 	r7, r8, r2, lsr #6
    and 	r2, r6, r2
    orr 	r2, r7, r2, lsl #2 		//BYTE_ROR(r2, 6)
    // ARK
    ldrd 	r6, r7, [r1], #8 		//load rkey
    eor 	r10, r10, r6
    eor 	r11, r11, r7
    ldrd 	r6, r7, [r1, #312] 		//load rkey_mask
    ldr.w   r14, [r0], #4 			//load rconst
    eor 	r3, r3, r6
    eor 	r4, r4, r7
    eor 	r12, r12, r14
    // 5th round
    //sbox layer
    orn 	r6, r9, r4
    and 	r7, r9, r11
    eor 	r8, r6, r7
    orn 	r6, r2, r4
    and 	r7, r2, r11
    eor 	r7, r7, r6
    eor 	r10, r10, r8 			//s1 ^= s0 & s2
    eor 	r3, r3, r7 				//s1_m ^= s0_m & s2_m
    orn 	r6, r10, r5
    and 	r7, r10, r12
    eor 	r8, r6, r7
    orn 	r6, r3, r5
    and 	r7, r3, r12
    eor 	r7, r7, r6
    eor 	r9, r9, r8 				//s0 ^= s1 & s3
    eor 	r2, r2, r7 				//s0_m ^= s1_m & s3_m
    orr 	r6, r9, r3
    and 	r7, r9, r10
    eor 	r8, r6, r7
    and 	r6, r2, r3
    orr 	r7, r2, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 | s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m | s1_m
    eor 	r12, r12, r11
    eor 	r5, r5, r4
    eor 	r10, r10, r12
    eor 	r3, r3, r5
    orn 	r6, r9, r3
    and 	r7, r9, r10
    eor 	r8, r6, r7
    orn 	r6, r2, r3
    and 	r7, r2, r10
    eor 	r7, r7, r6
    eor 	r11, r11, r8 			//s2 ^= s0 & s1
    eor 	r4, r4, r7 				//s2_m ^= s0_m & s1_m
    mvn 	r12, r12, ror #24
    //ARK
    ldrd 	r6, r7, [r1], #8 		//load rkey
    eor 	r10, r6, r10, ror #16
    eor 	r11, r7, r11, ror #8
    ldrd 	r6, r7, [r1, #312] 		//load rkey_mask
    eor 	r3, r6, r3, ror #16
    eor 	r4, r7, r4, ror #8
    ldr.w   r6, [r0], #4 			//load rconst
    ldr.w 	r14, [sp]
    eor 	r9, r9, r6
    eor     r9, r9, r12             //swap r9 with r12
    eor     r12, r12, r9            //swap r9 with r12
    eor     r9, r9, r12             //swap r9 with r12
    eor     r2, r2, r5             	//swap r2 with r5
    eor     r5, r5, r2            	//swap r2 with r5
    eor     r2, r2, r5             	//swap r2 with r5
    ror 	r2, r2, #24 			//to match the sbox code at the next call
    bx 		lr

/*****************************************************************************
* 1st order masked implementation of the GIFTb-128 block cipher. This function
* simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void giftb128_encrypt_block(u8 *out, const u32* rkey, const u8 *block)
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push 	{r0-r12,r14}
    ldm 	r2, {r6-r8,r14} 		//load plaintext blocks
    rev 	r6, r6
    rev 	r7, r7
    rev 	r8, r8
    rev 	r14, r14
    // ------------------ MASKING ------------------
    // generation of 4 random words
    movw 	r11, 0x0804
    movt 	r11, 0x5006 			//r11<- RNG_SR = 0x50060804
    mov 	r12, #4
    add 	r9, r11, #4  			//r9 <- RNG_DR = 0x50060808
giftb128_block_get_random:
    ldr 	r10, [r11]
    cmp 	r10, #1 				//check if RNG_SR == RNG_SR_DRDY
    bne 	giftb128_block_get_random
    ldr 	r10, [r9] 				//put the random number in r10
    push 	{r10} 					//push r10 on the stack
    subs 	r12, #1
    bne 	giftb128_block_get_random
    pop 	{r2-r5} 				//pop the randomn numbers from the stack
    eor 	r9, r2, r6 				//apply masks to the internal state
    eor 	r10, r3, r7 			//apply masks to the internal state
    eor 	r11, r4, r8 			//apply masks to the internal state
    eor 	r12, r5, r14 			//apply masks to the internal state
    // ------------------ GIFTb-CORE ROUTINE ------------------
    adr 	r0, rconst 				//put 'rconst' address in r0
    sub.w 	sp, #4 					//allocate space on stack to store 'lr'
    bl 		quintuple_round_masked 	//1st quintuple round
    bl 		quintuple_round_masked 	//2nd quintuple round
    bl 		quintuple_round_masked 	//3rd quintuple round
    bl 		quintuple_round_masked 	//4th quintuple round
    bl 		quintuple_round_masked 	//5th quintuple round
    bl 		quintuple_round_masked 	//6th quintuple round
    bl 		quintuple_round_masked 	//7th quintuple round
    bl 		quintuple_round_masked 	//8th quintuple round
    add.w 	sp, #4 					//restore the stack
    ldr.w 	r0, [sp] 				//restore 'ctext' address
    // ------------------ UNMASKING ------------------
    mov 	r6, r9
    mov 	r9, #0 					//clear r9 before unmasking to avoid HD leakages
    mov 	r7, r10
    mov 	r10, #0 				//clear r10 before unmasking to avoid HD leakages
    mov 	r8, r11
    mov 	r11, #0 				//clear r11 before unmasking to avoid HD leakages
    mov 	r14, r12
    mov 	r12, #0 				//clear r12 before unmasking to avoid HD leakages
    eor 	r9, r6, r2 				//unmask the internal state
    eor 	r10, r7, r3 			//unmask the internal state
    eor 	r11, r8, r4 			//unmask the internal state
    eor 	r12, r14, r5 			//unmask the internal state
    rev 	r9, r9
    rev 	r10, r10
    rev 	r11, r11
    rev 	r12, r12
    stm 	r0, {r9-r12}           //store output in RAM
    pop 	{r0-r12,r14}           //restore context
    bx 		lr

classical_key_update:
    // 1st classical key update
    and     r2, r10, r7, lsr #12
    and     r3, r7, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r7, lsr #2
    orr     r2, r2, r3
    and     r7, r7, #0x00030000
    orr     r7, r2, r7, lsl #14
    str.w   r7, [r1, #4]
    str.w   r5, [r1], #8
    // 2nd classical key update
    and     r2, r10, r6, lsr #12
    and     r3, r6, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r6, lsr #2
    orr     r2, r2, r3
    and     r6, r6, #0x00030000
    orr     r6, r2, r6, lsl #14
    str.w   r6, [r1, #4]
    str.w   r4, [r1], #8
    // 3rd classical key update
    and     r2, r10, r5, lsr #12
    and     r3, r5, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r5, lsr #2
    orr     r2, r2, r3
    and     r5, r5, #0x00030000
    orr     r5, r2, r5, lsl #14
    str.w   r5, [r1, #4]
    str.w   r7, [r1], #8
    // 4th classical key update
    and     r2, r10, r4, lsr #12
    and     r3, r4, r9
    orr     r2, r2, r3, lsl #4
    and     r3, r12, r4, lsr #2
    orr     r2, r2, r3
    and     r4, r4, #0x00030000
    orr     r4, r2, r4, lsl #14
    str.w   r4, [r1, #4]
    str.w   r6, [r1], #8
    bx      lr

rearrange_rkey_0:
    ldrd    r6, r4, [r1]
    eor     r12, r6, r6, lsr #9
    and     r12, r12, r3
    eor     r6, r12
    eor     r6, r6, r12, lsl #9     //SWAPMOVE(r6, r6, 0x00550055, 9);
    eor     r12, r4, r4, lsr #9
    and     r12, r12, r3
    eor     r4, r12
    eor     r4, r4, r12, lsl #9     //SWAPMOVE(r4, r4, 0x00550055, 9);
    eor     r12, r6, r6, lsr #18
    and     r12, r12, r10
    eor     r6, r12
    eor     r6, r6, r12, lsl #18    //SWAPMOVE(r6, r6, 0x3333, 18);
    eor     r12, r4, r4, lsr #18
    and     r12, r12, r10
    eor     r4, r12
    eor     r4, r4, r12, lsl #18    //SWAPMOVE(r4, r4, 0x3333, 18);
    eor     r12, r6, r6, lsr #12
    and     r12, r12, r11
    eor     r6, r12
    eor     r6, r6, r12, lsl #12    //SWAPMOVE(r6, r6, 0x000f000f, 12);
    eor     r12, r4, r4, lsr #12
    and     r12, r12, r11
    eor     r4, r12
    eor     r4, r4, r12, lsl #12    //SWAPMOVE(r4, r4, 0x000f000f, 12);
    eor     r12, r6, r6, lsr #24
    and     r12, r12, #0xff
    eor     r6, r12
    eor     r6, r6, r12, lsl #24    //SWAPMOVE(r6, r6, 0x000000ff, 24);
    eor     r12, r4, r4, lsr #24
    and     r12, r12, #0xff
    eor     r4, r12
    eor     r4, r4, r12, lsl #24    //SWAPMOVE(r4, r4, 0x000000ff, 24);
    str.w   r4, [r1, #4]
    str.w   r6, [r1]
    bx      lr

rearrange_rkey_1:
    ldrd    r5, r7, [r1]
    eor     r8, r7, r7, lsr #3
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #3      //SWAPMOVE(r7, r7, 0x11111111, 3);
    eor     r8, r5, r5, lsr #3
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #3      //SWAPMOVE(r5, r5, 0x11111111, 3);
    eor     r8, r7, r7, lsr #6
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #6      //SWAPMOVE(r7, r7, 0x03030303, 6);
    eor     r8, r5, r5, lsr #6
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #6      //SWAPMOVE(r5, r5, 0x03030303, 6);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x000000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    str.w   r7, [r1, #4]
    str.w   r5, [r1]
    bx      lr

rearrange_rkey_2:
    ldrd    r5, r7, [r1]
    eor     r8, r7, r7, lsr #15
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #15     //SWAPMOVE(r7, r7, 0x0000aaaa, 15);
    eor     r8, r5, r5, lsr #15
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #15     //SWAPMOVE(r5, r5, 0x0000aaaa, 15);
    eor     r8, r7, r7, lsr #18
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #18     //SWAPMOVE(r7, r7, 0x00003333, 18);
    eor     r8, r5, r5, lsr #18
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #18     //SWAPMOVE(r5, r5, 0x00003333, 18);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x00000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    str.w   r7, [r1, #4]
    str.w   r5, [r1]
    bx      lr

rearrange_rkey_3:
    ldrd    r5, r7, [r1]
    eor     r8, r7, r7, lsr #3
    and     r8, r8, r3
    eor     r7, r8
    eor     r7, r7, r8, lsl #3      //SWAPMOVE(r7, r7, 0x0a0a0a0a, 3);
    eor     r8, r5, r5, lsr #3
    and     r8, r8, r3
    eor     r5, r8
    eor     r5, r5, r8, lsl #3      //SWAPMOVE(r5, r5, 0x0a0a0a0a, 3);
    eor     r8, r7, r7, lsr #6
    and     r8, r8, r10
    eor     r7, r8
    eor     r7, r7, r8, lsl #6      //SWAPMOVE(r7, r7, 0x00cc00cc, 6);
    eor     r8, r5, r5, lsr #6
    and     r8, r8, r10
    eor     r5, r8
    eor     r5, r5, r8, lsl #6      //SWAPMOVE(r5, r5, 0x00cc00cc, 6);
    eor     r8, r7, r7, lsr #12
    and     r8, r8, r11
    eor     r7, r8
    eor     r7, r7, r8, lsl #12     //SWAPMOVE(r7, r7, 0x000f000f, 12);
    eor     r8, r5, r5, lsr #12
    and     r8, r8, r11
    eor     r5, r8
    eor     r5, r5, r8, lsl #12     //SWAPMOVE(r5, r5, 0x000f000f, 12);
    eor     r8, r7, r7, lsr #24
    and     r8, r8, #0xff
    eor     r7, r8
    eor     r7, r7, r8, lsl #24     //SWAPMOVE(r7, r7, 0x000000ff, 24);
    eor     r8, r5, r5, lsr #24
    and     r8, r8, #0xff
    eor     r5, r8
    eor     r5, r5, r8, lsl #24     //SWAPMOVE(r5, r5, 0x000000ff, 24);
    str.w   r7, [r1, #4]
    str.w   r5, [r1]
    bx      lr

key_update_0:
    ldrd    r4, r5, [r1], #80
    and     r2, r12, r4, ror #24
    and     r4, r4, r11
    orr     r4, r2, r4, ror #16     //KEY_TRIPLE_UPDATE_1(r4)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r8
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x55551100, 1)
    eor     r2, r5, r5, lsr #16
    and     r2, r2, r10
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #16     //SWAPMOVE(r5, r5, 0x00003333, 16)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r9
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x555544444, 1)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    and     r2, r12, r5, ror #24
    and     r5, r5, r11
    orr     r5, r2, r5, ror #16     //KEY_TRIPLE_UPDATE_1(r5)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r8
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x55551100, 1)
    eor     r2, r4, r4, lsr #16
    and     r2, r2, r10
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #16     //SWAPMOVE(r4, r4, 0x00003333, 16)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r9
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x555544444, 1)
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
    and     r2, r12, r4, ror #24
    and     r4, r4, r11
    orr     r4, r2, r4, ror #16     //KEY_TRIPLE_UPDATE_1(r4)
    eor     r2, r4, r4, lsr #1
    and     r2, r2, r8
    eor     r4, r4, r2
    eor     r4, r4, r2, lsl #1      //SWAPMOVE(r4, r4, 0x55551100, 1)
    eor     r2, r5, r5, lsr #16
    and     r2, r2, r10
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #16     //SWAPMOVE(r5, r5, 0x00003333, 16)
    eor     r2, r5, r5, lsr #1
    and     r2, r2, r9
    eor     r5, r5, r2
    eor     r5, r5, r2, lsl #1      //SWAPMOVE(r5, r5, 0x555544444, 1)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

key_update_1:
    ldrd    r4, r5, [r1], #80
    and     r2, r9, r4, lsr #6
    and     r3, r4, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #5
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r12, r5, lsr #4
    and     r3, r5, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r5, lsr #6
    orr     r2, r2, r3
    and     r5, r5, r10
    orr     r5, r2, r5, lsl #2      //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    and     r2, r9, r5, lsr #6
    and     r3, r5, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #5
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r12, r4, lsr #4
    and     r3, r4, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r4, lsr #6
    orr     r2, r2, r3
    and     r4, r4, r10
    orr     r4, r2, r4, lsl #2      //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
    and     r2, r9, r4, lsr #6
    and     r3, r4, r10, lsl #8
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #5
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r12, r5, lsr #4
    and     r3, r5, r12
    orr     r2, r2, r3, lsl #4
    and     r3, r11, r5, lsr #6
    orr     r2, r2, r3
    and     r5, r5, r10
    orr     r5, r2, r5, lsl#2       //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

key_update_2:
    ldrd    r4, r5, [r1], #80
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    and     r2, r12, r5, ror #24
    and     r5, r11, r5, ror #20
    orr     r5, r5, r2              //KEY_TRIPLE_UPDATE_2(r5)
    and     r2, r11, r4, ror #24
    and     r4, r12, r4, ror #16
    orr     r4, r4, r2              //KEY_DOUBLE_UPDATE_2(r4)
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
    and     r2, r12, r4, ror #24
    and     r4, r11, r4, ror #20
    orr     r4, r4, r2              //KEY_TRIPLE_UPDATE_2(r4)
    and     r2, r11, r5, ror #24
    and     r5, r12, r5, ror #16
    orr     r5, r5, r2              //KEY_DOUBLE_UPDATE_2(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

key_update_3:
    ldrd    r4, r5, [r1], #80
    and     r2, r10, r4, lsr #18
    and     r3, r4, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r4, lsr #14
    orr     r2, r2, r3
    and     r3, r4, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7, lsr #16
    orr     r4, r2, r4, lsl #19     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r9, r5, lsr #2
    and     r3, r9, r5
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    and     r2, r10, r5, lsr #18
    and     r3, r5, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r5, lsr #14
    orr     r2, r2, r3
    and     r3, r5, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7, lsr #16
    orr     r5, r2, r5, lsl #19     //KEY_TRIPLE_UPDATE_4(r5)
    and     r2, r9, r4, lsr #2
    and     r3, r9, r4
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7
    orr     r4, r2, r4, lsl #3      //KEY_DOUBLE_UPDATE_4(r4)
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
    and     r2, r10, r4, lsr #18
    and     r3, r4, r7, lsr #4
    orr     r2, r2, r3, lsl #3
    and     r3, r11, r4, lsr #14
    orr     r2, r2, r3
    and     r3, r4, r12, lsr #11
    orr     r2, r2, r3, lsl #15
    and     r3, r12, r4, lsr #1
    orr     r2, r2, r3
    and     r4, r4, r7, lsr #16
    orr     r4, r2, r4, lsl #19     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r9, r5, lsr #2
    and     r3, r9, r5
    orr     r2, r2, r3, lsl #2
    and     r3, r8, r5, lsr #1
    orr     r2, r2, r3
    and     r5, r5, r7
    orr     r5, r2, r5, lsl #3      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

key_update_4:
    ldrd    r4, r5, [r1], #80
    and     r2, r7, r4, lsr #6
    and     r3, r4, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r4, lsr #4
    orr     r2, r2, r3
    and     r4, r4, #0x000f
    orr     r4, r2, r4, lsl #12     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r10, r5, lsr #4
    and     r3, r5, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r5, lsr #8
    orr     r2, r2, r3
    and     r5, r5, r8
    orr     r5, r2, r5, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    and     r2, r7, r5, lsr #6
    and     r3, r5, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r5, lsr #4
    orr     r2, r2, r3
    and     r5, r5, #0x000f
    orr     r5, r2, r5, lsl #12     //KEY_TRIPLE_UPDATE_4(r5)
    and     r2, r10, r4, lsr #4
    and     r3, r4, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r4, lsr #8
    orr     r2, r2, r3
    and     r4, r4, r8
    orr     r4, r2, r4, lsl #8      //KEY_DOUBLE_UPDATE_4(r4)
    str.w   r5, [r1, #4]
    str.w   r4, [r1], #80
    and     r2, r7, r4, lsr #6
    and     r3, r4, #0x003f0000
    orr     r2, r2, r3, lsl #10
    and     r3, r12, r4, lsr #4
    orr     r2, r2, r3
    and     r4, r4, #0x000f
    orr     r4, r2, r4, lsl #12     //KEY_TRIPLE_UPDATE_4(r4)
    and     r2, r10, r5, lsr #4
    and     r3, r5, #0x000f0000
    orr     r2, r2, r3, lsl #12
    and     r3, r8, r5, lsr #8
    orr     r2, r2, r3
    and     r5, r5, r8
    orr     r5, r2, r5, lsl #8      //KEY_DOUBLE_UPDATE_4(r5)
    str.w   r4, [r1, #4]
    str.w   r5, [r1], #80
    bx      lr

/*****************************************************************************
* 1st order masked implementation of the GIFT-128 key schedule according to
* the fixsliced representation.
*****************************************************************************/
@ void gift128_keyschedule(const u8* key, u32* rkey) {
.global gift128_keyschedule
.type   gift128_keyschedule,%function
gift128_keyschedule:
    push    {r0-r12, r14}
    ldm     r0, {r9-r12}         	//load key words
    mov 	r0, #2 					//r0 <- 2
    rev     r9, r9              	//endianness (could be skipped with another representation)
    rev     r10, r10             	//endianness (could be skipped with another representation)
    rev     r11, r11         		//endianness (could be skipped with another representation)
    rev     r12, r12            	//endianness (could be skipped with another representation)
    // ------------------ MASKING ------------------
    // generation of 4 random words
    movw 	r14, 0x0804
    movt 	r14, 0x5006 			//r14<- RNG_SR = 0x50060804
    mov 	r2, #4
    add 	r3, r14, #4  			//r3 <- RNG_DR = 0x50060808
gift128_key_get_random:
    ldr.w 	r4, [r14]
    cmp 	r4, #1 					//check if RNG_SR == RNG_SR_DRDY
    bne 	gift128_key_get_random
    ldr.w 	r4, [r3] 				//put the random number in r10
    push 	{r4} 					//push r10 on the stack
    subs 	r2, #1
    bne 	gift128_key_get_random
    pop 	{r2,r3,r8,r14} 			//pop the randomn numbers from the stack
    eor 	r4, r9, r2 				//apply masks to the internal state
    eor 	r5, r10, r3 			//apply masks to the internal state
    eor 	r6, r11, r8 			//apply masks to the internal state
    eor 	r7, r12, r14 			//apply masks to the internal state
    strd   	r7, r5, [r1], #8 		//store the first rkeys
    strd   	r14, r3, [r1, #312] 	//store the corresponding masks
    strd   	r6, r4, [r1], #8 		//store the first rkeys
    strd  	r8, r2, [r1, #312]    	//store the corresponding masks
loop:
    // keyschedule using classical representation for the first 20 rounds
    movw    r12, #0x3fff
    lsl     r12, r12, #16           //r12<- 0x3fff0000
    movw    r10, #0x000f            //r10<- 0x0000000f
    movw    r9, #0x0fff             //r9 <- 0x00000fff
    bl      classical_key_update
    bl      classical_key_update
    sub.w   r1, r1, #80
    // rearrange the rkeys to their respective new representations
    movw    r3, #0x0055
    movt    r3, #0x0055             //r3 <- 0x00550055
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0x000f
    movt    r11, #0x000f            //r11<- 0x000f000f
    bl      rearrange_rkey_0
    add.w   r1, r1, #40
    bl      rearrange_rkey_0
    sub.w   r1, r1, #32
    movw    r3, #0x1111
    movt    r3, #0x1111             //r3 <- 0x11111111
    movw    r10, #0x0303
    movt    r10, #0x0303            //r10<- 0x03030303
    bl      rearrange_rkey_1
    add.w   r1, r1, #40
    bl      rearrange_rkey_1
    sub.w   r1, r1, #32
    movw    r3, #0xaaaa             //r3 <- 0x0000aaaa
    movw    r10, #0x3333            //r10<- 0x00003333
    movw    r11, #0xf0f0            //r11<- 0x0000f0f0
    bl      rearrange_rkey_2
    add.w   r1, r1, #40
    bl      rearrange_rkey_2
    sub.w   r1, r1, #32
    movw    r3, #0x0a0a
    movt    r3, #0x0a0a             //r3 <- 0x0a0a0a0a
    movw    r10, #0x00cc
    movt    r10, #0x00cc            //r10<- 0x00cc00cc
    bl      rearrange_rkey_3
    add.w   r1, r1, #40
    bl      rearrange_rkey_3
    sub.w   r1, r1, #64
    movw    r10, #0x3333            //r10<- 0x00003333
    eor     r12, r10, r10, lsl #16  //r12<- 0w33333333 
    mvn     r11, r12                //r11<- 0xcccccccc
    movw    r9, #0x4444
    movt    r9, #0x5555             //r9 <- 0x55554444
    movw    r8, #0x1100
    movt    r8, #0x5555             //r8 <- 0x55551100
    bl      key_update_0 			//keyupdate according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_0 			//keyupdate according to fixslicing
    sub.w   r1, r1, #352
    movw    r12, #0x0f00
    movt    r12, #0x0f00            //r12<- 0x0f000f00
    movw    r11, #0x0003
    movt    r11, #0x0003            //r11<- 0x00030003
    movw    r10, #0x003f
    movt    r10, #0x003f            //r10<- 0x003f003f
    lsl     r9, r11, #8             //r9 <- 0x03000300
    and     r8, r10, r10, lsr #3    //r8 <- 0x00070007
    orr     r7, r8, r8, lsl #2      //r7 <- 0x001f001f
    bl      key_update_1 			//keyupdate according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_1 			//keyupdate according to fixslicing
    sub.w   r1, r1, #352
    movw    r12, #0x5555
    movt    r12, #0x5555            //r12<- 0x55555555
    mvn     r11, r12                //r11<- 0xaaaaaaaa
    bl      key_update_2 			//keyupdate according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_2 			//keyupdate according to fixslicing
    sub.w   r1, r1, #352
    orr     r12, r8, r8, lsl #8     //r12<- 0x07070707
    movw    r11, #0xc0c0            //r11<- 0x0000c0c0
    movw    r10, #0x3030            //r10<- 0x00003030
    and     r9, r12, r12, lsr #1    //r9 <- 0x03030303
    lsl     r8, r12, #4             //r8 <- 0x70707070
    eor     r7, r8, r9, lsl #5      //r7 <- 0x10101010
    movw    r6, #0xf0f0             //r6 <- 0x0000f0f0
    bl      key_update_3 			//keyupdate according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_3 			//keyupdate according to fixslicing
    sub.w   r1, r1, #352
    movw    r12, #0x0fff
    lsl     r10, r12, #16
    movw    r8, #0x00ff             //r8 <- 0x000000ff
    movw    r7, #0x03ff             //r7 <- 0x000003ff
    lsl     r7, r7, #16
    bl      key_update_4 			//keyupdate according to fixslicing
    sub.w   r1, r1, #280
    bl      key_update_4 			//keyupdate according to fixslicing
    sub.w 	r1, r1, #72 			//r1 now points to the masks
    ldrd 	r7, r5, [r1], #8
    ldrd 	r6, r4, [r1], #8
    subs 	r0, r0, #1 				//r0 <- r0-1 
    bne 	loop 					//go to 'loop' if r0=0
    pop     {r0-r12,r14}
    bx      lr
