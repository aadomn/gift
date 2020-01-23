# Efficient constant-time implementations of GIFT and GIFT-COFB

GIFT is a lightweight block cipher that operates either on 64-bit or 128-bit blocks. For more information on GIFT, see: https://giftcipher.github.io/gift/.

GIFT-COFB is an authenticated cipher based on GIFT-128. It is a submission to the NIST LWC competition. For more information on GIFT-COFB, see: https://www.isical.ac.in/~lightweight/COFB/.

This repository contains optimized software implementations for the following algorithms:

- `crypto_aead/giftcofb128v1`: GIFT-COFB v1  
- `crypto_bc/gift64`: GIFT-64  
- `crypto_bc/gift128`: GIFT-128  

For each algorithm, one can find:

- `opt32`: 32-bit oriented C implementation  
- `armcortexm`: ARM assembly implementation for Cortex-M processors  

Note that ARM implementations have been compiled/tested using arm-none-eabi-gcc version 6.3.1 on the STM32L100C and STM32F407VG development boards.

Regarding C implementations, a simple Makefile is provided to run some test vectors.

