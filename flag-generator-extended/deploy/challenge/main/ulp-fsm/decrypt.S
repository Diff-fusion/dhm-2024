#include "sdkconfig.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/rtc_io_reg.h"
#include "soc/soc_ulp.h"
#include "soc/sens_reg.h"

    .data
key_add:
    .short 35835, 34792, 315, 58643, 57287, 19882, 28091, 14325

	/* Define variables, which go into .bss section (zero-initialized data) */
	.bss

    .global key
key:
    .fill 8, 2

    .global iv
iv:
    .fill 8, 2

    .global data
data:
    .fill 2048, 2

    .global data_len
data_len:
    .long 0

data_ctr:
    .long 0

mix_block_tmp:
    .long 0

gen_block_key:
	.long 0
gen_block_iv:
	.long 0
gen_block_ctr:
	.long 0

add_blocks_ret:
    .long 0
gen_block_ret:
	.long 0

	/* Code goes into .text section */
	.text
	.global entry

entry:
    move r1, iv
    move r2, key
    move r0, ret1
    jump gen_block
ret1:

    // load addr of data + ctr
    move r3, data_ctr
    ld r2, r3, 0
    move r1, data
    add r1, r1, r2

    move r2, iv
    move r0, ret2
    jump add_blocks
ret2:

    // inc counter
    move r3, data_ctr
    ld r2, r3, 0
    add r2, r2, 4
    st r2, r3, 0
    // compare with data_len
    move r3, data_len
    ld r1, r3, 0
    // data_ctr - data_len
    sub r0, r2, r1
    // will set overflow as long as data_ctr is less than data_len
    jump entry, OV

exit:
    WRITE_RTC_FIELD(RTC_CNTL_ULP_CP_TIMER_REG, RTC_CNTL_ULP_CP_SLP_TIMER_EN, 0)
    wake
    halt


// function
add_blocks:
    // r0: ret address
    // r1: block1 src and dst
    // r2: block2 src

    // save return address
    move r3, add_blocks_ret
    st r0, r3, 0

    stage_rst
add_blocks_loop:
    ldl r0, r1, 0
    ldl r3, r2, 0
    add r0, r0, r3
    stl r0, r1, 0

    ldh r0, r1, 0
    ldh r3, r2, 0
    add r0, r0, r3
    sth r0, r1, 0

    add r1, r1, 1
    add r2, r2, 1
    stage_inc 1
    jumps add_blocks_loop, 4, LT

    // return
    move r3, add_blocks_ret
    ld r0, r3, 0
    jump r0


// function
mix_block:
    // r0: ret address
    // r1: block

    // save last value and load prev
    ldh r2, r1, 15
    //move r3, mix_block_tmp
    //stl r2, r3, 0

    stage_rst
mix_block_loop:
    // load curr
    ldl r3, r1, 0
    // add and store
    add r2, r2, r3
    stl r2, r1, 0
    // set prev = curr
    move r2, r3

    // same with high bits
    ldh r3, r1, 0
    add r2, r2, r3
    sth r2, r1, 0
    move r2, r3

    add r1, r1, 1
    stage_inc 1
    jumps mix_block_loop, 4, LT

    // return
    jump r0


// function
gen_block:
    // r0: ret address
    // r1: iv
    // r2: key

    // save return address
    move r3, gen_block_ret
    st r0, r3, 0

    // save iv
    move r3, gen_block_iv
    st r1, r3, 0

    // save key
    move r3, gen_block_key
    st r2, r3, 0

    // add iv, key
    move r0, gen_block_ret1
    jump add_blocks
gen_block_ret1:

    // set ctr zero
    move r3, gen_block_ctr
    move r0, 0
    st r0, r3, 0

gen_block_loop:

    // mix iv
    move r3, gen_block_iv
    ld r1, r3, 0
    move r0, gen_block_ret2
    jump mix_block
gen_block_ret2:

    // add key, key_add
    move r3, gen_block_key
    ld r1, r3, 0
    move r2, key_add
    move r0, gen_block_ret3
    jump add_blocks
gen_block_ret3:

    // add iv, key
    move r3, gen_block_iv
    ld r1, r3, 0
    move r3, gen_block_key
    ld r2, r3, 0
    move r0, gen_block_ret4
    jump add_blocks
gen_block_ret4:

    // inc ctr
    move r3, gen_block_ctr
    ld r0, r3, 0
    add r0, r0, 1
    st r0, r3, 0
    // loop 8 times
    jumpr gen_block_loop, 8, LT


    // return
    move r3, gen_block_ret
    ld r0, r3, 0
    jump r0
