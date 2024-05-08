//go:build !noasm && arm64
// AUTO-GENERATED BY GOAT -- DO NOT EDIT

TEXT ·dot_byte_256(SB), $0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD res+16(FP), R2
	MOVD len+24(FP), R3
	WORD $0xa9bf7bfd    // stp	x29, x30, [sp,
	WORD $0xf9400068    // ldr	x8, [x3]
	WORD $0x910003fd    // mov	x29, sp
	WORD $0x6b0803e9    // negs	w9, w8
	WORD $0x12000d0a    // and	w10, w8,
	WORD $0x12000d29    // and	w9, w9,
	WORD $0x5a894549    // csneg	w9, w10, w9, mi
	WORD $0x4b09010a    // sub	w10, w8, w9
	WORD $0x7101015f    // cmp	w10,
	WORD $0x540000ea    // b.ge	.LBB0_2
	WORD $0x6f00e400    // movi	v0.2d,
	WORD $0x2a1f03eb    // mov	w11, wzr
	WORD $0x6f00e401    // movi	v1.2d,
	WORD $0x6f00e403    // movi	v3.2d,
	WORD $0x6f00e402    // movi	v2.2d,
	WORD $0x1400001a    // b	.LBB0_4

LBB0_2:
	WORD $0x6f00e402 // movi	v2.2d,
	WORD $0xaa1f03eb // mov	x11, xzr
	WORD $0x6f00e403 // movi	v3.2d,
	WORD $0x6f00e401 // movi	v1.2d,
	WORD $0x6f00e400 // movi	v0.2d,

LBB0_3:
	WORD $0x8b0b000c // add	x12, x0, x11
	WORD $0x4c402184 // ld1	{ v4.16b, v5.16b, v6.16b, v7.16b }, [x12]
	WORD $0x8b0b002c // add	x12, x1, x11
	WORD $0x4c402190 // ld1	{ v16.16b, v17.16b, v18.16b, v19.16b }, [x12]
	WORD $0x9102016c // add	x12, x11,
	WORD $0x9101016b // add	x11, x11,
	WORD $0xeb0a019f // cmp	x12, x10
	WORD $0x4e249e14 // mul	v20.16b, v16.16b, v4.16b
	WORD $0x4e259e35 // mul	v21.16b, v17.16b, v5.16b
	WORD $0x4e269e56 // mul	v22.16b, v18.16b, v6.16b
	WORD $0x4e279e64 // mul	v4.16b, v19.16b, v7.16b
	WORD $0x4e202a85 // saddlp	v5.8h, v20.16b
	WORD $0x4e202aa6 // saddlp	v6.8h, v21.16b
	WORD $0x4e202ac7 // saddlp	v7.8h, v22.16b
	WORD $0x4e202884 // saddlp	v4.8h, v4.16b
	WORD $0x4e6068a2 // sadalp	v2.4s, v5.8h
	WORD $0x4e6068c3 // sadalp	v3.4s, v6.8h
	WORD $0x4e6068e1 // sadalp	v1.4s, v7.8h
	WORD $0x4e606880 // sadalp	v0.4s, v4.8h
	WORD $0x54fffda9 // b.ls	.LBB0_3

LBB0_4:
	WORD $0x6b0a017f // cmp	w11, w10
	WORD $0x5400016a // b.ge	.LBB0_7
	WORD $0x2a0b03eb // mov	w11, w11
	WORD $0x93407d4c // sxtw	x12, w10

LBB0_6:
	WORD $0x3ceb6804 // ldr	q4, [x0, x11]
	WORD $0x3ceb6825 // ldr	q5, [x1, x11]
	WORD $0x9100416b // add	x11, x11,
	WORD $0xeb0c017f // cmp	x11, x12
	WORD $0x4e249ca4 // mul	v4.16b, v5.16b, v4.16b
	WORD $0x4e202884 // saddlp	v4.8h, v4.16b
	WORD $0x4e606882 // sadalp	v2.4s, v4.8h
	WORD $0x54ffff2b // b.lt	.LBB0_6

LBB0_7:
	WORD $0x4eb1b842 // addv	s2, v2.4s
	WORD $0x7100053f // cmp	w9,
	WORD $0x4eb1b863 // addv	s3, v3.4s
	WORD $0x4eb1b821 // addv	s1, v1.4s
	WORD $0x1e26004b // fmov	w11, s2
	WORD $0x1e26006c // fmov	w12, s3
	WORD $0x4eb1b800 // addv	s0, v0.4s
	WORD $0x0b0b018b // add	w11, w12, w11
	WORD $0x1e26002c // fmov	w12, s1
	WORD $0x0b0c016b // add	w11, w11, w12
	WORD $0x1e26000c // fmov	w12, s0
	WORD $0x0b0c016b // add	w11, w11, w12
	WORD $0x5400018b // b.lt	.LBB0_9
	WORD $0x5100050c // sub	w12, w8,
	WORD $0x1100054d // add	w13, w10,
	WORD $0x93407d8c // sxtw	x12, w12
	WORD $0x6b0801bf // cmp	w13, w8
	WORD $0x1a8ad50a // csinc	w10, w8, w10, le
	WORD $0x0b0a0129 // add	w9, w9, w10
	WORD $0x386c682d // ldrb	w13, [x1, x12]
	WORD $0x4b080128 // sub	w8, w9, w8
	WORD $0x386c6809 // ldrb	w9, [x0, x12]
	WORD $0x1b0d7d08 // mul	w8, w8, w13
	WORD $0x1b092d0b // madd	w11, w8, w9, w11

LBB0_9:
	WORD $0xb900004b // str	w11, [x2]
	WORD $0xa8c17bfd // ldp	x29, x30, [sp],
	WORD $0xd65f03c0 // ret