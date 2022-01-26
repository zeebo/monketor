#include "textflag.h"

// func trampoline()
TEXT ·trampoline(SB), NOSPLIT, $0
	ADJSP $24
	MOVQ R12, (0)(SP)
	MOVQ R13, (8)(SP)

	MOVQ ·ctrBase(SB), R12
	MOVQ ·ordOffset(SB), R13
	ADDQ 24(SP), R13
	MOVL (R13), R13
	INCL (R12)(R13*4)
	MOVQ ·tabOffset(SB), R12
	ADDQ 24(SP), R12
	MOVL (R12), R12
	
	MOVQ R12, 16(SP)
	MOVQ (0)(SP), R12
	MOVQ (8)(SP), R13

	ADJSP $-24
	JMP -8(SP)

