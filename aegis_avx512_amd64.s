#include "textflag.h"

DATA C0<>+0(SB)/8, $0x0d08050302010100
DATA C0<>+8(SB)/8, $0x6279e99059372215
GLOBL C0<>(SB), RODATA|NOPTR, $16

DATA C1<>+0(SB)/8, $0xf12fc26d55183ddb
DATA C1<>+8(SB)/8, $0xdd28b57342311120
GLOBL C1<>(SB), RODATA|NOPTR, $16

// ROUND processes state in X[0..5] and uses X7 as a temporary
#define ROUND(Mreg) \
	VAESENC X0, X5, X7    \
	VAESENC X5, X4, X5    \
	VAESENC X4, X3, X4    \
	VAESENC X3, X2, X3    \
	VAESENC X2, X1, X2    \
	VAESENC X1, X0, X1    \
	VPXOR   Mreg, X7, X0

// func open256AVX512Asm(key, nonce *[32]byte, out, ciphertext, tag, additionalData []byte) (ok bool)
// AEGIS-256 unseal, EVEX/AVX-512 single stream. Requires: VAES, AVX512VL+BW.
TEXT ·open256AVX512Asm(SB), NOSPLIT, $0-113
	MOVQ out_base+16(FP), AX
	MOVQ key+0(FP), CX
	MOVQ nonce+8(FP), DX

	// Load key/nonce halves and constants.
	VMOVDQU (CX), X10            // k0
	VMOVDQU 16(CX), X11          // k1
	VMOVDQU (DX), X8             // n0
	VMOVDQU 16(DX), X9           // n1
	VMOVDQU C0<>+0(SB), X12      // C0
	VMOVDQU C1<>+0(SB), X13      // C1

	// Initial state.
	VPXOR   X8, X10, X0          // S0 = k0 ^ n0
	VPXOR   X9, X11, X1          // S1 = k1 ^ n1
	VMOVDQU X13, X2              // S2 = C1
	VMOVDQU X12, X3              // S3 = C0
	VPXOR   X12, X10, X4         // S4 = k0 ^ C0
	VPXOR   X13, X11, X5         // S5 = k1 ^ C1

	// Persistent init messages: k0, k1, k0^n0, k1^n1.
	VPXOR   X8, X10, X14         // k0 ^ n0
	VPXOR   X9, X11, X15         // k1 ^ n1
	// (k0 = X10, k1 = X11 stay put.)

	// 16 initialization rounds.
	MOVL $4, R8
initRounds:
	ROUND(X10)
	ROUND(X11)
	ROUND(X14)
	ROUND(X15)
	DECL R8
	JNZ  initRounds

	// ---- absorb additional data ----
	MOVQ additionalData_base+88(FP), DX
	MOVQ additionalData_len+96(FP), CX
	SHRQ $0x04, CX
	JZ   authPartial

authFull:
	VMOVDQU (DX), X6
	ROUND(X6)
	ADDQ $0x10, DX
	SUBQ $0x01, CX
	JNZ  authFull

authPartial:
	MOVQ additionalData_len+96(FP), CX
	ANDQ $0x0f, CX
	JZ   decrypt
	MOVL  $1, BX
	SHLL  CX, BX
	SUBL  $1, BX
	KMOVW BX, K1
	VMOVDQU8.Z (DX), K1, X6     // M = [ad | 0]  (masked load, no OOB read)
	ROUND(X6)

decrypt:
	MOVQ ciphertext_base+40(FP), DX
	MOVQ ciphertext_len+48(FP), CX
	SHRQ $0x04, CX
	JZ   decryptPartial

decryptFull:
	VMOVDQU    X5, X6
	VPTERNLOGD $0x78, X3, X2, X6   // X6 = S5 ^ (S2 & S3)
	VPTERNLOGD $0x96, X1, X4, X6   // X6 = (that) ^ S4 ^ S1 = z
	VMOVDQU (DX), X7               // ci
	VPXOR   X7, X6, X6             // xi = ci ^ z   (= M)
	VMOVDQU X6, (AX)               // store 16 plaintext bytes
	ROUND(X6)
	ADDQ $0x10, AX
	ADDQ $0x10, DX
	SUBQ $0x01, CX
	JNZ  decryptFull

decryptPartial:
	MOVQ ciphertext_len+48(FP), CX
	ANDQ $0x0f, CX
	JZ   finalize
	MOVL  $1, BX
	SHLL  CX, BX
	SUBL  $1, BX
	KMOVW BX, K1
	VMOVDQU    X5, X6
	VPTERNLOGD $0x78, X3, X2, X6   // X6 = S5 ^ (S2 & S3)
	VPTERNLOGD $0x96, X1, X4, X6   // X6 = (that) ^ S4 ^ S1 = z
	VMOVDQU8.Z (DX), K1, X7        // ci_padded = [ci | 0]  (masked, fault-suppressed)
	VPXOR      X7, X6, X7          // [pt | z_tail]
	VMOVDQU8   X7, K1, (AX)        // store n plaintext bytes
	VMOVDQU8.Z X7, K1, X6          // xn = [pt | 0]  (zero the tail for the update)
	ROUND(X6)

finalize:
	MOVQ additionalData_len+96(FP), AX
	MOVQ ciphertext_len+48(FP), CX
	SHLQ $0x03, AX              // ad bits
	SHLQ $0x03, CX              // msg bits
	VMOVQ   AX, X6
	VPINSRQ $1, CX, X6, X6      // [ad_bits | msg_bits]
	VPXOR   X3, X6, X6          // t = (that) ^ S3
	MOVL    $7, R8
finalRounds:
	ROUND(X6)
	DECL    R8
	JNZ     finalRounds
	// tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5  (two ternlogs + xor)
	VPTERNLOGD $0x96, X2, X1, X0   // S0 ^ S1 ^ S2
	VPTERNLOGD $0x96, X5, X4, X3   // S3 ^ S4 ^ S5
	VPXOR      X3, X0, X0          // tag

	// constant-time compare vs provided tag
	MOVQ     tag_base+64(FP), AX
	VMOVDQU  (AX), X9
	VPCMPEQB X9, X0, K1
	KMOVW    K1, AX
	CMPL     AX, $0x0000ffff
	SETEQ    ok+112(FP)

	VZEROALL
	// ensure we don't leak the number of correct bytes
	// in the authentication tag in any registers:
	XORL     AX, AX
	KXORW    K1, K1, K1
	RET
