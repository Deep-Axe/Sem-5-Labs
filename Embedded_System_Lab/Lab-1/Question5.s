	AREA RESET, DATA, READONLY
	EXPORT __Vectors
__Vectors
    DCD 0x10000000
    DCD Reset_Handler
    ALIGN
	AREA DeepCode, CODE, READONLY
	ENTRY
	EXPORT Reset_Handler
Reset_Handler
    MOV R3, #5
    LDR R0, = SRC + (N - 1)*4
    LDR R1, = SRC +(N - 1 + Shifts)*4
BACK
    LDR R2, [R0], #-4
    STR R2, [R1], #-4
    SUB R3, R3, #1
    CMP R3, #0
    BNE BACK
STOP B STOP
N EQU 5
Shifts EQU 2
	AREA DeepData, DATA, READWRITE
SRC DCD 0,0,0,0,0,0,0
	END
