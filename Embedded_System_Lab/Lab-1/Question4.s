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
    LDR R0, =SRC
    LDR R1, =DSTN
BACK
    LDR R2, [R0], #4
    STR R2, [R1], #4
    SUB R3, R3, #1
    CMP R3, #0
    BNE BACK
STOP B STOP

	AREA DeepData, DATA, READWRITE
SRC DCD 0x12345678, 0xFF10, 0xAAAA, 0xBBBB, 0xCCCC
DSTN DCD 0,0,0,0,0
	END
