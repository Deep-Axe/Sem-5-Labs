    AREA RESET, DATA, READONLY
    EXPORT __Vectors
__Vectors
    DCD 0x10000000
    DCD Reset_Handler
    ALIGN
    AREA DeepCode, CODE, READONLY
    ENTRY
    EXPORT Reset_Handler
	
Num2 DCD 0xD1111111, 0x22222222, 0x33333333, 0x94444444   
Num1 DCD 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD   

Reset_Handler

	LDR R0, =Num1
    LDR R1, =Num2
    LDR R2, =Result
    MOV R3, #4        
	MOVS R4, #0
	
SubLoop

    LDR R5, [R0], #4
    LDR R6, [R1], #4
    SBCS R7, R5, R6
	STR R7, [R2], #4
	SUBS R3, R3, #1
	BNE SubLoop
	
STOP B STOP

    AREA DeepData, DATA, READWRITE
Result DCD 0,0,0,0                   
    END