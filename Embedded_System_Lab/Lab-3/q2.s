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
	LDR R0, = INPUT_bcd
	LDRB R1, [R0]
	LDRB R2, [R0, #1]
	
	MOV R3, #0
	MOV R4, #10
	
	MLA R3, R1, R4, R3
	ADD R3,R3, R2
	LDR R0, = hex_res
	STR R3, [R0]
STOP B STOP

INPUT_bcd DCB 0x3, 0x9
hex_res DCB 0x0

	END