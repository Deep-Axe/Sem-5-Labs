	AREA RESET, DATA, READONLY
	EXPORT __Vectors
__Vectors
    DCD 0x10001000     
    DCD Reset_Handler
    ALIGN

	AREA mycode, CODE, READONLY
	ENTRY
	EXPORT Reset_Handler

Reset_Handler
    LDR R0, =ARRAY      
    LDR R1, =ARRAY_RAM    
    MOV R2, #ARRAY_SIZE

copy_loop
    CMP R2, #0
    BEQ sort_start

    LDR R3, [R0], #4
    STR R3, [R1], #4
    SUBS R2, R2, #1
    B copy_loop

sort_start
    LDR R0, =ARRAY_RAM
    MOV R1, #ARRAY_SIZE
    MOV R2, #0

outer_loop
    CMP R2, R1
    BGE STOP

    MOV R3, R2
    ADD R4, R2, #1

inner_loop
    CMP R4, R1
    BGE swap_min

    LDR R5, [R0, R3, LSL #2]
    LDR R6, [R0, R4, LSL #2]
    CMP R6, R5
    BGE no_update_min
    MOV R3, R4

no_update_min
    ADD R4, R4, #1
    B inner_loop

swap_min
    CMP R3, R2
    BEQ skip_swap

    LDR R5, [R0, R2, LSL #2]
    LDR R6, [R0, R3, LSL #2]
    STR R6, [R0, R2, LSL #2]
    STR R5, [R0, R3, LSL #2]

skip_swap
    ADD R2, R2, #1
    B outer_loop

STOP  B STOP

ARRAY_SIZE EQU 6
ARRAY    DCD 1,2,5,3,6,0

	AREA data, DATA, READWRITE
ARRAY_RAM SPACE 24

	END
