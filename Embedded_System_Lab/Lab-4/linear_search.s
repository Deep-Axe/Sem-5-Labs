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
    BEQ search_start

    LDR R3, [R0], #4
    STR R3, [R1], #4
    SUBS R2, R2, #1
    B copy_loop

search_start
    LDR R0, =ARRAY_RAM     
    MOV R1, #ARRAY_SIZE    
    LDR R2, =SEARCH_VALUE   
    LDR R2, [R2]            
    MOV R3, #0             

search_loop
    CMP R3, R1           
    BGE not_found

    LDR R4, [R0, R3, LSL #2] 
    CMP R4, R2
    BEQ found

    ADD R3, R3, #1
    B search_loop

found
    MOV R0, R3
    B STOP

not_found
    MVN R0, #0             
    B STOP

STOP B STOP

ARRAY_SIZE  EQU 6
ARRAY       DCD 1,2,5,3,6,0
SEARCH_VALUE DCD 3  

        AREA data, DATA, READWRITE
ARRAY_RAM  SPACE 24

        END
