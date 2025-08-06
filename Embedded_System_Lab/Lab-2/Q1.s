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
    LDR R0, =Numbers
    MOV R1, #0
    MOV R2, #10
    MOV R4, #0
    MOV R5, #0
SumLoop
    LDR R3, [R0], #4
    ADDS R4, R4, R3
    ADC  R5, R5, #0
    SUBS R2, R2, #1
    BNE  SumLoop
    LDR R6, =Result
    STR R4, [R6]
    LDR R6, =Carry
    STR R5, [R6]
STOP B STOP
Numbers DCD 0x1229A, 0x9999F14, 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50, 0x5A, 0xFFFFFFFF
    AREA DeepData, DATA, READWRITE
Result DCD 0
Carry DCD 0

    END
