        AREA RESET, DATA, READONLY
        EXPORT __Vectors
__Vectors
        DCD 0x10001000         
        DCD Reset_Handler
        ALIGN

        AREA mycode, CODE, READONLY
        ENTRY
        EXPORT Reset_Handler
        EXPORT factorial

factorial
        CMP     R0, #0
        BEQ     fact_base

        PUSH    {R0, LR}        
        SUB     R0, R0, #1
        BL      factorial
        POP     {R1, LR}
        MUL     R0, R0, R1       
        BX      LR

fact_base
        MOV     R0, #1
        BX      LR

Reset_Handler
        MOV     R0, #5          
        BL      factorial        
        LDR     R1, =RESULT       
        STR     R0, [R1]     

        B    STOP         


STOP B STOP

        AREA DATA, DATA, READWRITE
RESULT  DCD 0                    
        END
