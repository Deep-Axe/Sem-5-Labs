    AREA RESET, DATA, READONLY
    EXPORT __Vectors
__Vectors
    DCD 0x10000000
    DCD Reset_Handler
    ALIGN
    AREA LCMCode, CODE, READONLY
    ENTRY
    EXPORT Reset_Handler
NumA    DCD 12             
NumB    DCD 36
Reset_Handler
    LDR     R0, =NumA       
    LDR     R1, [R0]       
    LDR     R0, =NumB        
    LDR     R2, [R0]       
    MOV     R3, #1            
LCMLoop
    MUL     R4, R3, R1        
    MOV     R0, R4           
    MOV     R5, R2            
    CMP     R5, #0           
    BEQ     Found           
SubtractLoop
    CMP     R0, R5           
    BLT     CheckRemainder    
    SUB     R0, R0, R5       
    B       SubtractLoop          
CheckRemainder
    CMP     R0, #0          
    BEQ     Found            
    ADD     R3, R3, #1        
    B       LCMLoop              
Found
    LDR     R0, =Result       
    STR     R4, [R0]         
STOP B STOP                    
    AREA LCMData, DATA, READWRITE
Result  DCD 0                

    END