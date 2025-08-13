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
	LDR     R0, =NUM            
    LDRB    R1, [R0]              
    MOV     R3, R1, LSR #4 
    AND     R3, R3, #0x0F     

    CMP     R3, #9              
    BLE     UpperIsDigit         
    ADD     R3, R3, #7        

UpperIsDigit
    ADD     R3, R3, #0x30       
    AND     R2, R1, #0x0F        
    CMP     R2, #9               
    BLE     LowerIsDigit         
    ADD     R2, R2, #7           
			
LowerIsDigit
    ADD     R2, R2, #0x30        
    MOV     R3, R3, LSL #8       
    ORR     R3, R3, R2           
    LDR     R0, =RESULT           
    STRH    R3, [R0]            

STOP B STOP                    
NUM     DCB 0x3A                  
RESULT  DCB 0, 0    
    END                       

