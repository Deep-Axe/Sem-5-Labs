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

    LDR R0, =hex_input      
    LDR R1, [R0]           
    
    MOV R2, #10            
    UDIV R3, R1, R2        
    MUL R4, R3, R2         
    SUB R4, R1, R4          
    
    LDR R0, =bcd_res       
    STRB R3, [R0]         
    STRB R4, [R0, #1]     

hex_input DCD 0x27       
bcd_res DCB 0x0, 0x0     

STOP B STOP               



    END