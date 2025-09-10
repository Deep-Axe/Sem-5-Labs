#include <LPC17xx.h>
#include <stdio.h>
//johnson up down counter
int main(void) {
    int ctr = 0x0; 
    int j;
    SystemInit();
    SystemCoreClockUpdate();
    LPC_PINCON->PINSEL0 = 0x00000000;
    LPC_GPIO0->FIODIR = 0xF << 4; 
    LPC_PINCON->PINSEL4 &= ~(0x3 << 8); 
    LPC_GPIO2->FIODIR &= ~(0x1 << 4);   //input p2.4 as gpio input
    for (j = 0; j < 600000; j++);
    while (1) {
        int switch_state = (LPC_GPIO2->FIOPIN >> 4) & 0x1;
        if (switch_state) {

            int msb_inverted = (~(ctr >> 3)) & 0x1;
            ctr = (ctr << 1) | msb_inverted;
            ctr &= 0xF;
        } else {
            int lsb_inverted = (~ctr & 0x1) << 3;
            ctr = (ctr >> 1) | lsb_inverted;
            ctr &= 0xF;
        }
        LPC_GPIO0->FIOCLR = 0xF << 4; 
        LPC_GPIO0->FIOSET = ctr << 4;       
        for (j = 0; j < 600000; j++);
    }
    return 0;
}
