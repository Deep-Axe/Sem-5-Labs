#include <LPC17xx.h>

int main(void) {
    SystemInit();
    SystemCoreClockUpdate();

    LPC_GPIO0->FIODIR = (0x1 << 4); 
    LPC_GPIO2->FIODIR = (0x0 << 12);

    while (1) {
        if (LPC_GPIO2->FIOPIN & (1 << 12)) {  
            LPC_GPIO0->FIOCLR = (1 << 4);  
        } else {
            LPC_GPIO0->FIOSET = (1 << 4);  
        }
    }
    return 0;
}
