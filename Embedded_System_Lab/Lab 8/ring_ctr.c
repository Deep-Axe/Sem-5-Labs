#include <LPC17xx.h>

unsigned char seg[10] = {
    0x3F, 
    0x06,
    0x5B, 
    0x4F, 
    0x66, 
    0x6D, 
    0x7D, 
    0x07, 
    0x7F, 
    0x6F  
};

#define FIRST   0xF87FFFFF
#define SECOND  0xF8FFFFFF
#define THIRD   0xF97FFFFF
#define FOURTH  0xF9FFFFFF
#define OFF     0xFA7FFFFF

void delay_ms(int t) {
    int i, j;
    for(i=0;i<t;i++)
        for(j=0;j<10000;j++);
}

int main(void) {
    int pos = 0;   

    SystemInit();
    SystemCoreClockUpdate();

    LPC_PINCON->PINSEL0 &= 0xFF0000FF;
    LPC_GPIO0->FIODIR   |= 0x00000FF0;

    LPC_PINCON->PINSEL3 &= 0xFFC03FFF;
    LPC_GPIO1->FIODIR   |= 0x07800000;

    while(1) {
        LPC_GPIO1->FIOPIN = OFF;

        switch(pos) {
            case 0: LPC_GPIO1->FIOPIN = FIRST;  break;
            case 1: LPC_GPIO1->FIOPIN = SECOND; break;
            case 2: LPC_GPIO1->FIOPIN = THIRD;  break;
            case 3: LPC_GPIO1->FIOPIN = FOURTH; break;
        }

        LPC_GPIO0->FIOCLR = 0x00000FF0;        
        LPC_GPIO0->FIOSET = seg[1] << 4;   

        delay_ms(500);   

        pos = (pos + 1) % 4;
    }
}
