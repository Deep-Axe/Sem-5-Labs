#include <LPC17xx.h>

unsigned char seg[10] = {
    0x3F, // 0
    0x06, // 1
    0x5B, // 2
    0x4F, // 3
    0x66, // 4
    0x6D, // 5
    0x7D, // 6
    0x07, // 7
    0x7F, // 8
    0x6F  // 9
};

#define FIRST   0xF87FFFFF
#define SECOND  0xF8FFFFFF
#define THIRD   0xF97FFFFF
#define FOURTH  0xF9FFFFFF
#define OFF     0xFA7FFFFF

// crude delay
void delay_ms(int t) {
    int i, j;
    for(i=0;i<t;i++)
        for(j=0;j<10000;j++);
}

int main(void) {
    int num=0, dir=1, d[4], i, refresh;

    SystemInit();
    SystemCoreClockUpdate();

    LPC_PINCON->PINSEL0 &= 0xFF0000FF;
    LPC_GPIO0->FIODIR   |= 0x00000FF0;

    LPC_PINCON->PINSEL3 &= 0xFFC03FFF;
    LPC_GPIO1->FIODIR   |= 0x07800000;

    LPC_PINCON->PINSEL1 &= ~(3<<10);   
    LPC_GPIO0->FIODIR   &= ~(1<<21);   

    while(1) {
        d[0] = num % 10;
        d[1] = (num/10) % 10;
        d[2] = (num/100) % 10;
        d[3] = (num/1000) % 10;

        for(refresh=0; refresh<200; refresh++) {
            for(i=0;i<4;i++) {
                LPC_GPIO1->FIOPIN = (i==0?FIRST : i==1?SECOND : i==2?THIRD : FOURTH);

                LPC_GPIO0->FIOCLR = 0x00000FF0;        
                LPC_GPIO0->FIOSET = seg[d[i]] << 4;     

                delay_ms(1); 

                LPC_GPIO1->FIOPIN = OFF; 
            }
        }

        if((LPC_GPIO0->FIOPIN & (1<<21)) == 0)
            dir = -1;   
        else
            dir = 1;    
        if(dir == 1) {
            num++;
            if(num > 9999) num = 0;
        } else {
            if(num == 0) num = 9999;
            else num--;
        }
    }
}
