#include <LPC17xx.h>
#include <stdio.h>
//NXP-LPC1768 microcontroller Arm Cortex m3 board
int main(void){
	int i;
	SystemInit();
	SystemCoreClockUpdate();
	LPC_PINCON->PINSEL0=0x0;
	LPC_GPIO0->FIODIR=0x1<<4;
	while(1){
		LPC_GPIO0->FIOSET=0x1<<4;
		for(i = 0;i<10000;i++);
		LPC_GPIO0->FIOCLR=0x1<<4;
		for(i = 0;i<10000;i++);
	}
}
//code to blink led
