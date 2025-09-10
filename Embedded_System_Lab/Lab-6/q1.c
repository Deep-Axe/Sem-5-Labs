#include <LPC17xx.h>
#include <stdio.h>
//binary up counter

int main(void){
	int i,j;
	SystemInit();
	SystemCoreClockUpdate();
	LPC_PINCON->PINSEL0=0x0;
	LPC_GPIO0->FIODIR=0xFF<<4;
	while(1){
		for(i=0;i<256;i++){
			LPC_GPIO0->FIOPIN = (i<<4);
			for(j=0;j<600000;j++);
		}
	}
}
