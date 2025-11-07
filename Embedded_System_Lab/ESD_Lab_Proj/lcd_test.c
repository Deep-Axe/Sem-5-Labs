
#include <LPC17xx.h>
#include <stdio.h>
#include "lcd_msg.h"    // use the provided LCD routines (lcd_init, lcd_puts, lcd_com, etc.)

#define PIR_PIN  (1 << 15)      // P0.15 (PIR input)
#define ADC_CHANNEL 0
#define TEMP_THRESHOLD 30  // corresponds to ~30°C
#define TEMP_ADJUST 50
#define BYPASS_PIR 0
#define BYPASS_PIR_VALUE 0

void ADC_Init(void);
uint16_t ADC_Read(void);
void delay_ms(uint32_t ms);

char msg_on1[]  = "INTRUSION: ";
char msg_values[20];
char msg_off1[] = "DETECTING: ";

unsigned int i;

int main(void)
{
		int sumTemp = 0;
		int tickrate=0;
    int ifDetectedPIR=0;
	  int ifDetectedTEMP=0;
		uint16_t adc_value=0;
		int temperature_c=0;
	
    SystemInit();
    SystemCoreClockUpdate();

    // Configure pins
    LPC_PINCON->PINSEL0 = 0;   // P0.0–P0.15 as GPIO
    LPC_PINCON->PINSEL1 = 0;
	// PIR input
	LPC_GPIO0->FIODIR &= ~PIR_PIN;  // PIR input

	// Initialize LCD (use lcd_msg.h implementation)
	lcd_init();

	ADC_Init();

	// Initial message on LCD (first line)
	lcd_puts((unsigned char*)msg_off1);

    // Main loop
    while (1)
    {
				sumTemp = 0;
				tickrate = 0;
			  while(tickrate<5){
				  	adc_value = ADC_Read();
					sumTemp = ((adc_value / 4095.0f) * 330.0f)- TEMP_ADJUST; // Vref is 3.3, so 3.3 * 100 = 330
					delay_ms(1000);
				  	tickrate +=1;
				}
				temperature_c = sumTemp/5;
				if(temperature_c > TEMP_THRESHOLD){
					ifDetectedTEMP = 1;
				}
				else{
					ifDetectedTEMP = 0;
				}
        ifDetectedPIR = (LPC_GPIO0->FIOPIN & PIR_PIN) ? 1 : 0; // Normalize to 0 or 1
				if(BYPASS_PIR){
						ifDetectedPIR = BYPASS_PIR_VALUE;
				}
        if (ifDetectedTEMP & ifDetectedPIR) // Motion detected
        {

      // Update LCD: INTRUSION
      temp1 = 0x80; lcd_com();
      lcd_puts((unsigned char*)msg_on1);

      temp1 = 0xC0; lcd_com();
      sprintf(msg_values,"TEMP %d PIR %d",temperature_c,ifDetectedPIR);
      lcd_puts((unsigned char*)msg_values);
      delay_lcd(50000);
      delay_ms(10000);
						
        }
        else // No motion
        {
            // Update LCD: DETECTING << values
      temp1 = 0x80; lcd_com();
      lcd_puts((unsigned char*)msg_off1);

      temp1 = 0xC0; lcd_com();
      sprintf(msg_values,"TEMP %d PIR %d",temperature_c,ifDetectedPIR);
      lcd_puts((unsigned char*)msg_values);
        }
        delay_lcd(50000);
    }
		
}


void ADC_Init(void) {
    LPC_PINCON->PINSEL1 &= ~(3 << 14);
    LPC_PINCON->PINSEL1 |=  (1 << 14);   
    LPC_SC->PCONP |= (1 << 12);          
    LPC_ADC->ADCR = (1 << ADC_CHANNEL) | 
                    (4 << 8) |           
                    (1 << 21);           
}

uint16_t ADC_Read(void) {
		uint16_t result;
    LPC_ADC->ADCR |= (1 << 24);          
    while ((LPC_ADC->ADGDR & (1U << 31)) == 0); 
    result = (LPC_ADC->ADGDR >> 4) & 0xFFF; 
    return result;
}

void delay_ms(uint32_t ms) {
    uint32_t i, j;
    for (i = 0; i < ms; i++)
        for (j = 0; j < 5000; j++);
}

