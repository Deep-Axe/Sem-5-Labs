#include <LPC17xx.h>

#define ROW_MASK  (0x000000F0)   // P0.4–P0.7
#define COL_MASK  (0x00000F00)   // P0.8–P0.11

void pwm_init(void);
void keypad_init(void);
unsigned char keyscan(void);
void set_intensity(unsigned char key);

int main(void)
{
    unsigned char key;
		volatile int d;

    SystemInit();
    SystemCoreClockUpdate();

    pwm_init();
    keypad_init();

    while(1)
    {
        key = keyscan();       // Read key
        if(key != 0xFF)        // Valid key pressed
        {
            set_intensity(key);
            for(d=0; d<1000000; d++); // simple delay
        }
    }
}

/* ---------------- PWM Initialization ---------------- */
void pwm_init(void)
{
    LPC_SC->PCONP |= (1<<6);           // Power PWM1
    LPC_PINCON->PINSEL3 &= ~(0x0000C000); 
    LPC_PINCON->PINSEL3 |=  (0x00008000); // Select PWM1.4 (P1.23)
    
    LPC_PWM1->PR  = 0x00000000;         // Count frequency = Fpclk
    LPC_PWM1->PCR = 0x00001000;         // PWM1 single-edge mode
    LPC_PWM1->MCR = 0x00000002;         // Reset on MR0
    LPC_PWM1->MR0 = 30000;              // PWM period

    LPC_PWM1->MR4 = 3000;               // Initial duty = 10%
    LPC_PWM1->LER = 0xFF;               // Enable shadow latch

    LPC_PWM1->TCR = 0x02;               // Reset counter
    LPC_PWM1->TCR = 0x09;               // Enable PWM + counter
}

/* ---------------- Keypad Initialization ---------------- */
void keypad_init(void)
{
    LPC_PINCON->PINSEL0 &= ~((0x3FF) << 8); // P0.4–P0.11 as GPIO
    LPC_GPIO0->FIODIR |= ROW_MASK;          // Rows output
    LPC_GPIO0->FIODIR &= ~(COL_MASK);       // Columns input
}

/* ---------------- Key Scan Function ----------------
   Only Row-0 is used (P0.4)
   Keys: 0, 1, 2, 3 (columns P0.8–P0.11)
---------------------------------------------------- */
unsigned char keyscan(void)
{
    unsigned long temp;
    unsigned char key = 0xFF;

    // Drive Row-0 (P0.4) high, others low
    LPC_GPIO0->FIOCLR = ROW_MASK;
    LPC_GPIO0->FIOSET = (1 << 4);

    temp = LPC_GPIO0->FIOPIN & COL_MASK;

    if(temp & (1 << 8))  key = '0';  // Col0 ? P0.8
    else if(temp & (1 << 9))  key = '1'; // Col1 ? P0.9
    else if(temp & (1 << 10)) key = '2'; // Col2 ? P0.10
    else if(temp & (1 << 11)) key = '3'; // Col3 ? P0.11

    return key;
}

/* ---------------- Set LED Intensity ---------------- */
void set_intensity(unsigned char key)
{
    switch(key)
    {
        case '0': LPC_PWM1->MR4 = 0.1 * LPC_PWM1->MR0; break; // 10%
        case '1': LPC_PWM1->MR4 = 0.25 * LPC_PWM1->MR0; break; // 25%
        case '2': LPC_PWM1->MR4 = 0.5 * LPC_PWM1->MR0; break; // 50%
        case '3': LPC_PWM1->MR4 = 0.75 * LPC_PWM1->MR0; break; // 75%
        default: return;
    }
    LPC_PWM1->LER = 0xFF; // Update PWM shadow latch
}
