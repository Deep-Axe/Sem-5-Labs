#include <LPC17xx.h>

#define ROW_MASK (0x000000F0) // P0.4–P0.7
#define COL_MASK (0x00000F00) // P0.8–P0.11

void pwm_init(void);
void keypad_init(void);
unsigned char keyscan(void);
void set_intensity(unsigned char key);
void delay_ms(unsigned int d);

int main(void)
{
    unsigned char key;

    SystemInit();
    SystemCoreClockUpdate();

    pwm_init();
    keypad_init();

    while (1)
    {
        key = keyscan();
        if (key != 0xFF) // valid key pressed
        {
            set_intensity(key);
            delay_ms(300); // debounce delay
        }
    }
}

/* ---------------- PWM Initialization ---------------- */
void pwm_init(void)
{
    LPC_SC->PCONP |= (1 << 6); // Power PWM1
    LPC_PINCON->PINSEL3 &= ~(0x0000C000);
    LPC_PINCON->PINSEL3 |= (0x00008000); // Select PWM1.4 (P1.23)

    LPC_PWM1->PR = 0x00000000;  // Count frequency = Fpclk
    LPC_PWM1->PCR = 0x00001000; // Enable PWM1.4 output (single edge)
    LPC_PWM1->MCR = 0x00000002; // Reset on MR0
    LPC_PWM1->MR0 = 30000;      // PWM period
    LPC_PWM1->MR4 = 3000;       // Initial duty = 10%
    LPC_PWM1->LER = 0xFF;       // Enable shadow latch

    LPC_PWM1->TCR = 0x02; // Reset counter
    LPC_PWM1->TCR = 0x09; // Enable PWM + counter
}

/* ---------------- Keypad Initialization ---------------- */
void keypad_init(void)
{
    LPC_PINCON->PINSEL0 &= ~((0xFFF) << 8); // P0.4–P0.11 as GPIO
    LPC_GPIO0->FIODIR |= ROW_MASK;          // Rows output
    LPC_GPIO0->FIODIR &= ~(COL_MASK);       // Columns input
}

/* ---------------- Key Scan Function ---------------- */
unsigned char keyscan(void)
{
    unsigned char row, col;
    unsigned long temp;

    const unsigned char keymap[4][4] = {
        {'1', '2', '3', 'A'},
        {'4', '5', '6', 'B'},
        {'7', '8', '9', 'C'},
        {'*', '0', '#', 'D'}};

    for (row = 0; row < 4; row++)
    {
        // Drive only one row high at a time
        LPC_GPIO0->FIOCLR = ROW_MASK;
        LPC_GPIO0->FIOSET = (1 << (4 + row));
        delay_ms(2); // small settle delay

        temp = LPC_GPIO0->FIOPIN & COL_MASK;

        if (temp)
        {
            // Determine which column was pressed
            for (col = 0; col < 4; col++)
            {
                if (temp & (1 << (8 + col)))
                {
                    while (LPC_GPIO0->FIOPIN & (1 << (8 + col)))
                        ; // wait for release
                    return keymap[row][col];
                }
            }
        }
    }
    return 0xFF; // no key pressed
}

/* ---------------- Set LED Intensity ---------------- */
void set_intensity(unsigned char key)
{
    switch (key)
    {
    case '0':
        LPC_PWM1->MR4 = 0.1 * LPC_PWM1->MR0;
        break;
    case '1':
        LPC_PWM1->MR4 = 0.2 * LPC_PWM1->MR0;
        break;
    case '2':
        LPC_PWM1->MR4 = 0.3 * LPC_PWM1->MR0;
        break;
    case '3':
        LPC_PWM1->MR4 = 0.4 * LPC_PWM1->MR0;
        break;
    case '4':
        LPC_PWM1->MR4 = 0.5 * LPC_PWM1->MR0;
        break;
    case '5':
        LPC_PWM1->MR4 = 0.6 * LPC_PWM1->MR0;
        break;
    case '6':
        LPC_PWM1->MR4 = 0.7 * LPC_PWM1->MR0;
        break;
    case '7':
        LPC_PWM1->MR4 = 0.8 * LPC_PWM1->MR0;
        break;
    case '8':
        LPC_PWM1->MR4 = 0.9 * LPC_PWM1->MR0;
        break;
    case '9':
        LPC_PWM1->MR4 = 1.0 * LPC_PWM1->MR0;
        break;
    case 'A':
        LPC_PWM1->MR4 = 0.25 * LPC_PWM1->MR0;
        break;
    case 'B':
        LPC_PWM1->MR4 = 0.5 * LPC_PWM1->MR0;
        break;
    case 'C':
        LPC_PWM1->MR4 = 0.75 * LPC_PWM1->MR0;
        break;
    case 'D':
        LPC_PWM1->MR4 = 0.9 * LPC_PWM1->MR0;
        break;
    default:
        return;
    }
    LPC_PWM1->LER = 0xFF; // Update PWM shadow latch
}

/* ---------------- Simple Delay ---------------- */
void delay_ms(unsigned int d)
{
    volatile unsigned int i, j;
    for (i = 0; i < d; i++)
        for (j = 0; j < 5000; j++)
            ;
}
