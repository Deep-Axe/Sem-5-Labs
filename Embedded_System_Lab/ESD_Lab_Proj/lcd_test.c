#include <LPC17xx.h>
#include "lcd_msg.h"   // use the header/file you provided

#define PIR_PIN  (1U << 15) // P0.15 input

unsigned long x;

int main(void)
{
    SystemInit();
    SystemCoreClockUpdate();

    /* Initialize LCD (this configures P0.23..P0.28 for the LCD) */
    lcd_init();

    /* Ensure P0.15 is GPIO input (do not touch LCD pinselects done by lcd_init) */
    LPC_PINCON->PINSEL0 = 0;    // P0.0..P0.15 = GPIO (clearing ensures P0.15 is GPIO)
    LPC_PINCON->PINSEL1 = 0;    // P0.16..P0.31 = GPIO (harmless here)
    LPC_GPIO0->FIODIR &= ~PIR_PIN;  // PIR as input

    /* Sanity check message (use the delays from the ADC example you shared) */
    temp1 = 0x80;     // set cursor to first line
    lcd_com();
    delay_lcd(80000); // as used in your ADC reference
    lcd_puts((unsigned char *)"LCD OK          "); // padded to clear remainder
    delay_lcd(200000);

    /* Main loop — only PIR & LCD, no LED functionality */
    while (1)
    {
        x = LPC_GPIO0->FIOPIN & PIR_PIN;
        if (x) // motion detected
        {
            /* Write two full 16-character lines (padded) to avoid leftover garbage */
            temp1 = 0x80; // first line
            lcd_com();
            delay_lcd(80000);
            lcd_puts((unsigned char *)"PIR: MOTION     ");

            temp1 = 0xC0; // second line
            lcd_com();
            delay_lcd(80000);
            lcd_puts((unsigned char *)"OBJECT: YES     ");
        }
        else // no motion
        {
            temp1 = 0x80; // first line
            lcd_com();
            delay_lcd(80000);
            lcd_puts((unsigned char *)"PIR: NO MOTION  ");

            temp1 = 0xC0; // second line
            lcd_com();
            delay_lcd(80000);
            lcd_puts((unsigned char *)"OBJECT: NO      ");
        }

        /* small pause between reads */
        delay_lcd(50000);
    }

    return 0;
}
