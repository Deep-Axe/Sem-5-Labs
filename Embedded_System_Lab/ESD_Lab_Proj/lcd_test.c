#include <LPC17xx.h>
#include "lcd_msg.h"   // the header you provided (contains lcd_init, lcd_puts, lcd_com, clr_disp, delay_lcd, etc.)

#define PIR_PIN  (1U << 15) // P0.15
#define LED_PIN  (1U << 5)  // P0.5

unsigned long x;

int main(void)
{
    SystemInit();
    SystemCoreClockUpdate();

    /* Ensure P0.15 is GPIO input and P0.5 is GPIO output.
       lcd_init() configures P0.23-P0.28 for the LCD, so we only touch PIR and LED here. */
    LPC_PINCON->PINSEL0 = 0;    // clear PINSEL0 (P0.0..P0.15) - safe default
    LPC_PINCON->PINSEL1 = 0;    // clear PINSEL1 (P0.16..P0.31) - ensure P0.15 is GPIO

    LPC_GPIO0->FIODIR |= LED_PIN;   // LED as output
    LPC_GPIO0->FIODIR &= ~PIR_PIN;  // PIR as input
    LPC_GPIO0->FIOCLR = LED_PIN;    // LED off

    // Initialize the LCD (from your lcd_msg.h implementation)
    lcd_init();

    // Simple sanity check: display a normal message first so you can confirm LCD works
    temp1 = 0x80;     // first line
    lcd_com();
    delay_lcd(80000);
    lcd_puts((unsigned char *)"LCD OK");   // short message to verify LCD

    delay_lcd(200000); // leave message on screen for a short while

    // Now enter PIR loop — show status on LCD and toggle LED
    while (1)
    {
        x = LPC_GPIO0->FIOPIN & PIR_PIN;
        if (x) // motion detected
        {
            LPC_GPIO0->FIOSET = LED_PIN;

            // Update LCD: LED ON / OBJECT YES
            // Clear display first to avoid leftover characters
            clr_disp();
            delay_lcd(20000);

            temp1 = 0x80; // first line
            lcd_com();
            delay_lcd(2000);
            lcd_puts((unsigned char *)"LED:ON ");

            temp1 = 0xC0; // second line
            lcd_com();
            delay_lcd(2000);
            lcd_puts((unsigned char *)"OBJECT:YES");
        }
        else // no motion
        {
            LPC_GPIO0->FIOCLR = LED_PIN;

            // Update LCD: LED OFF / OBJECT NO
            clr_disp();
            delay_lcd(20000);

            temp1 = 0x80; // first line
            lcd_com();
            delay_lcd(2000);
            lcd_puts((unsigned char *)"LED:OFF");

            temp1 = 0xC0; // second line
            lcd_com();
            delay_lcd(2000);
            lcd_puts((unsigned char *)"OBJECT:NO ");
        }

        delay_lcd(50000);
    }

    // not reached
    return 0;
}
