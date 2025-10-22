#include <LPC17xx.h>

int main(void) {
    SystemInit();
    SystemCoreClockUpdate();

    // === Configure P0.4 as output (for an LED) ===
    // (This is the same as your Johnson counter code)
    LPC_PINCON->PINSEL0 &= ~(0x3 << 8);  // Set P0.4 to GPIO function
    LPC_GPIO0->FIODIR |= (0x1 << 4);    // Set P0.4 as output

    // === Configure P2.1 as input (from ESP32) ===
    // (This is the MODIFIED part)
    LPC_PINCON->PINSEL4 &= ~(0x3 << 2);  // Set P2.1 to GPIO function (bits 3:2)
    LPC_GPIO2->FIODIR &= ~(0x1 << 1);    // Set P2.1 as input (bit 1)

    // Clear the LED initially
    LPC_GPIO0->FIOCLR = (0x1 << 4);

    while (1) {
        // Read the input signal from the ESP32 on P2.1
        int motion_signal = (LPC_GPIO2->FIOPIN >> 1) & 0x1;

        if (motion_signal) {
            // Motion detected: Turn LED ON
            LPC_GPIO0->FIOSET = (0x1 << 4);
        } else {
            // No motion: Turn LED OFF
            LPC_GPIO0->FIOCLR = (0x1 << 4);
        }
    }
    // return 0; // Unreachable
}
