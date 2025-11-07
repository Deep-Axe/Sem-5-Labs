#include <LPC17xx.h>
#include <stdio.h>
#include "lcd_msg.h"   // use the header/file you provided

/*
  Updated lcd_test.c

  - When PIR (P0.15) detects motion, LCD asks "Which user?" with options:
      1. alice   2. bob   3. carol
  - User selects 1/2/3 via a 4x4 keypad wired to P0.4..P0.11.
    Rows: P0.4..P0.7  (outputs)
    Cols: P0.8..P0.11 (inputs)
  - After selection, user is prompted to enter a password (max 5 chars).
    Key mapping: characters chosen from "1234567890ABCDEF"
    Special keys:
      'D' -> submit/enter
      'E' -> backspace/delete
  - Passwords for alice, bob, carol defined as constants below.
    Edit these strings to set your own passwords (max 5 chars).
*/

#define PIR_PIN  (1U << 15) // P0.15 input

/* Keypad pin masks (P0.4..P0.11) */
#define KEY_ROW_SHIFT 4
#define KEY_COL_SHIFT 8
#define KEY_ROWS_MASK (0xF << KEY_ROW_SHIFT)  // P0.4..P0.7
#define KEY_COLS_MASK (0xF << KEY_COL_SHIFT)  // P0.8..P0.11

/* configurable passwords (user can change these) */
static const char *PWD_ALICE = "1A3F";  // example (max 5 chars)
static const char *PWD_BOB   = "BEEF";  // example
static const char *PWD_CAROL = "C0DE";  // example

/* helper prototypes from your lcd implementation (they use global temp1/temp2) */
extern unsigned long int temp1;
void lcd_init(void);
void lcd_com(void);
void delay_lcd(unsigned int);
void lcd_puts(unsigned char*);
void lcd_data(void);

/* small utility functions here */
static void lcd_set_cursor_first(void) {
    temp1 = 0x80;
    lcd_com();
    delay_lcd(80000);
}
static void lcd_set_cursor_second(void) {
    temp1 = 0xC0;
    lcd_com();
    delay_lcd(80000);
}
static void lcd_clear_display(void) {
    temp1 = 0x01;
    lcd_com();
    delay_lcd(200000);
}

/* mapping for keys: rows 0..3, cols 0..3 */
static const char keymap[4][4] = {
    { '1', '2', '3', 'A' },
    { '4', '5', '6', 'B' },
    { '7', '8', '9', 'C' },
    { 'E', '0', 'F', 'D' }  // E=backspace, D=enter/submit
};

/* small delay helper for debouncing */
static void small_delay(void) {
    delay_lcd(20000);
}

/* Initialize keypad pins as GPIO:
   rows P0.4..P0.7 = outputs (driven high idle),
   cols P0.8..P0.11 = inputs (with internal pull-ups assumed).
*/
static void keypad_init(void) {
    /* Be careful not to disturb LCD pin selections done by lcd_init.
       The original file set PINSEL0/PINSEL1 = 0 after lcd_init;
       we will keep that behavior so P0.4..P0.11 are GPIO (in PINSEL0). */
    LPC_PINCON->PINSEL0 = 0;    // P0.0..P0.15 = GPIO
    LPC_PINCON->PINSEL1 = 0;    // P0.16..P0.31 = GPIO (harmless here)

    /* Configure directions:
       rows: outputs
       cols: inputs
    */
    LPC_GPIO0->FIODIR |= KEY_ROWS_MASK;   // rows -> outputs
    LPC_GPIO0->FIODIR &= ~KEY_COLS_MASK;  // cols -> inputs

    /* drive all rows HIGH (idle state) */
    LPC_GPIO0->FIOSET = KEY_ROWS_MASK;

    /* PIR pin input */
    LPC_GPIO0->FIODIR &= ~PIR_PIN;
}

/* Scan keypad once; returns 0 if no key, or ASCII key char */
static char keypad_scan_once(void) {
    unsigned int row,col;
    unsigned int pin_read;
    char key = 0;

    /* Drive all rows high first */
    LPC_GPIO0->FIOSET = KEY_ROWS_MASK;
    small_delay();

    for (row = 0; row < 4; row++) {
        /* Drive only this row low, others high */
        LPC_GPIO0->FIOSET = KEY_ROWS_MASK;                        // set all rows
        LPC_GPIO0->FIOCLR = (1 << (KEY_ROW_SHIFT + row));         // clear current row -> low

        small_delay();

        /* read column pins */
        pin_read = LPC_GPIO0->FIOPIN & KEY_COLS_MASK;

        /* columns are active low; check each */
        for (col = 0; col < 4; col++) {
            if (!(pin_read & (1 << (KEY_COL_SHIFT + col)))) {
                key = keymap[row][col];
                /* simple debounce: wait until released */
                while (!(LPC_GPIO0->FIOPIN & (1 << (KEY_COL_SHIFT + col)))) {
                    delay_lcd(5000);
                }
                small_delay();
                return key;
            }
        }
    }

    return 0;
}

/* Blocking wait for a keypress; returns ASCII of key. */
static char keypad_wait_key(void) {
    char k = 0;
    while (1) {
        k = keypad_scan_once();
        if (k) return k;
        delay_lcd(30000);
    }
}

/* show selection menu after motion detected and return chosen user 1..3 or 0 for cancel */
static int choose_user(void) {
    char k;
    lcd_clear_display();
    lcd_set_cursor_first();
    lcd_puts((unsigned char *)"Which user?      "); // first line
    lcd_set_cursor_second();
    lcd_puts((unsigned char *)"1:alice 2:bob    ");
    delay_lcd(200000);

    while (1) {
        k = keypad_scan_once();
        if (k == '1' || k == '2' || k == '3') {
            return k - '0';
        }
        delay_lcd(30000);
    }
}

/* prompt and collect password up to maxlen. 'D' submits, 'E' deletes */
static int collect_password(char *buf, int maxlen) {
    int len = 0;
    int i;
    char k;
    lcd_clear_display();
    lcd_set_cursor_first();
    lcd_puts((unsigned char *)"Enter pwd:       ");
    lcd_set_cursor_second();

    /* show prompt second line empty */
    lcd_puts((unsigned char *)"                ");
    lcd_set_cursor_second();

    while (1) {
        k = keypad_wait_key();

        if (k == 'D') { // submit
            buf[len] = '\0';
            return len;
        }
        else if (k == 'E') { // backspace
            if (len > 0) {
                len--;
                buf[len] = '\0';
                /* update display */
                /* move cursor to second line start then print stars and pad */
                lcd_set_cursor_second();
                for (i = 0; i < len; i++) {
                    temp1 = '*';
                    lcd_data();
                    delay_lcd(10000);
                }
                /* clear remainder */
                for (i = len; i < 16; i++) {
                    temp1 = ' ';
                    lcd_data();
                    delay_lcd(5000);
                }
                /* place cursor after current stars */
                temp1 = 0xC0 + len;
                lcd_com();
            }
            continue;
        }
        else {
            /* accept only 0-9, A-F (as specified) */
            if ((k >= '0' && k <= '9') || (k >= 'A' && k <= 'F')) {
                if (len < maxlen) {
                    buf[len++] = k;
                    /* display '*' for each char */
                    temp1 = k;
                    lcd_data();
                    delay_lcd(10000);
                }
                /* if max reached, auto submit */
                if (len >= maxlen) {
                    buf[len] = '\0';
                    return len;
                }
            }
            /* ignore other keys */
        }
    }
}

/* compare entered password with stored */
static int check_password_for_user(int user, const char *entered) {
    const char *stored = 0;
    int i = 0;
    if (user == 1) stored = PWD_ALICE;
    else if (user == 2) stored = PWD_BOB;
    else if (user == 3) stored = PWD_CAROL;
    if (!stored) return 0;
    /* simple strcmp */
    while (stored[i] || entered[i]) {
        if (stored[i] != entered[i]) return 0;
        i++;
    }
    return 1;
}

int main(void)
{
    SystemInit();
    SystemCoreClockUpdate();

    /* Initialize LCD (this configures P0.23..P0.28 for the LCD) */
    lcd_init();

    /* configure keypad pins & PIR */
    keypad_init();

    /* Sanity check message */
    temp1 = 0x80;     // set cursor to first line
    lcd_com();
    delay_lcd(80000); // as used in your ADC reference
    lcd_puts((unsigned char *)"LCD OK          "); // padded to clear remainder
    delay_lcd(200000);

    while (1) {
        unsigned long x = LPC_GPIO0->FIOPIN & PIR_PIN;
        if (x) { // motion detected
            /* prompt for user selection */
            int user = choose_user();

            /* if user valid, collect password */
            if (user >= 1 && user <= 3) {
                char entered[8];
                int llen = collect_password(entered, 5); // max 5 chars

                lcd_clear_display();
                lcd_set_cursor_first();
                if (check_password_for_user(user, entered)) {
                    /* Success: show welcome on first line */
                    lcd_puts((unsigned char *)"Welcome!         ");
                } else {
                    /* Failure: show wrong password message */
                    lcd_puts((unsigned char *)"Wrong Password   ");
                }
                delay_lcd(400000);

                /* second line: show username on success, or hint on failure */
                lcd_set_cursor_second();
                if (check_password_for_user(user, entered)) {
                    if (user == 1) lcd_puts((unsigned char *)"User: alice      ");
                    else if (user == 2) lcd_puts((unsigned char *)"User: bob        ");
                    else if (user == 3) lcd_puts((unsigned char *)"User: carol      ");
                } else {
                    lcd_puts((unsigned char *)"Try again        ");
                }
                delay_lcd(400000);
            }
        } else {
            /* no motion: show idle status */
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
