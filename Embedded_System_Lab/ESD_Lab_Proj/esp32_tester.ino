// Pins
const int pirPin = 13;      // PIR sensor output
const int ledPin = 2;       // ESP32 built-in LED
const int lpcSignalPin = 15; // Output pin to LPC1768

int motionCount = 0;
bool lastState = LOW;

void setup() {
  pinMode(pirPin, INPUT);
  pinMode(ledPin, OUTPUT);
  pinMode(lpcSignalPin, OUTPUT); // Set our new pin as an OUTPUT
  
  digitalWrite(lpcSignalPin, LOW); // Ensure it starts LOW
  
  Serial.begin(115200);
  Serial.println("PIR sensor test starting...");
}

void loop() {
  int currentState = digitalRead(pirPin);

  // Detect rising edge (motion just started)
  if (currentState == HIGH && lastState == LOW) {
    motionCount++;
    Serial.print("Motion event #");
    Serial.println(motionCount);
    
    digitalWrite(ledPin, HIGH);
    digitalWrite(lpcSignalPin, HIGH); // Send HIGH signal to LPC1768
  }

  // Turn off LED and signal if no motion
  if (currentState == LOW) {
    digitalWrite(ledPin, LOW);
    digitalWrite(lpcSignalPin, LOW); // Send LOW signal to LPC1768
  }

  lastState = currentState;
  delay(100); // small delay
}
