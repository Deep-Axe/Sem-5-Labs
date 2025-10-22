// Pins
const int pirPin = 13;    // PIR sensor output
const int ledPin = 2;     // ESP32 built-in LED

int motionCount = 0;
bool lastState = LOW;

void setup() {
  pinMode(pirPin, INPUT);
  pinMode(ledPin, OUTPUT);
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
  }

  // Turn off LED if no motion
  if (currentState == LOW) {
    digitalWrite(ledPin, LOW);
  }

  lastState = currentState;
  delay(100); // small delay
}
