#include <M5AtomS3.h>
#include "P105Control.h"
#include "ArduinoJson.h"
#define GPIO_BUTTON 41

// Please modify login information
P105Control p105(IPAddress(192,168,xxx,xxx), "username@mail.com", "password");

volatile bool g_irq0 = false;
void setIRQ0() {
  g_irq0 = true;
}

void setup() {
  M5.begin(false, true, false, true); // Enable Serial and RGB LED
  M5.dis.clear();
  M5.dis.show();

  WiFi.begin("ssid", "password");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  USBSerial.print("WiFi connected\r\n");
 
  pinMode(GPIO_BUTTON, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(GPIO_BUTTON), setIRQ0, FALLING);
}
 
void loop() {
  if(!g_irq0){
    return;
  }
  M5.dis.drawpix(CRGB::Aqua);
  M5.dis.show();

  if(!p105.HasActiveSession()){
    p105.Handshake();
    p105.Login();
  }

  auto info = p105.GetDeviceInfo();

  DynamicJsonDocument doc(2048);
  deserializeJson(doc, info);
  bool state = doc["result"]["device_on"];

  p105.SetDeviceState(!state);

  delay(100);
  M5.dis.clear();
  M5.dis.show();
  g_irq0 = false;
}