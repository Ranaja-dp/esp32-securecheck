// Intentionally vulnerable demo. Never use these values on a real device.
#include <ArduinoOTA.h>
const char* wifi_password = "demo-secret-12345";
const char* endpoint = "http://example.com/api";
void setup() {
  Serial.begin(115200);
  Serial.println(wifi_password);
  // client.setInsecure(); // Uncomment to test TLS001.
  ArduinoOTA.begin();     // Configure OTA authentication.
}
