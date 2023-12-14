#include <Arduino.h>
#include <Arduino_DebugUtils.h>
#include <IRQManager.h>
#include <regex>
#include <utils.h>
#include "arduino_secrets.h"

#define CNETIF_STATS_ENABLED
#include <NetworkInterfaces.h>

#ifdef CNETIF_STATS_ENABLED
#define STATS_BUFFER_SIZE 1000
char cnetif_stats_buffer[STATS_BUFFER_SIZE];
// netif_stats _stats;
#endif // CNETIF_STATS_ENABLED

static char const SSID[] = SECRET_SSID;  /* your network SSID (name) */
static char const PASS[] = SECRET_PASS;  /* your network password (use for WPA, or use as key for WEP) */

WiFIStationLWIPNetworkInterface C33WifiIface;
uint64_t debug_start;

void setup() {
  int res = 0;
  Serial.begin(115200);
  while(!Serial);

  Serial.println("C33 wifi test");

  lwip_init(); // TODO move this inside the network stack init
  LWIPNetworkStack::getInstance(); // TODO make this automatic

  C33WifiIface.begin();

  Serial.println("Begin");
  res = C33WifiIface.connectToAP(SSID, SECRET_PASS);
  Serial.println(res);


  Serial.println("Scanning APs");
  res = C33WifiIface.scanForAp();
  Serial.println(res);


  Serial.println("Print APs");
  C33WifiIface.printAps();

  Serial.println("Begin");
  res = C33WifiIface.connectToAP(SSID, SECRET_PASS);
  Serial.println(res);

  debug_start = millis();
}

void loop() {

  if(millis() - debug_start > 3000) {
    if(C33WifiIface.isDhcpAcquired()) {

    }
#ifdef CNETIF_STATS_ENABLED
    netif_stats_sprintf(cnetif_stats_buffer, C33WifiIface.stats, STATS_BUFFER_SIZE, (8*1e6)/(1<<20), "Mbit/s");
    arduino::lock();
    NETIF_STATS_RESET_AVERAGES(C33WifiIface.stats);
    arduino::unlock();

    DEBUG_INFO(cnetif_stats_buffer);
#endif // CNETIF_STATS_ENABLED

    debug_start = millis();
  }
}