#include <EthernetDriver.h>
#include <NetworkInterfaces.h>
#include <Arduino_DebugUtils.h>

EthernetC33Driver C33EthernetDriver(2, 2, mem_malloc, 1536);
C33EthernetLWIPNetworkInterface C33EthernetIface;

void application();
extern "C" void sys_printf(const char *format, ...);

#define BLOCKING_DNS_RESOLUTION

void setup() {
    Serial.begin(115200);
    while(!Serial);

    lwip_init();

    DEBUG_INFO("Setting up driver");
    C33EthernetDriver.begin();

    DEBUG_INFO("Setting up netif");
    C33EthernetIface.begin();

    delay(100);
}

void loop() {
    LWIPNetworkStack::getInstance().task();

    application();
}

// application stuff
volatile uint8_t state = 0;
uint32_t counter = 0;

char* domains[] = {
    "google.it"
    , "andreagilardoni.com"
    , "a.andreagilardoni.com"
    , "b.andreagilardoni.com"
    , "c.andreagilardoni.com"
    , "d.andreagilardoni.com"
    , "e.andreagilardoni.com"
    , "f.andreagilardoni.com"
    , "g.andreagilardoni.com"
    , "h.andreagilardoni.com"
    , "i.andreagilardoni.com"
    , "j.andreagilardoni.com"
    , "k.andreagilardoni.com"
    , "j.andreagilardoni.com"
    , "l.andreagilardoni.com"
    , "m.andreagilardoni.com"
    , "n.andreagilardoni.com"
    , "www.google.com"
    , "arduino.cc"
    , "oniudra.cc"
    , "youtube.it"
    , "youtube.com"
    , "github.com"
    , "drive.google.com"
};

#ifndef BLOCKING_DNS_RESOLUTION
void dns_cbk(const IPAddress& ip) {
    DEBUG_INFO("DNS request completed %d: %s", counter, ip.toString().c_str());
    state = 1;
    counter++;
}
#endif // BLOCKING_DNS_RESOLUTION

void application() {

    switch(state) {
    case 0:
        if(C33EthernetIface.isDhcpAcquired()) {
            DEBUG_INFO("dhcp acquired");

            state = 1;
        }
        break;
    case 1: {
#ifdef BLOCKING_DNS_RESOLUTION
        IPAddress ip;

        auto res = LWIPNetworkStack::getInstance().getHostByName(
            domains[counter % (sizeof(domains)/sizeof(char*))],
            ip,
            true);

        counter++;
        DEBUG_INFO("DNS %u request performed for %s: %u %s ",
            counter,
            domains[counter % (sizeof(domains)/sizeof(char*))],
            res,
            ip.toString().c_str());
#else
        state = 2;
        auto res = LWIPNetworkStack::getInstance().getHostByName(
            domains[counter % (sizeof(domains)/sizeof(char*))],
            dns_cbk);

        if(res != 1) {
            counter++;
        }
        DEBUG_INFO("DNS request performed for %s: %u", domains[counter % (sizeof(domains)/sizeof(char*))], res);
#endif // BLOCKING_DNS_RESOLUTION
        break;
    }
    case 2:
        // do nothing, request made, wait for request to complete
        break;
    }

}

void sys_printf(const char *format, ...) {
    static char debug_buf[1024];
    va_list argptr;
    va_start(argptr, format);
    vsprintf(debug_buf, format, argptr);
    va_end(argptr);
    Serial.print(debug_buf);
}
