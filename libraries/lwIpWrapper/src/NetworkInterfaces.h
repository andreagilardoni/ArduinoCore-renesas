#pragma once

#include "lwip/include/lwip/dhcp.h"
#include "lwip/include/lwip/dns.h"
#include "lwip/include/lwip/init.h"
#include "lwip/include/lwip/ip_addr.h"
#include "lwip/include/lwip/opt.h"
#include "lwip/include/lwip/prot/dhcp.h"
#include "lwip/include/lwip/tcp.h"
#include "lwip/include/lwip/timeouts.h"
#include "lwip/include/lwip/udp.h"
#include "lwip/include/netif/ethernet.h"
#include <EthernetDriver.h>
#include "Arduino.h"

// #define CNETIF_STATS_ENABLED
#include "CNetifStats.h"

/*
 * The following class represent a generic network interface independently of the
 * Network engine that is working on top of.
 */
class NetworkInterface {
public:
    virtual ~NetworkInterface() {};
};

/*
 * This class represent a generic network stack present on top of a board.
 * This class is a singleton and provides all the necessary tools to send packets to the network
 * regardless of the interface we are interested on sending the packets to
 */
class NetworkStack {

};

#ifdef LWIP_DHCP
#define MAX_DHCP_TRIES 4
#define DHCP_CHECK_NONE (0)
#define DHCP_CHECK_RENEW_FAIL (1)
#define DHCP_CHECK_RENEW_OK (2)
#define DHCP_CHECK_REBIND_FAIL (3)
#define DHCP_CHECK_REBIND_OK (4)
typedef enum {
    DHCP_IDLE_STATUS,
    DHCP_START_STATUS,
    DHCP_WAIT_STATUS,
    DHCP_GOT_STATUS,
    DHCP_RELEASE_STATUS,
    DHCP_STOP_STATUS
} DhcpSt_t;
#endif
/*
 * This interface groups all the interfaces that are implemented through lwip network stack
 * this class provides utility functions to implement a generic lwip interface
 */
class LWIPNetworkInterface: public NetworkInterface {
public:
    LWIPNetworkInterface();
    virtual ~LWIPNetworkInterface();

    /*
     * The begin function is called by the user in the sketch to initialize the network interface
     * that he is planning on using in the sketch.
     */
     // FIXME we need to use arduino defined ip address structures
    virtual void begin(ip_addr_t *ip = nullptr, ip_addr_t *nm = nullptr, ip_addr_t *gw = nullptr); // FIXME set adequate default values

    /*
     * This method performs interface specific tasks (if any)
     */
    virtual void task();

#ifdef LWIP_DHCP
    bool DhcpIsStarted() { return dhcp_started; }
    void DhcpSetTimeout(unsigned long t);
    /* stops DHCP */
    void DhcpStop();
    /* tells DHCP is not used on that interface */
    void DhcpNotUsed();
    /* starts DHCP and tries to acquire addresses, return true if acquired, false otherwise */
    bool DhcpStart();
    /* tells if DHCP has acquired addresses or not */
    bool isDhcpAcquired();
    int checkLease();
#endif
protected:
    struct netif ni;
    ip_addr_t ip, nm, gw;

    /*
     * this function is used to initialize the netif structure of lwip
     */
    virtual err_t init(struct netif* ni) = 0;

    /*
     * This function is passed to lwip and used to send a buffer to the driver in order to transmit it
     */
    virtual err_t output(struct netif* ni, struct pbuf* p) = 0;

    // FIXME Driver interface pointer
    NetworkDriver *driver = nullptr;

    // the following functions are used to call init and output from lwip in the object context in the C code
    friend err_t _netif_init(struct netif* ni);
    friend err_t _netif_output(struct netif* ni, struct pbuf* p);

#ifdef LWIP_DHCP
    // DHCP related members
    unsigned long dhcp_last_time_call = 0;
    unsigned long dhcp_timeout;
    DhcpSt_t dhcp_st;
    bool dhcp_started;
    volatile bool dhcp_acquired;
    uint8_t _dhcp_lease_state;
    void dhcp_task();
    void dhcp_reset();
    bool dhcp_request();
    uint8_t dhcp_get_lease_state();
#endif

#ifdef CNETIF_STATS_ENABLED
public:
    netif_stats stats;
#endif
};


/*
 * This class represent the interface for LWIP that handles the on board ethernet interface on the
 * Portenta C33 board.
 * TODO change C33 with the board family name that supports eth
 */
class C33EthernetLWIPNetworkInterface: public LWIPNetworkInterface {
public:
    C33EthernetLWIPNetworkInterface();
    virtual ~C33EthernetLWIPNetworkInterface();

    virtual void begin(ip_addr_t *ip = nullptr, ip_addr_t *nm = nullptr, ip_addr_t *gw = nullptr) override;
    // virtual void task();
protected:
    static const char eth_ifname_prefix = 'e';
    static uint8_t eth_id;

    virtual err_t init(struct netif* ni) override;
    virtual err_t output(struct netif* ni, struct pbuf* p) override;

private:
    /*
     * This function is passed to the driver class and it is meant to
     * take a pointer to a buffer, and pass it to lwip to process it
     */
    void consume_callback(uint8_t* buffer, uint32_t len);
};

class WiFIStationLWIPNetworkInterface: public LWIPNetworkInterface {
public:
    // TODO add all the specific methods for wifi modules
    virtual const char* getSSID();
    virtual uint8_t* getBSSID(uint8_t* bssid);
    virtual int32_t getRSSI();
    virtual uint8_t getEncryptionType();
protected:
    static const char prefix = 'w';
    // static uint8_t id;

    virtual err_t init(struct netif* ni) override;
    virtual err_t output(struct netif* ni, struct pbuf* p) override;
};

class SoftAPLWIPNetworkInterface: public LWIPNetworkInterface {
protected:
    // FIXME understand the cpp way of setting this pointer
    static const char prefix = 's';
    // static uint8_t id = 0;

    virtual err_t init(struct netif* ni) override;
    virtual err_t output(struct netif* ni, struct pbuf* p) override;
};

class LWIPNetworkStack: public NetworkStack {
private:
    LWIPNetworkStack();
    virtual ~LWIPNetworkStack();
};