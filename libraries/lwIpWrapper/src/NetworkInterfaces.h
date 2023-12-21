#pragma once
#include <Arduino.h>
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
#include "CCtrlWrapper.h"
#include "CEspControl.h"

// #define CNETIF_STATS_ENABLED
#include "CNetifStats.h"


#define NETWORKSTACK_USE_TIMER

#ifdef NETWORKSTACK_USE_TIMER
#include <FspTimer.h>
#endif // NETWORKSTACK_USE_TIMER

void* buffer_allocator(unsigned int size);

//forward declarations
class LWIPNetworkStack;

/*
 * The following class represent a generic network interface independently of the
 * Network engine that is working on top of.
 */
class NetworkInterface {
public:
    virtual ~NetworkInterface() {};
    virtual void begin(const IPAddress &ip = INADDR_NONE, const IPAddress &nm = INADDR_NONE, const IPAddress &gw = INADDR_NONE) = 0;
    virtual void task() = 0;
    virtual void up() = 0;
    virtual void down() = 0;
};

/*
 * This class represent a generic network stack present on top of a board.
 * This class is a singleton and provides all the necessary tools to send packets to the network
 * regardless of the interface we are interested on sending the packets to
 */
class NetworkStack {
    int getHostByName(const char* aHostname, IPAddress& aResult);
};

/*
 * This interface groups all the interfaces that are implemented through lwip network stack
 * this class provides utility functions to implement a generic lwip interface
 */
class LWIPNetworkInterface: public NetworkInterface {
public:
    LWIPNetworkInterface();

    /*
     * The begin function is called by the user in the sketch to initialize the network interface
     * that he is planning on using in the sketch.
     */
    virtual void begin(const IPAddress &ip = INADDR_NONE, const IPAddress &nm = INADDR_NONE, const IPAddress &gw = INADDR_NONE);

    /*
     * This method performs interface specific tasks (if any)
     */
    virtual void task();

    virtual void up();
    virtual void down();

#ifdef LWIP_DHCP
    // starts DHCP and tries to acquire addresses, return true if request was made successfully (ususally memory issues)
    bool dhcpStart();
    // stops DHCP
    void dhcpStop();
    // tells DHCP server that the interface uses a statically provided ip address
    void dhcpNotUsed();
    // force DHCP renewal, returns false on error (ususally memory issues)
    bool dhcpRenew();
    // force DHCP release, usually called before dhcp stop (ususally memory issues)
    bool dhcpRelease();
    // tells if DHCP has acquired addresses or not
    bool isDhcpAcquired();
#endif
protected:
    friend class LWIPNetworkStack;
    struct netif ni;

    /*
     * this function is used to initialize the netif structure of lwip
     */
    virtual err_t init(struct netif* ni) = 0;

    /*
     * This function is passed to lwip and used to send a buffer to the driver in order to transmit it
     */
    virtual err_t output(struct netif* ni, struct pbuf* p) = 0;

    // the following functions are used to call init and output from lwip in the object context in the C code
    friend err_t _netif_init(struct netif* ni);
    friend err_t _netif_output(struct netif* ni, struct pbuf* p);

    // Driver interface pointer
    NetworkDriver *driver = nullptr;

    // Callbacks for driver basic functions
    void linkUpCallback();
    void linkDownCallback();

#ifdef LWIP_DHCP
    // DHCP related members
    volatile bool dhcp_acquired;
#endif

#ifdef CNETIF_STATS_ENABLED
public:
    netif_stats stats; // FIXME decide how to handle this
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

    virtual void begin(const IPAddress &ip = INADDR_NONE, const IPAddress &nm = INADDR_NONE, const IPAddress &gw = INADDR_NONE) override;
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

typedef enum {
    WL_NO_SHIELD = 255,
    WL_NO_MODULE = WL_NO_SHIELD,
    WL_IDLE_STATUS = 0,
    WL_NO_SSID_AVAIL,
    WL_SCAN_COMPLETED,
    WL_CONNECTED,
    WL_CONNECT_FAILED,
    WL_CONNECTION_LOST,
    WL_DISCONNECTED,
    WL_AP_LISTENING,
    WL_AP_CONNECTED,
    WL_AP_FAILED
} WifiStatus_t;

/* Encryption modes */
enum wl_enc_type {
    ENC_TYPE_WEP,
    ENC_TYPE_WPA,
    ENC_TYPE_WPA2,
    ENC_TYPE_WPA2_ENTERPRISE,
    ENC_TYPE_WPA3,
    ENC_TYPE_NONE,
    ENC_TYPE_AUTO,

    ENC_TYPE_UNKNOWN = 255
};

// TODO there should be an intermediate interface class for wifi based devices
class WiFIStationLWIPNetworkInterface: public LWIPNetworkInterface {
public:
    WiFIStationLWIPNetworkInterface();

    int begin();
    int connectToAP(const char* ssid, const char *passphrase=nullptr);
    int disconnectFromAp();
    void init();

    virtual const char* getSSID();
    virtual uint8_t* getBSSID(uint8_t* bssid);
    virtual int32_t getRSSI();
    virtual uint8_t getEncryptionType();

    int scanForAp();
    void printAps();

    void task() override;
protected:
    static const char wifistation_ifname_prefix = 'w';
    static uint8_t wifistation_id;

    virtual err_t init(struct netif* ni) override;
    virtual err_t output(struct netif* ni, struct pbuf* p) override;

private:
    /*
     * This function is passed to the driver class and it is meant to
     * take a pointer to a buffer, and pass it to lwip to process it
     */
    void consume_callback(uint8_t* buffer, uint32_t len);

    WifiApCfg_t access_point_cfg;
    std::vector<AccessPoint_t> access_points;
    bool hw_init; // TODO this should be moved to the wifi driver class
};

class SoftAPLWIPNetworkInterface: public LWIPNetworkInterface {
public:
    // TODO add all the specific methods for wifi modules
    virtual const char* getSSID();
    virtual uint8_t* getBSSID(uint8_t* bssid);
    virtual int32_t getRSSI();
    virtual uint8_t getEncryptionType();
protected:
    // FIXME understand the cpp way of setting this pointer
    static const char prefix = 's';
    // static uint8_t id = 0;

    virtual err_t init(struct netif* ni) override;
    virtual err_t output(struct netif* ni, struct pbuf* p) override;
};


class LWIPNetworkStack: public NetworkStack {
public:
    LWIPNetworkStack(LWIPNetworkStack const&) = delete;
    void operator=(LWIPNetworkStack const&) = delete;


    static LWIPNetworkStack& getInstance() {
        //FIXME this doesn't to seem good
        static LWIPNetworkStack instance; // this is private in case we need to synch the access to the singleton
        return instance;
    }

    // run polling tasks from all the LWIP Network Interfaces
    // this needs to be called in the loop() if we are not running it
    // with a timer
    void task();

    // Function that provides a Client of the correct kind given the protocol provided in url
    // Client* connect(std::string url);
    // void request(std::string url, std::function<void(uint8_t*, size_t)>);

    // function for setting an iface as default
    void setDefaultIface(LWIPNetworkInterface* iface);

    // functions that handle DNS resolution
    // DNS servers are also set by dhcp
#if LWIP_DNS
    // add a dns server, priority set to 0 means it is the first being queryed, -1 means the last
    uint8_t addDnsServer(const IPAddress& aDNSServer, int8_t priority=-1);
    void clearDnsServers();

    // DNS resolution works with a callback if the resolution doesn't return immediately
    int getHostByName(const char* aHostname, IPAddress& aResult, bool execute_task=false); // blocking call
    int getHostByName(const char* aHostname, std::function<void(const IPAddress&)> cbk); // callback version
#endif
private:
    LWIPNetworkStack();

    // TODO define a Timer for calling tasks

    std::vector<LWIPNetworkInterface*> ifaces;

    virtual void add_iface(LWIPNetworkInterface* iface);
    // virtual void del_iface(LWIPNetworkInterface* iface);

    // lwip stores the netif in a linked list called: netif_list

    friend class LWIPNetworkInterface;

#ifdef NETWORKSTACK_USE_TIMER
    FspTimer timer;
#endif
};
