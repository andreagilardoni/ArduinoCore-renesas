#include "NetworkInterfaces.h"
#include <functional>
#include "utils.h"

err_t _netif_init(struct netif* ni);
err_t _netif_output(struct netif* ni, struct pbuf* p);

// Custom Pbuf definition used to handle RX zero copy
// TODO make better documentation on how this works

typedef struct zerocopy_pbuf {
    struct pbuf_custom p;
    uint8_t* buffer;
} zerocopy_pbuf_t;

static void zerocopy_pbuf_free(struct pbuf *p) {
    // SYS_ARCH_DECL_PROTECT(zerocopy_pbuf_free);
    zerocopy_pbuf_t* zcpbuf = (zerocopy_pbuf_t*) p;

    // SYS_ARCH_PROTECT(zerocopy_pbuf_free);

    // FIXME pbufs may be allocated in a different memory pool, deallocate them accordingly
    mem_free(zcpbuf->buffer);
    zcpbuf->buffer = nullptr;
    mem_free(zcpbuf); // TODO understand if pbuf_free deletes the pbuf
    // SYS_ARCH_UNPROTECT(zerocopy_pbuf_free);
}

static inline zerocopy_pbuf_t* get_zerocopy_pbuf(uint8_t *buffer) {
    zerocopy_pbuf_t* p = (zerocopy_pbuf_t*)mem_malloc(sizeof(zerocopy_pbuf_t));
    p->buffer = buffer;
    p->p.custom_free_function = zerocopy_pbuf_free;
    return p;
}

// LWIPNetworkInterface

LWIPNetworkInterface::LWIPNetworkInterface()
:
#ifdef LWIP_DHCP
    dhcp_acquired(false)
#endif
{
    NETIF_STATS_INIT(this->stats);

    if(driver != nullptr) {
        // TODO check that this calls are effective
        driver->setLinkDownCallback(std::bind(&LWIPNetworkInterface::linkDownCallback, this));
        driver->setLinkUpCallback(std::bind(&LWIPNetworkInterface::linkUpCallback, this));
    }

    // TODO add the interface to the network stack
}

LWIPNetworkInterface::~LWIPNetworkInterface() {

}


void LWIPNetworkInterface::begin(const IPAddress &ip, const IPAddress &nm, const IPAddress &gw) {
    ip_addr_t _ip = fromArduinoIP(ip);
    ip_addr_t _nm = fromArduinoIP(nm);
    ip_addr_t _gw = fromArduinoIP(gw);

    // netif add copies the ip addresses into the netif, no need to store them also in the object
    struct netif *_ni = netif_add(
        &this->ni,
        &_ip, &_nm, &_gw, // FIXME understand if ip addresses are being copied
        this,
        _netif_init,
        ethernet_input
    );
    if(_ni == nullptr) {
        // FIXME error in netif_add, return error
        return;
    }

    netif_set_default(&this->ni); // TODO let the user decide which is the default one

    //TODO add link up and down callback and set the link
    netif_set_up(&this->ni);
    netif_set_link_up(&this->ni);

#ifdef LWIP_DHCP
    // dhcp is started when begin gets ip == nullptr
    if(ip != INADDR_NONE) {
        this->dhcpNotUsed();
    } else {
        this->dhcpStart();
    }
#endif
}

err_t _netif_init(struct netif* ni) {
    LWIPNetworkInterface *iface = (LWIPNetworkInterface*)ni->state;

    return iface->init(ni); // This function call can be a jmp instruction
}

err_t _netif_output(struct netif* ni, struct pbuf* p) {
    LWIPNetworkInterface *iface = (LWIPNetworkInterface*)ni->state;

    return iface->output(ni, p); // This function call can be a jmp instruction
}

void LWIPNetworkInterface::task() {
#ifdef LWIP_DHCP
    // handle dhcp FSM
    // if (dhcp_last_time_call == 0 || millis() - dhcp_last_time_call > DHCP_FINE_TIMER_MSECS) {
        // dhcp_task();
        // dhcp_last_time_call = millis();
    // }
    // TODO we can add a lazy evaluated timer for this condition if dhcp_supplied_address takes too long
    if(!this->dhcp_acquired && dhcp_supplied_address(&this->ni)) {
        dhcp_acquired = true;
    }

#endif
    driver->poll();

    // FIXME this function should not be called here
    // sys_check_timeouts();
}

#ifdef LWIP_DHCP

void LWIPNetworkInterface::dhcpNotUsed() {
    dhcp_inform(&this->ni);
}

bool LWIPNetworkInterface::isDhcpAcquired() {
    return dhcp_acquired;
}

bool LWIPNetworkInterface::dhcpStart() {
    return dhcp_start(&this->ni) == ERR_OK;
}

void LWIPNetworkInterface::dhcpStop() {
    this->dhcpRelease();
    dhcp_stop(&this->ni);
}
bool LWIPNetworkInterface::dhcpRelease() {
    return dhcp_release(&this->ni) == ERR_OK;
}

bool LWIPNetworkInterface::dhcpRenew() {
    return dhcp_renew(&this->ni) == ERR_OK;
}

#endif

void LWIPNetworkInterface::up() {
    netif_set_up(&this->ni);
}

void LWIPNetworkInterface::down() {
    netif_set_down(&this->ni);
}


void LWIPNetworkInterface::linkUpCallback() {
    netif_set_link_up(&this->ni); // TODO check that this sets the interface up also
}

void LWIPNetworkInterface::linkDownCallback() {
    netif_set_link_down(&this->ni); // TODO check that this sets the interface down also
}

// C33EthernetLWIPNetworkInterface
uint8_t C33EthernetLWIPNetworkInterface::eth_id = 0;

C33EthernetLWIPNetworkInterface::C33EthernetLWIPNetworkInterface() {
    LWIPNetworkInterface::driver = &C33EthernetDriver; // driver is the pointer to C33 ethernet driver implementation
}

C33EthernetLWIPNetworkInterface::~C33EthernetLWIPNetworkInterface() {

}

void C33EthernetLWIPNetworkInterface::begin(const IPAddress &ip, const IPAddress &nm, const IPAddress &gw) {
    // The driver needs a callback to consume the incoming buffer
    this->driver->setConsumeCallback(
        std::bind(&C33EthernetLWIPNetworkInterface::consume_callback,
            this, std::placeholders:: _1, std::placeholders::_2));

    // Call the begin function on the Parent class to init the interface
    LWIPNetworkInterface::begin(ip, nm, gw);
}


err_t C33EthernetLWIPNetworkInterface::init(struct netif* ni) {
    // Setting up netif
#if LWIP_NETIF_HOSTNAME
    // TODO pass the hostname in the constructor os with a setter
    ni->hostname                       = "C33_eth";
#endif
    ni->name[0]                        = C33EthernetLWIPNetworkInterface::eth_ifname_prefix;
    ni->name[1]                        = '0' + C33EthernetLWIPNetworkInterface::eth_id++;
    ni->mtu                            = 1500; // FIXME get this from the network
    ni->flags                          |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;

    memcpy(ni->hwaddr, this->driver->getMacAddress(), 6); // FIXME handle this using a constant
    // ni->hwaddr                         = C33EthernetDriver.getMacAddress();
    // ni->hwaddr_len                     = sizeof(macaddress);
    ni->hwaddr_len                     = 6;

    ni->output                         = etharp_output;
    ni->linkoutput                     = _netif_output;

    return ERR_OK;
}

err_t C33EthernetLWIPNetworkInterface::output(struct netif* ni, struct pbuf* p) {
    err_t errval = ERR_OK;
    NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(this->stats);
    NETIF_STATS_TX_TIME_START(this->stats);

    // TODO check if this works, I may get a pbuf chain
    struct pbuf *q = p;
    do {
        auto err = C33EthernetDriver.send((uint8_t*)q->payload, q->len);
        if(err != 0) {

            NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
            errval = ERR_IF;
        }
        q = q->next;
    } while(q != nullptr && errval != ERR_OK);

    NETIF_STATS_INCREMENT_TX_BYTES(this->stats, p->len);
    NETIF_STATS_TX_TIME_AVERAGE(this->stats);
    return errval;
}

void C33EthernetLWIPNetworkInterface::consume_callback(uint8_t* buffer, uint32_t len) {
    // TODO understand if this callback can be moved into the base class

    NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(this->stats);
    zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer);

    // TODO trim the buffer in order to not waste memory
    // mem_trim(buffer, len); // FIXME Assertion "mem_trim: legal memory" failed at line 722

    // TODO consider allocating a custom pool for RX or use PBUF_POOL
    struct pbuf *p = pbuf_alloced_custom(
        PBUF_RAW, len, PBUF_RAM, &custom_pbuf->p, buffer, len);

    if (this->ni.input((struct pbuf*)p, &this->ni) != ERR_OK) {
        NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(this->stats);
        NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(this->stats);
        pbuf_free((struct pbuf*)p);
    } else {
        NETIF_STATS_INCREMENT_RX_BYTES(this->stats, p->len);
    }
}
