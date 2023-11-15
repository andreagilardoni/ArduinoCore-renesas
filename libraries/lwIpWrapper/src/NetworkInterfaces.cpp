#include "NetworkInterfaces.h"
#include <functional>
#include <Arduino_DebugUtils.h>


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
    dhcp_timeout(30000),
    dhcp_started(false),
    dhcp_acquired(false),
    dhcp_st(DHCP_IDLE_STATUS),
    _dhcp_lease_state(DHCP_CHECK_NONE)
#endif
{
    NETIF_STATS_INIT(this->stats);
}

LWIPNetworkInterface::~LWIPNetworkInterface() {

}


void LWIPNetworkInterface::begin(ip_addr_t* ip, ip_addr_t* nm, ip_addr_t* gw) {
    netif_add(
        &this->ni,
        // &this->ip, &this->nm, &this->gw, // FIXME understand how to properly set the ip
        ip, nm, gw,
        this,
        _netif_init,
        ethernet_input
    );
    netif_set_default(&this->ni); // TODO let the user decide which is the default one

    //TODO add link up and down callback and set the link
    netif_set_up(&this->ni);
    netif_set_link_up(&this->ni);
#ifdef LWIP_DHCP
    // dhcp is started when begin gets ip == nullptr
    if(ip != nullptr) {
        return;
    }

    // block this call until dhcp server gives an ip address
    // do {
    //     // TODO manage the case that LWIP is run inside a timer.
    //     this->task();
    // } while(!dhcp_acquired);
    // dhcp_request();
    // DEBUG_INFO("dhcp start");

    // this->DhcpStart();
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
#endif
    driver->poll();

    // FIXME this function should not be called here
    // sys_check_timeouts();
}

#ifdef LWIP_DHCP

void LWIPNetworkInterface::DhcpNotUsed() {
    DhcpStop();
    dhcp_inform(&this->ni);
}

int LWIPNetworkInterface::checkLease() {
    int rc = DHCP_CHECK_NONE;

    task();
    rc = dhcp_get_lease_state();

    if (rc != _dhcp_lease_state) {
        switch (_dhcp_lease_state) {
        case DHCP_CHECK_NONE:
            _dhcp_lease_state = rc;
            rc = DHCP_CHECK_NONE;
            break;

        case DHCP_CHECK_RENEW_OK:
            _dhcp_lease_state = rc;
            if (rc == DHCP_CHECK_NONE) {
                rc = DHCP_CHECK_RENEW_OK;
            } else {
                rc = DHCP_CHECK_RENEW_FAIL;
            }
            break;

        case DHCP_CHECK_REBIND_OK:
            _dhcp_lease_state = rc;
            if (rc == DHCP_CHECK_NONE) {
                rc = DHCP_CHECK_REBIND_OK;
            } else {
                rc = DHCP_CHECK_REBIND_FAIL;
            }
            break;

        default:
            _dhcp_lease_state = DHCP_CHECK_NONE;
            break;
        }
    }

    return rc;
}

uint8_t LWIPNetworkInterface::dhcp_get_lease_state() {
    uint8_t res = 0;
    struct dhcp* dhcp = (struct dhcp*)netif_get_client_data(&this->ni, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP);

    if (dhcp->state == 5 /*DHCP_STATE_RENEWING*/) {
        res = 2;
    } else if (dhcp->state == 4 /* DHCP_STATE_REBINDING */) {
        res = 4;
    }
    return res;
}

bool LWIPNetworkInterface::dhcp_request() {
    /* make a DHCP request: it runs till an address is acquired or a timeout
       expires */
    unsigned long startTime = millis();
    bool acquired = false;

    do {
        this->task();
        acquired = isDhcpAcquired();
    } while (!acquired && ((millis() - startTime) < dhcp_timeout));

    return acquired;
}

void LWIPNetworkInterface::dhcp_reset() {
    /* it resets the DHCP status to IDLE */
    // TODO understand how this is supposed to reset timers for dhcp
    while (dhcp_st != DHCP_IDLE_STATUS) {
        task(); // FIXME understand if this is ok
    }
}

void LWIPNetworkInterface::DhcpSetTimeout(unsigned long t) {
    dhcp_timeout = t;
}

bool LWIPNetworkInterface::isDhcpAcquired() {
    return dhcp_acquired;
}

bool LWIPNetworkInterface::DhcpStart() {
    /* first stop / reset */
    DhcpStop();
    /* then actually start */
    dhcp_started = true;
    dhcp_st = DHCP_START_STATUS;
    return dhcp_request();
}

void LWIPNetworkInterface::DhcpStop() {
    dhcp_started = false;
    if (dhcp_st == DHCP_IDLE_STATUS) {
        return;
    }
    if (dhcp_st == DHCP_GOT_STATUS && netif_is_link_up(&this->ni)) {
        dhcp_st = DHCP_RELEASE_STATUS;
    } else {
        dhcp_st = DHCP_STOP_STATUS;
    }
    this->dhcp_reset();
}

void LWIPNetworkInterface::dhcp_task() {

    struct dhcp* lwip_dhcp;
    static unsigned long DHCPStartTime;

    switch (dhcp_st) {
    case DHCP_IDLE_STATUS:
        /* nothing to do... wait for DhcpStart() to start the process */
        break;
    case DHCP_START_STATUS:
        if (netif_is_link_up(&this->ni)) {
            DEBUG_INFO("dhcp_start");
            ip_addr_set_zero_ip4(&(this->ni.ip_addr));
            ip_addr_set_zero_ip4(&(this->ni.netmask));
            ip_addr_set_zero_ip4(&(this->ni.gw));
            /* start lwIP dhcp */
            dhcp_start(&this->ni);

            DHCPStartTime = millis();
            dhcp_st = DHCP_WAIT_STATUS;
        }
        break;
    case DHCP_WAIT_STATUS:
        if (netif_is_link_up(&this->ni)) {
            if (dhcp_supplied_address(&this->ni)) {
                dhcp_acquired = true;
                dhcp_st = DHCP_GOT_STATUS;
            } else if (millis() - DHCPStartTime > 1000) {
                // DEBUG_INFO("pino1");

                /* TIMEOUT */
                lwip_dhcp = (struct dhcp*)netif_get_client_data(&this->ni, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP);
                if (lwip_dhcp->tries > MAX_DHCP_TRIES) {
                    // DEBUG_INFO("pino2");
                    dhcp_st = DHCP_STOP_STATUS;
                }
            }
        } else {
            dhcp_st = DHCP_START_STATUS;
        }
        break;
    case DHCP_GOT_STATUS:
        // DEBUG_INFO("pino");
        if (!netif_is_link_up(&this->ni)) {
            dhcp_st = DHCP_STOP_STATUS;
        }

        break;
    case DHCP_RELEASE_STATUS:
        dhcp_release(&this->ni);
        dhcp_acquired = false;
        dhcp_st = DHCP_STOP_STATUS;
        break;
    case DHCP_STOP_STATUS:
        dhcp_acquired = false;
        dhcp_stop(&this->ni);
        if (dhcp_started) {
            dhcp_st = DHCP_START_STATUS;
        } else {
            dhcp_st = DHCP_IDLE_STATUS;
        }
        break;
    }
}
#endif

// C33EthernetLWIPNetworkInterface
uint8_t C33EthernetLWIPNetworkInterface::eth_id = 0;

C33EthernetLWIPNetworkInterface::C33EthernetLWIPNetworkInterface() {
    LWIPNetworkInterface::driver = &C33EthernetDriver; // driver is the pointer to C33 ethernet driver implementation
}

C33EthernetLWIPNetworkInterface::~C33EthernetLWIPNetworkInterface() {

}

void C33EthernetLWIPNetworkInterface::begin(ip_addr_t* ip, ip_addr_t* nm, ip_addr_t* gw) {
    this->driver->setConsumeCallback(
        std::bind(&C33EthernetLWIPNetworkInterface::consume_callback,
            this, std::placeholders:: _1, std::placeholders::_2));
    LWIPNetworkInterface::begin(ip, nm, gw);
}


err_t C33EthernetLWIPNetworkInterface::init(struct netif* ni) {
    DEBUG_INFO("netif init");
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
}

err_t C33EthernetLWIPNetworkInterface::output(struct netif* ni, struct pbuf* p) {
    err_t errval = ERR_OK;
    NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(this->stats);
    NETIF_STATS_TX_TIME_START(this->stats);
    // TODO check if this works, I may get a pbuf chain
    auto err = C33EthernetDriver.send((uint8_t*)p->payload, p->len);

    if(err != 0) {
        NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
        errval = ERR_IF;
    }

    NETIF_STATS_INCREMENT_TX_BYTES(this->stats, p->len);
    NETIF_STATS_TX_TIME_AVERAGE(this->stats);
    return errval;
}

void C33EthernetLWIPNetworkInterface::consume_callback(uint8_t* buffer, uint32_t len) {
    NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(this->stats);
    zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer);

    // TODO trim the buffer in order to not waste memory
    // mem_trim(buffer, len); // FIXME Assertion "mem_trim: legal memory" failed at line 722

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
