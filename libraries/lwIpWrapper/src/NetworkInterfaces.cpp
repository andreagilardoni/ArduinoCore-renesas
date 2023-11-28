#include "NetworkInterfaces.h"
#include <functional>
#include "utils.h"
#include <Arduino_DebugUtils.h>

err_t _netif_init(struct netif* ni);
err_t _netif_output(struct netif* ni, struct pbuf* p);

#ifdef NETWORKSTACK_USE_TIMER
static void timer_cb(timer_callback_args_t* arg);
#endif

#if LWIP_DNS
static void _getHostByNameCBK(const char *name, const ip_addr_t *ipaddr, void *callback_arg);
#endif // LWIP_DNS

// Custom Pbuf definition used to handle RX zero copy
// TODO make better documentation on how this works

typedef struct zerocopy_pbuf {
    struct pbuf_custom p;
    uint8_t* buffer;
} zerocopy_pbuf_t;

static void zerocopy_pbuf_free(struct pbuf *p) {
    // SYS_ARCH_DECL_PROTECT(zerocopy_pbuf_free);
    zerocopy_pbuf_t* zcpbuf = (zerocopy_pbuf_t*) p;

    arduino::lock();
    // SYS_ARCH_PROTECT(zerocopy_pbuf_free);

    // FIXME pbufs may be allocated in a different memory pool, deallocate them accordingly
    mem_free(zcpbuf->buffer);
    zcpbuf->buffer = nullptr;
    mem_free(zcpbuf); // TODO understand if pbuf_free deletes the pbuf
    // SYS_ARCH_UNPROTECT(zerocopy_pbuf_free);

    arduino::unlock();
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
}

void LWIPNetworkInterface::begin(const IPAddress &ip, const IPAddress &nm, const IPAddress &gw) {
    ip_addr_t _ip = fromArduinoIP(ip);
    ip_addr_t _nm = fromArduinoIP(nm);
    ip_addr_t _gw = fromArduinoIP(gw);

    // netif add copies the ip addresses into the netif, no need to store them also in the object
    struct netif *_ni = netif_add(
        &this->ni,
        &_ip, &_nm, &_gw, // ip addresses are being copied and not taken as reference, use a local defined variable
        this,
        _netif_init,
        ethernet_input
    );
    if(_ni == nullptr) {
        // FIXME error in netif_add, return error
        return;
    }

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

    // add the interface to the network stack
    LWIPNetworkStack::getInstance().add_iface(this); // TODO remove interface when it is needed (??)
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
    // TODO we can add a lazy evaluated timer for this condition if dhcp_supplied_address takes too long
    if(!this->dhcp_acquired && dhcp_supplied_address(&this->ni)) {
        dhcp_acquired = true;
    }

#endif
    driver->poll();
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

    /* TODO check if this makes sense, I may get a pbuf chain
     * it could happen that if I get a pbuf chain
     * - there are enough tx_buffers available to accomodate all the packets in the chain
     * - most of the chain is enqueued for delivery, but a certain point the driver.send call returns error
     *   then lwip is supposed to handle that, that may be an issue
     */
    struct pbuf *q = p;
    do {
        NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(this->stats);
        NETIF_STATS_TX_TIME_START(this->stats);
        auto err = C33EthernetDriver.send((uint8_t*)q->payload, q->len);
        if(err != 0) {
            NETIF_STATS_INCREMENT_ERROR(this->stats, err);
            NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
            errval = ERR_IF;
            break;
        }
        q = q->next;

        // FIXME remove this, only purpose is to verify if I ever deal with a pbuf chain
        // if(q!=nullptr) {
        //     NETIF_STATS_INCREMENT_ERROR(this->stats, 1024);
        // }
        NETIF_STATS_INCREMENT_TX_BYTES(this->stats, q->len);
        NETIF_STATS_TX_TIME_AVERAGE(this->stats);
    } while(q != nullptr && errval != ERR_OK);

    // arduino::unlock();

    return errval;
}

void C33EthernetLWIPNetworkInterface::consume_callback(uint8_t* buffer, uint32_t len) {
    // TODO understand if this callback can be moved into the base class
    arduino::lock();
    NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(this->stats);
    zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer);

    // TODO trim the buffer in order to not waste memory
    // mem_trim should be passed as an argument, since it depends on the kind of allocation performed
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
    arduino::unlock();
}


// LWIPNetworkStack
#ifdef NETWORKSTACK_USE_TIMER
static void timer_cb(timer_callback_args_t* arg) {
    LWIPNetworkStack* context = (LWIPNetworkStack*)arg->p_context;

    context->task();
}
#endif

LWIPNetworkStack::LWIPNetworkStack() {
#ifdef NETWORKSTACK_USE_TIMER
    uint8_t type = 8;
    int8_t ch = FspTimer::get_available_timer(type);

    if (ch < 0) {
        ch = FspTimer::get_available_timer(type, true);
    }

    /*
     * NOTE Timer and buffer size
     * The frequency for the timer highly influences the memory requirements for the desired transfer speed
     * You can calculate the buffer size required to achieve that performance from the following formula:
     * buffer_size[byte] = Speed[bit/s] * timer_frequency[Hz]^-1 / 8
     *
     * In the case of portenta C33, the maximum speed achievable was measured with
     * iperf2 tool (provided by lwip) and can reach up to 12Mbit/s.
     * Further improvements can be made, but if we desire to reach that speed the buffer size
     * and the timer frequency should be designed accordingly.
     * buffer = 12 * 10^6 bit/s * (100Hz)^-1 / 8 = 15000 Byte = 15KB
     *
     * Since this is a constrained environment we could accept performance loss and
     * delegate lwip to handle lost packets.
     */
    timer.begin(TIMER_MODE_PERIODIC, type, ch, 100.0, 0, timer_cb, this);
    timer.setup_overflow_irq();
    timer.open();
    timer.start();
#endif
}

void LWIPNetworkStack::add_iface(LWIPNetworkInterface* iface) {
    // if it is the first interface set it as the default route
    if(this->ifaces.empty()) {
        netif_set_default(&iface->ni); // TODO let the user decide which is the default one
    }

    // add the interface if not already present in the vector
    this->ifaces.push_back(iface);
}

void LWIPNetworkStack::task() {
    for(LWIPNetworkInterface* iface: this->ifaces) { // FIXME is this affecting performances?
        iface->task();
    }

    arduino::lock();
    sys_check_timeouts();
    arduino::unlock();
}

void LWIPNetworkStack::setDefaultIface(LWIPNetworkInterface* iface) {
    // TODO check if the iface is in the vector

    netif_set_default(&iface->ni);
}

#if LWIP_DNS

struct dns_callback {
    std::function<void(const IPAddress&)> cbk;
};

static void _getHostByNameCBK(const char *name, const ip_addr_t *ipaddr, void *callback_arg) {
    dns_callback* cbk = (dns_callback*)callback_arg;

    cbk->cbk(toArduinoIP(ipaddr));

    delete cbk;
}

// add a dns server, priority set to 0 means it is the first being queryed, -1 means the last
uint8_t LWIPNetworkStack::addDnsServer(const IPAddress& aDNSServer, int8_t priority) {
    // TODO test this function with all the possible cases of dns server position
    if(priority == -1) {
        // lwip has an array for dns servers that can be iterated with dns_getserver(num)
        // when a dns server is set to any value, it means it is the last

        for(priority=0;
            priority<DNS_MAX_SERVERS && !ip_addr_isany_val(*dns_getserver(priority));
            priority++) {}
    }

    if(priority >= DNS_MAX_SERVERS) {
        // unable to add another dns server, because priority is more than the dns server available space
        return -1;
    }

    ip_addr_t ip = fromArduinoIP(aDNSServer);

    dns_setserver(priority, &ip);
}

void LWIPNetworkStack::clearDnsServers() {
    for(uint8_t i=0; i<DNS_MAX_SERVERS; i++) {
        dns_setserver(i, IP_ANY_TYPE);
    }
}

// DNS resolution works with a callback if the resolution doesn't return immediately
int LWIPNetworkStack::getHostByName(const char* aHostname, IPAddress& aResult, bool execute_task) {
    /* this has to be a blocking call but we need to understand how to handle wait time
     * - we can have issues when running concurrently from different contextes,
     *   meaning that issues may arise if we run task() method of this class from an interrupt
     *   context and the "userspace".
     * - this function is expected to be called in the application layer, while the lwip stack is
     *   being run in an interrupt context, otherwise this call won't work because it will block
     *   everything
     * - this function shouldn't be called when lwip is run in the same context as the application
     */
    volatile bool completed = false;

    uint8_t res = this->getHostByName(aHostname, [&aResult, &completed](const IPAddress& ip){
        aResult = ip;
        completed = true;
    });

    while(res == 1 && !completed) { // DNS timeouts seems to be handled by lwip, no need to put one here
        delay(1);
        if(execute_task) {
            this->task();
        }
    }

    return res == 1 ? 0 : res;
}

// TODO instead of returning int return an enum value
int LWIPNetworkStack::getHostByName(const char* aHostname, std::function<void(const IPAddress&)> cbk) {
    ip_addr_t addr; // TODO understand if this needs to be in the heap
    uint8_t res = 0;

    dns_callback* dns_cbk = new dns_callback;
    dns_cbk->cbk = cbk;
    err_t err = dns_gethostbyname(aHostname, &addr, _getHostByNameCBK, dns_cbk);

    switch(err) {
    case ERR_OK:
        // the address was already present in the local cache
        cbk(toArduinoIP(&addr));

        delete dns_cbk;
        break;
    case ERR_INPROGRESS:
        // the address is not present in the local cache, return and wait for the address resolution to complete
        res = 1;
        break;
    case ERR_ARG: // there are issues in the arguments passed
    default:
        delete dns_cbk;
        res = -1;
    }

    return res;
}
#endif