#include "NetworkInterfaces.h"
#include <functional>
#include "utils.h"

extern "C" void dhcps_start(struct netif *netif);

err_t _netif_init(struct netif* ni);
err_t _netif_output(struct netif* ni, struct pbuf* p);

static uint8_t Encr2wl_enc(int enc);

#ifdef NETWORKSTACK_USE_TIMER
static void timer_cb(timer_callback_args_t* arg);
#endif

#if LWIP_DNS
static void _getHostByNameCBK(const char *name, const ip_addr_t *ipaddr, void *callback_arg);
#endif // LWIP_DNS

// Custom Pbuf definition used to handle RX zero copy
// TODO make better documentation on how this works
// TODO hostname should be defined at network stack level and shared among ifaces
// TODO buffer management (allocation/deallocation/trim/etc.) should be properly handled by a wrapper class and be transparent wrt the user

typedef struct zerocopy_pbuf {
    struct pbuf_custom p;
    uint8_t* buffer;
    uint32_t size;
    void(*buffer_free)(void*);
} zerocopy_pbuf_t;

static void zerocopy_pbuf_free(struct pbuf *p) {
    // SYS_ARCH_DECL_PROTECT(zerocopy_pbuf_free);
    zerocopy_pbuf_t* zcpbuf = (zerocopy_pbuf_t*) p;

    arduino::lock();
    // SYS_ARCH_PROTECT(zerocopy_pbuf_free);

    // FIXME pbufs may be allocated in a different memory pool, deallocate them accordingly
    zcpbuf->buffer_free(zcpbuf->buffer);
    zcpbuf->buffer = nullptr;
    mem_free(zcpbuf); // TODO understand if pbuf_free deletes the pbuf
    // SYS_ARCH_UNPROTECT(zerocopy_pbuf_free);

    arduino::unlock();
}

static inline zerocopy_pbuf_t* get_zerocopy_pbuf(uint8_t *buffer, uint32_t size, void(*buffer_free)(void*) = mem_free) {
    zerocopy_pbuf_t* p = (zerocopy_pbuf_t*)mem_malloc(sizeof(zerocopy_pbuf_t));
    p->buffer = buffer;
    p->size = size;
    p->p.custom_free_function = zerocopy_pbuf_mem_free;
    p->buffer_free = buffer_free;
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
    if(driver != nullptr) {
        driver->poll();
    }
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
    netif_set_link_up(&this->ni); // TODO test that moving this here still makes ethernet work
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

    const uint16_t trimmed_size = len;

    // zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer, 1536);
    zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer, trimmed_size);

    // mem_trim should be passed as an argument, since it depends on the kind of allocation performed
    void* buf = mem_trim(buffer, trimmed_size);

    // TODO consider allocating a custom pool for RX or use PBUF_POOL
    struct pbuf *p = pbuf_alloced_custom(
        PBUF_RAW, len, PBUF_RAM, &custom_pbuf->p, buffer, trimmed_size);

    err_t err = this->ni.input((struct pbuf*)p, &this->ni);
    if (err != ERR_OK) {
        NETIF_STATS_INCREMENT_ERROR(this->stats, err);

        NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(this->stats);
        NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(this->stats);
        pbuf_free((struct pbuf*)p);
    } else {
        NETIF_STATS_INCREMENT_RX_BYTES(this->stats, p->len);
    }
    // arduino::unlock();
}

// WiFIStationLWIPNetworkInterface
uint8_t WiFIStationLWIPNetworkInterface::wifistation_id = 0;

WiFIStationLWIPNetworkInterface::WiFIStationLWIPNetworkInterface()
: hw_init(false) {
    // TODO this class should implement the driver interface
    // CLwipIf::getInstance()
}

int WiFIStationLWIPNetworkInterface::begin() { // TODO This should be called only once, make it private
    int res = 0;
    int time_num = 0;

    // arduino::lock();
    CEspControl::getInstance().listenForStationDisconnectEvent([this] (CCtrlMsgWrapper *resp) -> int {
        netif_set_link_down(&this->ni);
        return ESP_CONTROL_OK;
    });
    CEspControl::getInstance().listenForInitEvent([this] (CCtrlMsgWrapper *resp) -> int {
        // Serial.println("init");
        this->hw_init = true;
        return ESP_CONTROL_OK;
    });

    if ((res=CEspControl::getInstance().initSpiDriver()) != 0) {
        res = -1; // FIXME put a proper error code
        goto exit;
    }

    while (time_num < 100 && !hw_init) { // TODO #define WIFI_INIT_TIMEOUT_MS 10000
        CEspControl::getInstance().communicateWithEsp();
        R_BSP_SoftwareDelay(100, BSP_DELAY_UNITS_MILLISECONDS);
        time_num++;
    }

    res = CEspControl::getInstance().setWifiMode(WIFI_MODE_STA);
    LWIPNetworkInterface::begin();
    // netif_set_link_up(&this->ni); // TODO this should be set only when successfully connected to an AP
exit:
    // arduino::unlock();
    return res;
}

int WiFIStationLWIPNetworkInterface::connectToAP(const char* ssid, const char *passphrase) {
    WifiApCfg_t ap;
    int rv = ESP_CONTROL_CTRL_ERROR; // FIXME this should be set with an error meaning AP not found
    bool found = false;
    int8_t best_index = -1; // this index is used to find the ap with the best rssi
    // AccessPoint_t* best_matching_ap;
    // arduino::lock();

    // if(access_points.size() == 0) {
    //     this->scanForAp();
    // }
    if((rv=this->scanForAp()) != WL_SCAN_COMPLETED) {
        // rv = -1; // FIXME set proper error code
        goto exit;
    }
    this->printAps();

    // find the AP with the best rssi
    for (uint8_t i = 0; i < access_points.size(); i++) {
        if(strcmp(ssid, (const char*)access_points[i].ssid) == 0
            && (best_index == -1 || access_points[best_index].rssi < access_points[i].rssi)
            ) {
            best_index=i;
        }
    }
    DEBUG_INFO("best rssi: %d", best_index);
    if(best_index != -1) {
        // memset(ap.ssid, 0x00, SSID_LENGTH); // I shouldn't need to zero the ssid string pointer
        strncpy((char*)ap.ssid, ssid, SSID_LENGTH);
        // memcpy(ap.ssid, access_points[best_index].ssid, SSID_LENGTH);

        // memset(ap.pwd, 0x00, PASSWORD_LENGTH);
        if(passphrase != nullptr) {
            auto slen = strlen(passphrase)+1;
            strncpy((char*)ap.pwd, passphrase, (slen < PASSWORD_LENGTH) ? slen : PASSWORD_LENGTH);
            // memcpy(ap.pwd, passphrase, (slen < PASSWORD_LENGTH) ? slen : PASSWORD_LENGTH);
        } else {
            // memset(ap.pwd, 0x00, PASSWORD_LENGTH);
            ap.pwd[0] = '\0';
        }

        memset(ap.bssid, 0x00, BSSID_LENGTH);
        memcpy(ap.bssid, access_points[best_index].bssid, BSSID_LENGTH);

        // arduino::lock();
        Serial.println("connect begin");
        CEspControl::getInstance().communicateWithEsp(); // TODO make this shared between SoftAP and station

        DEBUG_INFO("connecting to: \"%s\" \"%s\",  %X:%X:%X:%X:%X:%X", ap.ssid, ap.pwd, ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5]);
        rv=CEspControl::getInstance().connectAccessPoint(ap);
        DEBUG_INFO("res: %d", rv);
        // arduino::unlock();

        if (rv == ESP_CONTROL_OK) {
            CEspControl::getInstance().getAccessPointConfig(access_point_cfg);

            netif_set_link_up(&this->ni);
        }
        Serial.println("connect end");
        // arduino::unlock();
    }
    // else {
    //     // TODO return AP not found error
    // }

exit:
    // arduino::unlock();

    return rv;
}

// disconnect
int WiFIStationLWIPNetworkInterface::disconnectFromAp() {
    return CEspControl::getInstance().disconnectAccessPoint();
}

err_t WiFIStationLWIPNetworkInterface::init(struct netif* ni) {
    // Setting up netif
#if LWIP_NETIF_HOSTNAME
    // TODO pass the hostname in the constructor os with a setter
    ni->hostname                       = "C33-WifiSta";
#endif
    ni->name[0]                        = WiFIStationLWIPNetworkInterface::wifistation_ifname_prefix;
    ni->name[1]                        = '0' + WiFIStationLWIPNetworkInterface::wifistation_id++;
    ni->mtu                            = 1500; // FIXME get this from the network
    ni->flags                          |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;

    WifiMac_t MAC;
    MAC.mode = WIFI_MODE_STA;
    CEspControl::getInstance().getWifiMacAddress(MAC);
    CNetUtilities::macStr2macArray(ni->hwaddr, MAC.mac);
    ni->hwaddr_len = 6; // FIXME this should be a macro defined somewhere
    // ni->hwaddr_len = CLwipIf::getInstance().getMacAddress(NI_WIFI_STATION, ni->hwaddr);

    ni->output                         = etharp_output;
    ni->linkoutput                     = _netif_output;

    return ERR_OK;
}

err_t WiFIStationLWIPNetworkInterface::output(struct netif* _ni, struct pbuf* p) {
    // FIXME set ifn
    int ifn = 0; // interface number in CNetif.cpp seems to not be set anywhere
    uint8_t *buf = nullptr;
    uint16_t size=p->tot_len;
    err_t errval = ERR_IF;
    int err = ESP_CONTROL_OK;

    NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(this->stats);
    NETIF_STATS_TX_TIME_START(this->stats);

    // p may be a chain of pbufs
    if(p->next != nullptr) {
        buf = (uint8_t*) malloc(size*sizeof(uint8_t));
        if(buf == nullptr) {\
            NETIF_STATS_INCREMENT_ERROR(this->stats, ERR_MEM);
            NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
            errval = ERR_MEM;
            goto exit;
        }

        // copy the content of pbuf
        assert(pbuf_copy_partial(p, buf, size, 0) == size);
    } else {
        buf = (uint8_t*)p->payload;
    }

    // sendBuffer makes a memcpy of buffer
    // TODO send buffer should handle the buffer deletion and avoid a memcpy
    if ((err = CEspControl::getInstance().sendBuffer(
            ESP_STA_IF, ifn, buf, size)) == ESP_CONTROL_OK) {
        errval = ERR_OK;
        NETIF_STATS_INCREMENT_TX_BYTES(this->stats, size);
        NETIF_STATS_TX_TIME_AVERAGE(this->stats);
    } else {
        NETIF_STATS_INCREMENT_ERROR(this->stats, err);
        NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
    }

exit:
    if(p->next != nullptr && buf != nullptr) {
        free(buf);
    }
    return errval;
}

void WiFIStationLWIPNetworkInterface::task() {
    // calling the base class task, in order to make thigs work
    LWIPNetworkInterface::task();

    // TODO in order to make things easier this should be implemented inside of Wifi driver
    // and not override LWIPInterface method

    uint8_t if_num = 0;
    uint16_t dim = 0;
    uint8_t* buffer = nullptr;
    struct pbuf* p = nullptr;

    NETIF_STATS_RX_TIME_START(this->stats);
    // arduino::lock();
    // TODO do not perform this when not connected to an AP
    if(hw_init) {
        CEspControl::getInstance().communicateWithEsp(); // TODO make this shared between SoftAP and station

        // TODO handling buffer this way may be harmful for the memory
        buffer = CEspControl::getInstance().getStationRx(if_num, dim);
    }

    // empty the ESP32 queue
    while(buffer != nullptr) {
        // FIXME this section is redundant and should be generalized toghether with C33EthernetLWIPNetworkInterface::consume_callback
        // TODO understand if this should be moved into the base class
        NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(this->stats);
        // NETIF_STATS_RX_TIME_START(this->stats);

        zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer, dim, free);

        // TODO consider allocating a custom pool for RX or use PBUF_POOL
        struct pbuf *p = pbuf_alloced_custom(
            PBUF_RAW, dim, PBUF_RAM, &custom_pbuf->p, buffer, dim);

        err_t err = this->ni.input((struct pbuf*)p, &this->ni);
        if (err != ERR_OK) {
            NETIF_STATS_INCREMENT_ERROR(this->stats, err);

            NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(this->stats);
            NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(this->stats);
            pbuf_free((struct pbuf*)p);
        } else {
            NETIF_STATS_INCREMENT_RX_BYTES(this->stats, p->len);
        }

        buffer = CEspControl::getInstance().getStationRx(if_num, dim);
        // NETIF_STATS_RX_TIME_AVERAGE(this->stats);
    }
    NETIF_STATS_RX_TIME_AVERAGE(this->stats);
    // arduino::unlock();
}

void WiFIStationLWIPNetworkInterface::consume_callback(uint8_t* buffer, uint32_t len) {
    // FIXME take what is written in task and put it in here
}

const char* WiFIStationLWIPNetworkInterface::getSSID() {
    return (const char*)access_point_cfg.ssid;
}

uint8_t* WiFIStationLWIPNetworkInterface::getBSSID(uint8_t* bssid){
    CNetUtilities::macStr2macArray(bssid, (const char*)access_point_cfg.bssid);
    return bssid;
}

int32_t WiFIStationLWIPNetworkInterface::getRSSI() {
    // TODO should this be updated?
    return (uint32_t)access_point_cfg.rssi;
}

uint8_t WiFIStationLWIPNetworkInterface::getEncryptionType() {
    return Encr2wl_enc(access_point_cfg.encryption_mode);
}

// int WiFIStationLWIPNetworkInterface::getMacAddress(uint8_t* mac) {
// }

// uint8_t WiFIStationLWIPNetworkInterface::getChannel() {
//     return (uint8_t)access_point_cfg.channel;
// }

int WiFIStationLWIPNetworkInterface::scanForAp() {
    // arduino::lock();
    access_points.clear(); // FIXME create access_points vector

    int res = CEspControl::getInstance().getAccessPointScanList(access_points);
    if (res == ESP_CONTROL_OK) {
        res = WL_SCAN_COMPLETED;
    }
    // else {
    //     res = WL_NO_SSID_AVAIL; // TODO
    // }

    // arduino::unlock();

    return res;
}

void WiFIStationLWIPNetworkInterface::printAps() {
    for(auto ap: access_points) {
        Serial.print("Access point: \"");
        Serial.print((char*)ap.ssid);
        Serial.print("\" ");
        Serial.print("rssi: ");
        Serial.println(ap.rssi);
    }
}

static uint8_t Encr2wl_enc(int enc) {
    if (enc == WIFI_AUTH_OPEN) {
        return ENC_TYPE_NONE;
    } else if (enc == WIFI_AUTH_WEP) {
        return ENC_TYPE_WEP;
    } else if (enc == WIFI_AUTH_WPA_PSK) {
        return ENC_TYPE_WPA;
    } else if (enc == WIFI_AUTH_WPA2_PSK) {
        return ENC_TYPE_WPA2;
    } else if (enc == WIFI_AUTH_WPA_WPA2_PSK) {
        return ENC_TYPE_WPA2;
    } else if (enc == WIFI_AUTH_WPA2_ENTERPRISE) {
        return ENC_TYPE_WPA2_ENTERPRISE;
    } else if (enc == WIFI_AUTH_WPA3_PSK) {
        return ENC_TYPE_WPA3;
    } else if (enc == WIFI_AUTH_WPA2_WPA3_PSK) {
        return ENC_TYPE_WPA3;
    } else {
        return ENC_TYPE_UNKNOWN;
    }
}

// SoftAPLWIPNetworkInterface
uint8_t SoftAPLWIPNetworkInterface::softap_id = 0;

// This is required for dhcp server to assign ip addresses to AP clients
IPAddress default_nm("255.255.255.0");
IPAddress default_dhcp_server_ip("192.168.4.1");

SoftAPLWIPNetworkInterface::SoftAPLWIPNetworkInterface()
: hw_init(false) {

}

int SoftAPLWIPNetworkInterface::begin() { // TODO This should be called only once, make it private
    int res = 0;
    int time_num = 0;

    // arduino::lock();
    CEspControl::getInstance().listenForInitEvent([this] (CCtrlMsgWrapper *resp) -> int {
        // Serial.println("init");
        this->hw_init = true;
        return ESP_CONTROL_OK;
    });

    if ((res=CEspControl::getInstance().initSpiDriver()) != 0) {
        // res = -1; // FIXME put a proper error code
        goto exit;
    }

    while (time_num < 100 && !hw_init) { // TODO #define WIFI_INIT_TIMEOUT_MS 10000
        CEspControl::getInstance().communicateWithEsp();
        R_BSP_SoftwareDelay(100, BSP_DELAY_UNITS_MILLISECONDS);
        time_num++;
    }

    res = CEspControl::getInstance().setWifiMode(WIFI_MODE_AP);

    // netif_set_link_up(&this->ni); // TODO this should be set only when successfully connected to an AP
    LWIPNetworkInterface::begin(
        default_dhcp_server_ip,
        default_nm,
        default_dhcp_server_ip
    );
exit:
    // arduino::unlock();
    return res;
}

// TODO scan the other access point first and then set the channel if 0
// TODO there are requirements for ssid and password
int SoftAPLWIPNetworkInterface::startSoftAp(const char* ssid, const char* passphrase, uint8_t channel) {
    SoftApCfg_t cfg;

    strncpy((char*)cfg.ssid, ssid, SSID_LENGTH);
    // memset(cfg.ssid, 0x00, SSID_LENGTH);
    // memcpy(cfg.ssid, ssid, (strlen(ssid) < SSID_LENGTH) ? strlen(ssid) : SSID_LENGTH);
    // memset(cfg.pwd, 0x00, PASSWORD_LENGTH);
    if (passphrase == nullptr) {
        cfg.pwd[0] = '\0';
        cfg.encryption_mode = WIFI_AUTH_OPEN;
    } else {
        auto slen = strlen(passphrase)+1;
        strncpy((char*)cfg.pwd, passphrase, (slen < PASSWORD_LENGTH) ? slen : PASSWORD_LENGTH);

        cfg.encryption_mode = WIFI_AUTH_WPA_WPA2_PSK;
    }

    channel = (channel == 0) ? 1 : channel;
    cfg.channel = (channel > MAX_CHNL_NO) ? MAX_CHNL_NO : channel;
    cfg.max_connections = MAX_SOFAT_CONNECTION_DEF;
    cfg.bandwidth = WIFI_BW_HT40;
    cfg.ssid_hidden = false;

    int rv = CEspControl::getInstance().startSoftAccessPoint(cfg);
    if (rv == ESP_CONTROL_OK) {
        CEspControl::getInstance().getSoftAccessPointConfig(soft_ap_cfg);
        // wifi_status = WL_AP_LISTENING;
        netif_set_link_up(&this->ni);

        // FIXME the dhcp server should be started somewhere else
        dhcps_start(&(this->ni));
    } else {
        // wifi_status = WL_AP_FAILED;
    }


    return rv;
}

int SoftAPLWIPNetworkInterface::stopSoftAp() {

}

err_t SoftAPLWIPNetworkInterface::init(struct netif* ni) {
    // Setting up netif
#if LWIP_NETIF_HOSTNAME
    // TODO pass the hostname in the constructor os with a setter
    ni->hostname                       = "C33-SoftAP";
#endif
    ni->name[0]                        = SoftAPLWIPNetworkInterface::softap_ifname_prefix;
    ni->name[1]                        = '0' + SoftAPLWIPNetworkInterface::softap_id++;
    ni->mtu                            = 1500; // FIXME get this from the network
    ni->flags                          |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;

    WifiMac_t MAC;
    MAC.mode = WIFI_MODE_AP;
    CEspControl::getInstance().getWifiMacAddress(MAC);
    CNetUtilities::macStr2macArray(ni->hwaddr, MAC.mac);
    ni->hwaddr_len = 6; // FIXME this should be a macro defined somewhere

    ni->output                         = etharp_output;
    ni->linkoutput                     = _netif_output;

    return ERR_OK;
}

err_t SoftAPLWIPNetworkInterface::output(struct netif* _ni, struct pbuf* p) {
    // FIXME set ifn
    int ifn = 0; // interface number in CNetif.cpp seems to not be set anywhere
    uint8_t *buf = nullptr;
    uint16_t size=p->tot_len;
    err_t errval = ERR_IF;
    int err = ESP_CONTROL_OK;

    NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(this->stats);
    NETIF_STATS_TX_TIME_START(this->stats);

    // arduino::lock();
    // p may be a chain of pbufs
    if(p->next != nullptr) {
        buf = (uint8_t*) malloc(size*sizeof(uint8_t));
        if(buf == nullptr) {\
            NETIF_STATS_INCREMENT_ERROR(this->stats, ERR_MEM);
            NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
            errval = ERR_MEM;
            goto exit;
        }

        // copy the content of pbuf
        assert(pbuf_copy_partial(p, buf, size, 0) == size);
    } else {
        buf = (uint8_t*)p->payload;
    }

    // sendBuffer makes a memcpy of buffer
    // TODO send buffer should handle the buffer deletion and avoid a memcpy
    if ((err = CEspControl::getInstance().sendBuffer(
            ESP_AP_IF, ifn, buf, size)) == ESP_CONTROL_OK) {
        errval = ERR_OK;
        NETIF_STATS_INCREMENT_TX_BYTES(this->stats, size);
        NETIF_STATS_TX_TIME_AVERAGE(this->stats);
    } else {
        NETIF_STATS_INCREMENT_ERROR(this->stats, err);
        NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(this->stats);
    }

exit:
    if(p->next != nullptr && buf != nullptr) {
        free(buf);
    }
    // arduino::unlock();
    return errval;
}

void SoftAPLWIPNetworkInterface::task() {
    // calling the base class task, in order to make thigs work
    LWIPNetworkInterface::task();

    // TODO in order to make things easier this should be implemented inside of Wifi driver
    // and not override LWIPInterface method

    uint8_t if_num = 0;
    uint16_t dim = 0;
    uint8_t* buffer = nullptr;
    struct pbuf* p = nullptr;

    NETIF_STATS_RX_TIME_START(this->stats);
    // arduino::lock();
    // TODO do not perform this when not connected to an AP
    if(hw_init) {
        CEspControl::getInstance().communicateWithEsp(); // TODO make this shared between SoftAP and station

        // TODO handling buffer this way may be harmful for the memory
        buffer = CEspControl::getInstance().getSoftApRx(if_num, dim);
    }

    // empty the ESP32 queue
    while(buffer != nullptr) {
        // FIXME this section is redundant and should be generalized toghether with C33EthernetLWIPNetworkInterface::consume_callback
        // TODO understand if this should be moved into the base class
        NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(this->stats);
        // NETIF_STATS_RX_TIME_START(this->stats);

        zerocopy_pbuf_t *custom_pbuf = get_zerocopy_pbuf(buffer, dim, free);

        // TODO consider allocating a custom pool for RX or use PBUF_POOL
        struct pbuf *p = pbuf_alloced_custom(
            PBUF_RAW, dim, PBUF_RAM, &custom_pbuf->p, buffer, dim);

        err_t err = this->ni.input((struct pbuf*)p, &this->ni);
        if (err != ERR_OK) {
            NETIF_STATS_INCREMENT_ERROR(this->stats, err);

            NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(this->stats);
            NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(this->stats);
            pbuf_free((struct pbuf*)p);
        } else {
            NETIF_STATS_INCREMENT_RX_BYTES(this->stats, p->len);
        }

        buffer = CEspControl::getInstance().getStationRx(if_num, dim);
        // NETIF_STATS_RX_TIME_AVERAGE(this->stats);
    }
    NETIF_STATS_RX_TIME_AVERAGE(this->stats);
    // arduino::unlock();
}

const char* SoftAPLWIPNetworkInterface::getSSID() {
    return (const char*)soft_ap_cfg.ssid;
}

uint8_t* SoftAPLWIPNetworkInterface::getBSSID(uint8_t* bssid){
    // CNetUtilities::macStr2macArray(bssid, (const char*)soft_ap_cfg.bssid);
    // return bssid;
}

uint8_t SoftAPLWIPNetworkInterface::getEncryptionType() {
    return Encr2wl_enc(soft_ap_cfg.encryption_mode);
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
    timer.begin(TIMER_MODE_PERIODIC, type, ch, 200.0, 0, timer_cb, this); // TODO make the user decide how to handle these parameters
#endif
}

void LWIPNetworkStack::add_iface(LWIPNetworkInterface* iface) {
    // if it is the first interface set it as the default route
    if(this->ifaces.empty()) {
        netif_set_default(&iface->ni); // TODO let the user decide which is the default one

#ifdef NETWORKSTACK_USE_TIMER
        timer.setup_overflow_irq();
        timer.open();
        timer.start();
#endif
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