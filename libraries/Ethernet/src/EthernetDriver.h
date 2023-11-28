#pragma once

#include <stdint.h>
#include "r_ether_phy_api.h"
#include "r_ether_phy.h"
#include "r_ether_api.h"
#include "r_ether.h"
#include <functional>



enum network_driver_send_flags_t: uint8_t {
    NETWORK_DRIVER_SEND_FLAGS_NONE      = 0,
    // this option instructs the send function that it doesn't need to perform a memcpy to the passed argument
    // and is in charge of deleting the buffer
    NETWORK_DRIVER_SEND_FLAGS_ZERO_COPY = 1
};

enum network_driver_send_err_t: uint8_t {
    NETWORK_DRIVER_SEND_ERR_OK      = 0,
    NETWORK_DRIVER_SEND_ERR_MEM     = 1, // memory issues when trying to send a packet
    NETWORK_DRIVER_SEND_ERR_BUFFER  = 2, // there is no available buffer for sending the packet
    NETWORK_DRIVER_SEND_ERR_DRIVER  = 3  // generic error happening at fsp level
};


class NetworkDriver {
public:
    NetworkDriver() {};
    virtual ~NetworkDriver() {};

    /*
     * This function is used by the Interface handling the driver,
     * if used in polling mode, leave empty definition if the driver works though interrupts.
     * When working with interrupts it is expected that the constructor definces them
     */
    virtual void poll() {}; // TODO is it better to have a function pointer, that when set to null is not called?

    /*
     * This function is used to inistialize the driver at runtime and start using it
     */
    virtual void begin() = 0;

    /*
     * this function is used to send data to the network
     * + flags are used to specify additional options when sending
     * + when NETWORK_DRIVER_SEND_FLAGS_ZERO_COPY is provided, a free function must be passed, [default libc free()]
     */
    virtual network_driver_send_err_t send(uint8_t* data, uint16_t len,
        network_driver_send_flags_t flags=NETWORK_DRIVER_SEND_FLAGS_NONE,
        void(*free_function)(void*)=free) = 0;

    /*
     * Sets the callback funtion that is then used to consume incoming data
     */
    virtual void setConsumeCallback(std::function<void(uint8_t*, uint32_t)> consume_cbk) {this->consume_cbk = consume_cbk;}
    virtual void setLinkUpCallback(std::function<void()> link_up_cbk) {this->link_up_cbk = link_up_cbk;}
    virtual void setLinkDownCallback(std::function<void()> link_down_cbk) {this->link_down_cbk = link_down_cbk;}

    /*
     * FIXME define interfaces for RX zero copy
     */


    /*
     * The following functions should set the low level interface to up or down state
     */
    virtual void up() = 0;
    virtual void down() = 0;

    // TODO maybe we can manage mac address in the interface
    virtual uint8_t* getMacAddress() = 0;
    // TODO define callback functions for generic functionalities a network driver has to cope with, like link_up event
protected:
    std::function<void(uint8_t*, uint32_t)> consume_cbk; // TODO move in callbacks

    std::function<void()> tx_frame_cbk;
    std::function<void()> link_up_cbk;
    std::function<void()> link_down_cbk;
};

class EthernetC33Driver: public NetworkDriver {
public:
    EthernetC33Driver(
        uint8_t rx_descriptors_len=1,
        uint8_t tx_descriptors_len=1,
        void* (*buffer_allocator)(unsigned int)=malloc, // The allocator should return 16 byte aligned
        uint16_t buffer_size=1536,
        uint8_t* mac_address=nullptr, uint8_t len=0); // TODO provide pinmapping as parameter to the constructor
    ~EthernetC33Driver();


    /*
     * TODO define the meaning of begin: open + link up?
     */
    virtual void begin();

    // Provide a function to poll the driver
    virtual void poll();

    virtual fsp_err_t open(); // FIXME errors should be abstracted
    virtual fsp_err_t linkProcess();
    virtual void up();
    virtual void down();

    virtual network_driver_send_err_t send(uint8_t* data, uint16_t len,
        network_driver_send_flags_t flags=NETWORK_DRIVER_SEND_FLAGS_NONE,
        void(*free_function)(void*)=nullptr);


    // TODO add callbacks getters/setters
    virtual uint8_t* getMacAddress() override { return this->macaddress; }
protected:

    // extend the callbacks and add the Driver specific callbacks
    std::function<void()> wake_lan_cbk;
    std::function<void()> magic_packet_cbk;

private:
    ether_instance_descriptor_t *tx_descriptors;
    ether_instance_descriptor_t *rx_descriptors;

    uint8_t **rx_buffers;

    // array containing the info of the buffers queued to be sent
    struct _tx_buffer_info {
        uint16_t len=0;
        uint8_t* buffer=nullptr;
        void(*free_function)(void*)=nullptr;
    };
    _tx_buffer_info *tx_buffers_info;

    // tx circular buffer cursors
    uint8_t last = 0, first=0;

    // uint8_t tx_buffer[1536];
    volatile bool frame_in_transmission = false;

    // TODO macaddress setter
    uint8_t macaddress[8]; // FIXME differentiate between 6 and 8 len
    uint8_t macaddress_len = 0;

    // FSP structures for control and configuration of the driver
    ether_phy_cfg_t           phy_cfg;
    ether_phy_instance_ctrl_t phy_ctrl;
    ether_phy_instance_t      phy_instance;
    ether_cfg_t               cfg;
    ether_instance_ctrl_t     ctrl;
    ether_extended_cfg_t      extended_cfg;
    const uint32_t            irq_priority = 10;

    uint8_t rx_descriptors_len;
    uint8_t tx_descriptors_len;
    void* (*buffer_allocator)(unsigned int);
    uint16_t buffer_size;

    bool consumed = false;

    // This function initializes the driver and its configuration
    // TODO provide a way for the user to override the settings
    void init();

    // Strange function that needs to be present, for whatever reason, keeping it
    void eth_reset_due_to_ADE_bit();

    virtual void irq_ether_callback(ether_callback_args_t* p_args);
    friend void _irq_ether_callback(ether_callback_args_t* p_args);
};

extern EthernetC33Driver C33EthernetDriver;