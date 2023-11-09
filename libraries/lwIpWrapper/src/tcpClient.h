#pragma once

// forward declaration
class LWIPTCPClient;
using TCPClient = LWIPTCPClient;

// TODO define error codes in an enum

class LWIPTCPClient: Client { // : interfaces::TCPClient // TODO we probably need to import Client class definition
public:
    LWIPTCPClient();
    // LWIPTCPClient(struct tcp_struct* tcpClient); // FIXME this should be a private constructor, friend of Server

    // disable copy constructor
    LWIPTCPClient(const LWIPTCPClient&) = delete;
    void operator=(const LWIPTCPClient&) = delete;

    // keep move constructor
    LWIPTCPClient(LWIPTCPClient&&);
    void operator=(LWIPTCPClient&&);

    virtual ~LWIPTCPClient();

    uint8_t status();
    virtual int connect(IPAddress ip, uint16_t port);
    virtual int connect(const char* host, uint16_t port);
    virtual size_t write(uint8_t); // TODO implement this
    virtual size_t write(const uint8_t* buf, size_t size);
    virtual int available();
    virtual int read();
    virtual int read(uint8_t* buf, size_t size);

    // TODO define a read_callback approach, where we avoid copying data

    virtual int peek();
    virtual void flush();
    virtual void stop();
    virtual uint8_t connected();
    virtual operator bool();

    virtual bool operator==(const bool value) {
        return bool() == value;
    }
    virtual bool operator!=(const bool value) {
        return bool() != value;
    }

    // FIXME why do we need comparison operators?
    // virtual bool operator==(const lwipClient&);
    // virtual bool operator!=(const lwipClient& rhs) {
    //     return !this->operator==(rhs);
    // };
    uint8_t getSocketNumber();
    virtual uint16_t localPort() { // TODO verify this
        return (this->pcb->local_port);
    };
    virtual IPAddress remoteIP() { // TODO verify this
        return (IPAddress(this->pcb->remote_ip.addr));
    };
    virtual uint16_t remotePort() { // TODO verify this
        return (this->pcb->remote_port);
    };
    void setConnectionTimeout(uint16_t timeout) {
        _timeout = timeout;
    }

    using Print::write; // TODO understand why we need that here

private:
    enum _tcp_state_t: uint8_t {
        TCP_NONE = 0,
        // TCP_ACCEPTED,
        TCP_CONNECTED,
        TCP_CLOSING
    };

    // struct _lwip_tcp_client {
    tcp_state_t state=      TCP_NONE;
    struct pbuf* pbuf_head= nullptr;
    tcp_pcb* pcb=           nullptr;
    uint16_t pbuf_offset=   0;
    // };

    // struct _lwip_tcp_client* _tcp_client;
    uint16_t _timeout = 10000;


    err_t _connected_callback(struct tcp_pcb* tpcb, err_t err);
    void _lwip_tcp_read_free_pbuf_chain(uint16_t copied)
};