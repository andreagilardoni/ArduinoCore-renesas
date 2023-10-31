#include <Arduino.h>
#include <Arduino_DebugUtils.h>
#include <IRQManager.h>
#include <regex>

#define CNETIF_STATS_ENABLED
#include "CNetifStats.h"

#ifdef CNETIF_STATS_ENABLED
#define STATS_BUFFER_SIZE 1000
char cnetif_stats_buffer[STATS_BUFFER_SIZE];
netif_stats _stats;
#endif // CNETIF_STATS_ENABLED

// #define ETHER_CFG_PARAM_CHECKING_ENABLE
// Renesas libraries
#include <r_ether_phy_api.h>
#include <r_ether_phy.h>
#include <r_ether_api.h>
#include <r_ether.h>

// lwip libraries
// #include <lwip/dhcp.h>
// #include <lwip/dns.h>
// #include <lwip/init.h>
// #include <lwip/ip_addr.h>
// #include <lwip/opt.h>
// #include <lwip/prot/dhcp.h>
// #include <lwip/tcp.h>
// #include <lwip/timeouts.h>
// #include <lwip/udp.h>
// #include <netif/ethernet.h>
#include <lwIP_Arduino.h>
#include <lwip/include/lwip/apps/lwiperf.h>
#include <lwip/include/lwip/tcp.h>

#include "FspTimer.h"
#include "IPAddress.h"

// IPAddress default_ip("192.168.10.130");
// IPAddress default_nm("255.255.255.0");
// IPAddress default_gw("192.168.10.1");
ip_addr_t ip;
ip_addr_t nm;
ip_addr_t gw;

#define ETHERNET_PIN_CFG ((uint32_t) ((uint32_t) IOPORT_CFG_PERIPHERAL_PIN | (uint32_t) IOPORT_PERIPHERAL_ETHER_RMII))
#define ETHERNET_CHANNEL                        (0)
#define ADE_BIT_MASK                            (1 << 23)
#define ETHER_FRAME_RECEIVED_MASK               (1UL << 18)
#define ETHER_FRAME_TRANSFER_COMPLETED          (1UL << 21)
#define ETHER_MAGIC_PACKET_DETECTED_MASK        (1UL << 1)

#define ETHERNET_BUFFER_SIZE                    1536

// typedef struct custom_pbuf {
//   struct pbuf_custom p;
//   void* payload;
//   // uint8_t* payload;
// } zerocopy_pbuf_t;
//
// void custom_pbuf_free(pbuf* p) {
//   // zerocopy_pbuf_t* pbuf = (zerocopy_pbuf_t*) p;
//
//   mem_free(p->payload);
//   p->payload = nullptr;
// }
//
// zerocopy_pbuf_t input_pbuf;

FspTimer timer;

__attribute__((__aligned__(32))) uint8_t rx_buffer0[ETHERNET_BUFFER_SIZE];
__attribute__((__aligned__(32))) uint8_t rx_buffer1[ETHERNET_BUFFER_SIZE];
__attribute__((__aligned__(32))) uint8_t rx_buffer2[ETHERNET_BUFFER_SIZE];
__attribute__((__aligned__(32))) uint8_t rx_buffer3[ETHERNET_BUFFER_SIZE];
__attribute__((__aligned__(32))) uint8_t rx_buffer4[ETHERNET_BUFFER_SIZE];
uint8_t tx_buffer[ETHERNET_BUFFER_SIZE];
uint8_t* buffers[] = {
  rx_buffer0,
  rx_buffer1,
  rx_buffer2,
  rx_buffer3,
  rx_buffer4
};

#define FRAME_NONE 0
#define FRAME_IN_TRANSMISSION 1
#define FRAME_TRANSMITTED 2

// volatile bool frame_transmitted = false;
volatile uint8_t frame_phase = FRAME_NONE;

const uint8_t tx_descriptors_len = 1;
const uint8_t rx_descriptors_len = 5;
__attribute__((__aligned__(16))) ether_instance_descriptor_t tx_descriptors[tx_descriptors_len];
__attribute__((__aligned__(16))) ether_instance_descriptor_t rx_descriptors[rx_descriptors_len];

static uint8_t macaddress[6];

const uint32_t            irq_priority = 10;
ether_phy_cfg_t           phy_cfg;
ether_phy_instance_ctrl_t phy_ctrl;
ether_phy_instance_t      phy_instance;
ether_cfg_t               cfg;
ether_instance_ctrl_t     ctrl;
ether_extended_cfg_t      extended_cfg;


struct netif netif;

#define CHECK_PAYLOAD

// #define PBUF_ALLOC_IN_INTERRUPT
// #define NETIF_INPUT_IN_INTERRUPT

#ifndef PBUF_ALLOC_IN_INTERRUPT
std::deque<std::pair<uint8_t*, uint32_t> > rx_buffers;
#endif
#if !defined(NETIF_INPUT_IN_INTERRUPT) && !defined(PBUF_ALLOC_IN_INTERRUPT)
std::deque<struct pbuf*> pbuffs;
#endif


/* --------------------------------------- */
void irq_ether_callback(ether_callback_args_t* p_args);
err_t link_output(struct netif* ni, struct pbuf *p);
err_t initEth(struct netif *);
void lwip_iperf_report_fn(void *arg, enum lwiperf_report_type report_type,
const ip_addr_t* local_addr, u16_t local_port, const ip_addr_t* remote_addr, u16_t remote_port,
u32_t bytes_transferred, u32_t ms_duration, u32_t bandwidth_kbitpsec);
void timer_cb(timer_callback_args_t *arg);
void application();
void dump_buffer(uint8_t* b, uint32_t len, uint8_t blocks=4, uint8_t cols=16);
void dump_buffer_char(uint8_t* b, uint32_t len);
void application_report(bool force=false);
bool verify_buffer_sequential_faster_4B(uint8_t *buffer, size_t len, uint32_t& offset, uint8_t *excess, uint8_t &excess_len, bool print= false);
bool verify_buffer_sequential_4B(uint8_t *buffer, size_t len, uint32_t& offset, uint8_t *excess, uint8_t &excess_len, bool print=false);
void application_final_report();
inline void input_to_netif(struct pbuf* p);
inline struct pbuf* pbuf_alloc_populate(uint8_t* buffer, uint32_t len);
uint64_t debug_start;
/* --------------------------------------- */

void setup() {
  Serial.begin(115200);
  while(!Serial);

  NETIF_STATS_INIT(_stats);

  Serial.println("Renesas ethernet example");

  const bsp_unique_id_t* t = R_BSP_UniqueIdGet();
  macaddress[0] = 0xA8;
  macaddress[1] = 0x61;
  macaddress[2] = 0x0A;
  macaddress[3] = t->unique_id_words[0] ^ t->unique_id_words[1];
  macaddress[4] = t->unique_id_words[2];
  macaddress[5] = t->unique_id_words[3];

  // setup ether phy
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_02_PIN_14, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_02_PIN_11, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_04_PIN_05, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_04_PIN_06, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_07_PIN_00, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_07_PIN_01, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_07_PIN_02, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_07_PIN_03, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_07_PIN_04, ETHERNET_PIN_CFG);
  R_IOPORT_PinCfg(&g_ioport_ctrl, BSP_IO_PORT_07_PIN_05, ETHERNET_PIN_CFG);

  // phy setup
  phy_cfg.channel                     = ETHERNET_CHANNEL;
  phy_cfg.phy_lsi_address             = 0;
  phy_cfg.phy_reset_wait_time         = 0x00020000;
  phy_cfg.mii_bit_access_wait_time    = 8;
  phy_cfg.phy_lsi_type                = ETHER_PHY_LSI_TYPE_DEFAULT;
  phy_cfg.flow_control                = ETHER_PHY_FLOW_CONTROL_DISABLE;
  phy_cfg.mii_type                    = ETHER_PHY_MII_TYPE_RMII;
  phy_cfg.p_context                   = nullptr;
  phy_cfg.p_extend                    = nullptr;

  phy_instance.p_cfg                  = &phy_cfg;
  phy_instance.p_ctrl                 = &phy_ctrl;
  phy_instance.p_api                  = &g_ether_phy_on_ether_phy;

  // setup the driver
  extended_cfg.p_rx_descriptors       = rx_descriptors;
  extended_cfg.p_tx_descriptors       = tx_descriptors;


  cfg.channel                         = ETHERNET_CHANNEL;
  cfg.zerocopy                        = ETHER_ZEROCOPY_ENABLE;
  cfg.multicast                       = ETHER_MULTICAST_ENABLE;
  cfg.promiscuous                     = ETHER_PROMISCUOUS_DISABLE;
  cfg.flow_control                    = ETHER_FLOW_CONTROL_DISABLE;
  cfg.padding                         = ETHER_PADDING_DISABLE;
  cfg.padding_offset                  = 0;
  cfg.broadcast_filter                = 0;
  cfg.p_mac_address                   = macaddress;
  cfg.num_tx_descriptors              = tx_descriptors_len;
  cfg.num_rx_descriptors              = rx_descriptors_len;
  // cfg.pp_ether_buffers                = nullptr;
  cfg.pp_ether_buffers                = buffers;
  cfg.ether_buffer_size               = ETHERNET_BUFFER_SIZE;
  cfg.irq                             = FSP_INVALID_VECTOR;
  cfg.interrupt_priority              = (irq_priority);
  cfg.p_callback                      = irq_ether_callback;
  cfg.p_ether_phy_instance            = &phy_instance;
  // cfg.p_context                       = nullptr;
  cfg.p_extend                        = &extended_cfg;

  // lwip setup
  lwip_init();

  fsp_err_t err = FSP_SUCCESS;



  // Finished setup, starting the runtime

  DEBUG_INFO("status 0x%X", ctrl.p_rx_descriptor->status);
  // Open ether
  Serial.println("Ether open");
  err = R_ETHER_Open(&ctrl, &cfg);
  if(err != FSP_SUCCESS) {
    // DEBUG_ERROR("Error opening %d", err);
    Serial.print("Error opening ");
    Serial.println(err);
  }

  // // setup buffers
  // input_pbuf.p.custom_free_function = custom_pbuf_free;
  // // input_pbuf.payload = mem_malloc(ETHERNET_BUFFER_SIZE);
  // input_pbuf.payload = rx_buffer;
  //
  // if(input_pbuf.payload == nullptr) {
  //   DEBUG_ERROR("Error allocing the input buffer");
  //   return;
  // }
  // DEBUG_INFO("buffer at 0x%X, status 0x%x", input_pbuf.payload, ctrl.p_rx_descriptor->status);
  // err = R_ETHER_RxBufferUpdate(&ctrl, input_pbuf.payload);
  // DEBUG_INFO("status 0x%X", ctrl.p_rx_descriptor->status);
  //
  // if(err != FSP_SUCCESS) {
  //   DEBUG_ERROR("Error setting zero copy buffer: %d", err);
  //   return;
  // }

  // HAL_ETH_ReadPHYRegister(&EthHandle, PHY_IMR, &regvalue);
  //
  // regvalue |= PHY_ISFR_INT4;
  //
  // /* Enable Interrupt on change of link status */
  // HAL_ETH_WritePHYRegister(&EthHandle, PHY_IMR, regvalue);

  bool rv = IRQManager::getInstance().addPeripheral(IRQ_ETHERNET, &cfg);
  if(rv) {
    cfg.interrupt_priority = irq_priority;
    R_BSP_IrqCfgEnable(cfg.irq, cfg.interrupt_priority, &ctrl); /* ??? */
  } else {
    DEBUG_ERROR("Error setting up irq for ethernet");
    return;
  }

  // wait until link up
  do {
    err = R_ETHER_LinkProcess(&ctrl);
  } while(err != FSP_SUCCESS);
  DEBUG_INFO("Link up");

  // setup netif
  IP_ADDR4(&ip, 192, 168, 10, 130);
  IP_ADDR4(&nm, 255, 255, 255, 0);
  IP_ADDR4(&gw, 192, 168, 10, 1);

  DEBUG_INFO("Setting up netif");
  netif_add(&netif, &ip, &nm, &gw, NULL, initEth, ethernet_input);
  netif_set_default(&netif);

  netif_set_link_up(&netif);
  netif_set_up(&netif);
  // initEth(&netif);
  DEBUG_INFO("Begin of reception\n\n");
  debug_start = millis();

  // Run the sys_check_timeouts in a timer callback
  // uint8_t type = 8;
  // int8_t ch = FspTimer::get_available_timer(type);

  // if (ch < 0) {
  //     ch = FspTimer::get_available_timer(type, true);
  // }

  // timer.begin(TIMER_MODE_PERIODIC, type, ch, 1000.0, 50.0, timer_cb);
  // timer.setup_overflow_irq();
  // timer.open();
  // timer.start();
}

void loop() {
  // __disable_irq();
  uint64_t start = micros();
  // Poll the driver for data

#if !defined(NETIF_INPUT_IN_INTERRUPT) && !defined(PBUF_ALLOC_IN_INTERRUPT)
  __disable_irq();
  bool not_empty = !rx_buffers.empty();
  bool release = rx_buffers.size() == 5;
  NETIF_STATS_CUSTOM_AVERAGE(_stats, "size", rx_buffers.size());
  // if(not_empty) {
  //   Serial.print("->");
  // }
  for(; !not_empty; rx_buffers.pop_front()) {
    auto pair = rx_buffers.front();

    struct pbuf *p = pbuf_alloc_populate(pair.first, pair.second);

    if(release) {
      R_ETHER_BufferRelease(&ctrl);
    }
    if(p!=nullptr) {
      input_to_netif(p);
    }
  }
  __enable_irq();
#elif !defined(NETIF_INPUT_IN_INTERRUPT) && defined(PBUF_ALLOC_IN_INTERRUPT)
  for(; !pbuffs.empty(); pbuffs.pop_front()) {
    input_to_netif(pbuffs.front());
  }
#endif

  // NETIF_STATS_CUSTOM_AVERAGE_UNIT(_stats, "input", micros()-start, "us");
  // start = micros();
  // check lwip timeouts
  // Serial.print(">>");
  sys_check_timeouts();

  // NETIF_STATS_CUSTOM_AVERAGE_UNIT(_stats, "timeouts", micros()-start, "us");
  // start = micros();

  // Handle application FSM
  application();

  if(millis() - debug_start > 2000) { // print the debug _stats every 1 second
    application_report();

#ifdef CNETIF_STATS_ENABLED
    netif_stats_sprintf(cnetif_stats_buffer, _stats, STATS_BUFFER_SIZE, (8*1e6)/(1<<20), "Mbit/s");
    __disable_irq();
    NETIF_STATS_RESET_AVERAGES(_stats);
    __enable_irq();
    DEBUG_INFO(cnetif_stats_buffer);
#endif // CNETIF_STATS_ENABLED

    // reset some counters
    debug_start = millis();
  }

  uint64_t elapsed = micros()-start;
  // NETIF_STATS_CUSTOM_AVERAGE_UNIT(_stats, "cycle", elapsed, "us");

  float sleep = 0.015 - float(elapsed)/1000;
  // DEBUG_INFO("%.6f", sleep);
  if(sleep > 0) {
    delay(sleep);
  }
}

// Driver Stuff
err_t initEth(struct netif *_ni) {
  // Setting up netif
  _ni->hostname                       = "C33_eth";
  _ni->name[0]                        = 'e';
  _ni->name[1]                        = 't';
  _ni->mtu                            = 1500;
  _ni->flags                          |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
  // _ni->flags         = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;

  memcpy(_ni->hwaddr, macaddress, sizeof(macaddress));
  _ni->hwaddr_len                     = sizeof(macaddress);

  _ni->output                         = etharp_output;
  _ni->linkoutput                     = link_output;

  // lwiperf_start_tcp_server_default(lwip_iperf_report_fn, NULL);

  return ERR_OK;
}

inline void _read_from_buffer_end(const fsp_err_t &err, bool release=true) {
  NETIF_STATS_INCREMENT_ERROR(_stats, err);

  if(release) {
    R_ETHER_BufferRelease(&ctrl);
  }

  NETIF_STATS_RX_TIME_AVERAGE(_stats);
  NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(_stats);
  __enable_irq();
}

void read_from_buffer() {
  __disable_irq();
  NETIF_STATS_RX_TIME_START(_stats);

  uint32_t rx_frame_dim = 0;
  uint8_t* rx_frame_buf = nullptr;
  fsp_err_t err = R_ETHER_Read(&ctrl, &rx_frame_buf, &rx_frame_dim);

  if (err != FSP_SUCCESS) {
    NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(_stats);

    _read_from_buffer_end(err);
    return;
  }

#ifdef PBUF_ALLOC_IN_INTERRUPT
  struct pbuf* p=pbuf_alloc_populate(rx_frame_buf, rx_frame_dim);
  if(p==nullptr){
    _read_from_buffer_end(err);
    return;
  }
#else
  // Version 0: just push the reference to the buffer inside of the deque
  rx_buffers.push_back(std::pair(rx_frame_buf, rx_frame_dim));

  // Version 0 variant a: release the buffer only when there are less than 5 buffers in the deque
  if(rx_buffers.size() == rx_descriptors_len) {
    _read_from_buffer_end(err, false);
    return;
  }

  // Version 1: create a new array and push it to the deque
  //   variant a: allocate it with clib malloc
  //   variant b: allocate it with lwip mem_malloc
  // uint8_t* buf = (uint8_t*)malloc(rx_frame_dim);
  // uint8_t* buf = (uint8_t*)mem_malloc(rx_frame_dim);
  // memcpy(buf, rx_frame_buf, rx_frame_dim);

  // if(buf != nullptr) {
    // rx_buffers.push_back(std::pair(buf, rx_frame_dim));
  // }

#endif

#if defined(NETIF_INPUT_IN_INTERRUPT) && defined(PBUF_ALLOC_IN_INTERRUPT)
  input_to_netif(p);
#elif defined(PBUF_ALLOC_IN_INTERRUPT)
  pbuffs.push_back(p);
#endif

  _read_from_buffer_end(err);
  return;
}

inline struct pbuf* pbuf_alloc_populate(uint8_t* buffer, uint32_t len) {
  struct pbuf* p=nullptr;

  p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);

  if (p == nullptr) {
    NETIF_STATS_INCREMENT_RX_PBUF_ALLOC_FAILED_CALLS(_stats);
    NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(_stats);
  } else {
    /* Copy ethernet frame into pbuf */
    pbuf_take((struct pbuf*)p, (uint8_t*)buffer, (uint32_t)len);
  }

  return p;
}

inline void input_to_netif(struct pbuf* p) {
  if (netif.input((struct pbuf*)p, &netif) != ERR_OK) {
    pbuf_free((struct pbuf*)p);

    NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(_stats);
    NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(_stats);
  } else {
    NETIF_STATS_INCREMENT_RX_BYTES(_stats, p->len);
  }
}

err_t link_output(struct netif* _ni, struct pbuf *p) {
  (void)_ni;

  err_t errval = ERR_OK;
  NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(_stats);
  NETIF_STATS_TX_TIME_START(_stats);

  if(frame_phase == FRAME_IN_TRANSMISSION) {
    errval = ERR_INPROGRESS;
    NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(_stats);
  } else {
    // TODO analyze the race conditions that may arise from sharing a non synchronized buffer
    uint8_t *tx_buf = tx_buffer;
    uint16_t tx_buf_dim = ETHERNET_BUFFER_SIZE;
    assert (p->tot_len <= tx_buf_dim);

    uint16_t bytes_actually_copied = pbuf_copy_partial(p, tx_buf, p->tot_len, 0);
    fsp_err_t err = R_ETHER_Write(&ctrl, tx_buf, bytes_actually_copied);

    if (bytes_actually_copied > 0 && err != FSP_SUCCESS) {
      errval = ERR_IF;
      NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(_stats);
    } else {
      NETIF_STATS_INCREMENT_TX_BYTES(_stats, bytes_actually_copied);
    }
  }

  NETIF_STATS_TX_TIME_AVERAGE(_stats);
  return errval;
}

void timer_cb(timer_callback_args_t *arg) {
  (void)arg;
  sys_check_timeouts();
}

void reset_due_to_ADE_bit() {
  uint32_t *EDMAC_EESR_REG = (uint32_t *)0x40114028;
  uint32_t *EDMAC_CONTROL_REG = (uint32_t *)0x40114000;
  if( (*EDMAC_EESR_REG & ADE_BIT_MASK) == ADE_BIT_MASK) {
    R_ETHER_Close(&ctrl);
    *EDMAC_CONTROL_REG |= 0x1;
    R_ETHER_Open(&ctrl, &cfg);
  }
}

void irq_ether_callback(ether_callback_args_t* p_args){
  p_args->status_ecsr;
  uint32_t reg_eesr = p_args->status_eesr;
  if(p_args->channel == ETHERNET_CHANNEL) {
    if(p_args->event == ETHER_EVENT_WAKEON_LAN) {
      /* WAKE ON */
      // if(lan_wake_up != nullptr) {
      //     lan_wake_up();
      // }
    } else if(p_args->event == ETHER_EVENT_LINK_ON) {
      // /* LINK ON */
      // if(link_on != nullptr) {
      //     link_on();
      // }
    } else if(p_args->event == ETHER_EVENT_LINK_OFF) {
      /* LINK OFF */
      // if(link_off != nullptr) {
      //     link_off();
      // }
    } else if(p_args->event == ETHER_EVENT_INTERRUPT) {
      if (ETHER_MAGIC_PACKET_DETECTED_MASK == (p_args->status_ecsr & ETHER_MAGIC_PACKET_DETECTED_MASK)) {
        // /* MAGIC PACKET DETECTED */
        // if(magic_packet_received != nullptr) {
        //     magic_packet_received();
        // }
      }
      if (ETHER_FRAME_TRANSFER_COMPLETED == (reg_eesr & ETHER_FRAME_TRANSFER_COMPLETED)) {
        frame_phase = FRAME_TRANSMITTED;
      }
      if (ETHER_FRAME_RECEIVED_MASK == (reg_eesr & ETHER_FRAME_RECEIVED_MASK)) {
        /* FRAME RECEIVED */
        read_from_buffer();
      }
      if( (reg_eesr & ADE_BIT_MASK) == ADE_BIT_MASK) {
        /* weird error with ADE bit set as soon as reception is enabled */
        reset_due_to_ADE_bit();
      }
    } else {
    }
  }
}

void lwip_iperf_report_fn(void *arg, enum lwiperf_report_type report_type,
  const ip_addr_t* local_addr, u16_t local_port, const ip_addr_t* remote_addr, u16_t remote_port,
  u32_t bytes_transferred, u32_t ms_duration, u32_t bandwidth_kbitpsec){
  LWIP_UNUSED_ARG(arg);
  LWIP_UNUSED_ARG(local_addr);
  LWIP_UNUSED_ARG(local_port);

  DEBUG_INFO("IPERF report: type=%d, remote: %s:%d, total bytes: %d, duration in ms: %d, kbits/s: %d\n",
    (int)report_type, ipaddr_ntoa(remote_addr), (int)remote_port, bytes_transferred, ms_duration, bandwidth_kbitpsec);
}

// TCP stuff
enum tcp_state_t: uint8_t {
  TCP_NONE = 0,
  // TCP_ACCEPTED,
  TCP_CONNECTED,
  TCP_CLOSING
};

struct TCPClient {
  tcp_state_t state;
  struct pbuf* p=nullptr;
  tcp_pcb* pcb;
  uint16_t pbuf_offset=0;
};

err_t lwip_tcp_connected_callback(void* arg, struct tcp_pcb* tpcb, err_t err);
err_t lwip_tcp_recv_callback(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err);
err_t lwip_tcp_sent_callback(void* arg, struct tcp_pcb* tpcb, u16_t len);
void lwip_tcp_err_callback(void *arg, err_t err);
void lwip_tcp_connection_close(struct tcp_pcb* tpcb, struct tcp_struct* tcp);

err_t lwip_tcp_setup_stack(struct TCPClient* client) {
  err_t err = ERR_OK;
  client->pcb = tcp_new();

  if(client->pcb == nullptr) {
    // return ; // TODO find the proper error code
    return err;
  }

  tcp_err(client->pcb, lwip_tcp_err_callback);

  return err;
}

err_t lwip_tcp_connect(struct TCPClient* client, const ip_addr_t *ip_addr, uint16_t port) {
  err_t err = ERR_OK;

  // err = tcp_bind(
  //   pcb, IP_ANY_TYPE, 9999 // FIXME find a way to get a port number
  // );

  if(err != ERR_OK) {
    return err;
  }

  client->state = TCP_NONE;

  tcp_arg(client->pcb, client);

  err = tcp_connect(
    client->pcb, ip_addr, port,
    lwip_tcp_connected_callback
  );

  return err;
}

// copy a buffer from the app level to the send buffer of lwip
// TODO understand how to handle a zero copy mode
size_t lwip_tcp_send_buffer(struct TCPClient* client, uint8_t* buffer, size_t size) {
  uint8_t* buffer_cursor = buffer;
  uint8_t bytes_to_send = 0;

  do {
    bytes_to_send = min(size - (buffer - buffer_cursor), tcp_sndbuf(client->pcb));
    err_t res = tcp_write(client->pcb, buffer_cursor, bytes_to_send, TCP_WRITE_FLAG_COPY);

    if(res == ERR_OK) {
      buffer_cursor += bytes_to_send;
    } else if(res == ERR_MEM) {
      // we get into this case only if the sent data cannot be put in the send queue
    }

    // TODO understand if the tcp_write will send data if the buffer is not full
    // force send only if we filled the send buffer
    if (ERR_OK != tcp_output(client->pcb)) {
      // return 0;
      break;
    }
  } while(buffer_cursor < buffer + size);

  return buffer - buffer_cursor;
}

// this function checks the input parameters and return true if they are not valid
inline bool lwip_tcp_read_checks(struct TCPClient* client, uint8_t* buffer, uint16_t buffer_size) {
  // DEBUG_INFO("CHECK: size %6u, buf %08x, client %08x, pbuf %08x", buffer_size, buffer, client, client->p);

  return (buffer_size==0 || buffer==nullptr || client==nullptr || client->p==nullptr);
}

// copy data from lwip buffers to the application level
// FIXME consider synchronization issues while calling this function, interrupts may cause issues
uint16_t lwip_tcp_read_buffer(struct TCPClient* client, uint8_t* buffer, uint16_t buffer_size) {

  if(lwip_tcp_read_checks(client, buffer, buffer_size)) {
    return 0; // TODO extend checks
  }
  // copy data from the lwip buffer to the app provided buffer
  // TODO look into pbuf_get_contiguous(client->p, buffer_cursor, len);

  /*
   * a chain of pbuf is not granted to have a size multiple of buffer_size length
   * meaning that across different calls of this function a pbuf could be partially copied
   * we need to account that
   */
  uint16_t copied = pbuf_copy_partial(client->p, buffer, buffer_size, client->pbuf_offset);

  lwip_tcp_read_free_pbuf_chain(client, copied);

  return copied;
}

uint16_t lwip_tcp_read_buffer_until_token(struct TCPClient* client, uint8_t* buffer, uint16_t buffer_size, char* token, bool &found) {

  if(lwip_tcp_read_checks(client, buffer, buffer_size)) {
    return 0; // TODO extend checks and make them a general inline function
  }

  // TODO check that the buffer size is less than the token len

  uint16_t offset=client->pbuf_offset;
  /* iterate over pbufs until:
   * - the first occurrence of token
   * - the provided buffer is full
   * - the available pbufs have been consumed
   */
  size_t tkn_len = strlen(token);

  // FIXME if we have already found the token we hare wasting time to check the entire buffer again
  uint16_t position = pbuf_memfind(client->p, token, tkn_len, client->pbuf_offset); // TODO check efficiency of this function
  uint16_t buf_copy_len = buffer_size;

  // TODO triple check the indices of these conditions
  if(position != 0xffff && position + tkn_len <= buffer_size) { // TODO consider how to handle the case that the chain is long 0xffff
    // We found the token and it fits the user provided buffer
    buf_copy_len = position + tkn_len;
    found = true;
  } else if(position != 0xffff && position < buffer_size && position + tkn_len > buffer_size) {
    // if the token is found and fits partially with the user provided buffer
    buf_copy_len = position - 1; // copy without consuming the token
    found = false;
  } else {
    /*
     * we cover 2 cases here:
     * - we didn't find the token
     * - we found the token, but it doesn't fit the user provided buffer
     */
    found = false;
  }

  uint16_t copied = pbuf_copy_partial(client->p, buffer, buf_copy_len, client->pbuf_offset);

  lwip_tcp_read_free_pbuf_chain(client, copied);

  return copied;
}

inline void lwip_tcp_read_free_pbuf_chain(struct TCPClient* client, uint16_t copied) {
  /*
   * free pbufs that have been copied, if copied == 0 we have an error
   * free the buffer chain starting from the head up to the last entire pbuf ingested
   * taking into account the previously not entirely consumed pbuf
   */
  uint32_t tobefreed = 0;
  // DEBUG_INFO("cleaning up");
  copied += client->pbuf_offset;

  // in order to clean up the chain we need to find the pbuf in the last pbuf in the chain
  // that got completely consumed by the application, dechain it from it successor and delete the chain before it

  struct pbuf *head = client->p, *last=head, *prev=nullptr; // FIXME little optimization prev can be substituted by last->next

  while(last!=nullptr && last->len + tobefreed <= copied) {
    tobefreed += last->len;
    prev = last;
    last = last->next;
  }

  // dechain if we are not at the end of the chain (last == nullptr)
  // and if we haven't copied entirely the first pbuf (prev == nullptr) (head == last)
  // if we reached the end of the chain set the client pbuf pointer to nullptr
  if(prev != nullptr && last != nullptr) {
    pbuf_ref(last); // increase the reference of the last element, in order for it to not get freed
    client->p = pbuf_dechain(prev);
  } if(last == nullptr) {
    client->p = nullptr;
  }

  // the chain that is referenced by head is detached by the one referenced by client->p
  // free the chain if we haven't copied entirely the first pbuf (prev == nullptr)
  if(client->p != head) {
    uint8_t refs = pbuf_free(head);

    // DEBUG_INFO("Freed: %2u", refs);
  }

  client->pbuf_offset = copied - tobefreed; // This offset should be referenced to the first pbuf in queue

  // acknowledge the received data
  tcp_recved(client->pcb, copied);
}

void lwip_tcp_err_callback(void *arg, err_t err) {
  TCPClient* tcp_arg = (TCPClient*)arg;

  DEBUG_ERROR("TCP Error collected: %d", err);
}

err_t lwip_tcp_connected_callback(void* arg, struct tcp_pcb* tpcb, err_t err) {
  TCPClient* tcp_arg = (TCPClient*)arg;

  if(err != ERR_OK) {
    lwip_tcp_connection_close(tpcb, tcp_arg);
    return err;
  }

  if(tcp_arg == NULL) {
    // Setup was not performed correctly and the arg was not setup properly
    lwip_tcp_connection_close(tpcb, tcp_arg);
    return ERR_ARG;
  }

  tcp_arg->state = TCP_CONNECTED;

  /* initialize LwIP tcp_recv callback function */
  tcp_recv(tpcb, lwip_tcp_recv_callback);

  /* initialize LwIP tcp_sent callback function */
  tcp_sent(tpcb, lwip_tcp_sent_callback);

  /* initialize LwIP tcp_err callback function */
  // tcp_err(tpcb, lwip_tcp_err_callback);

  // TODO try to use application level polling
  // tcp_poll(tpcb, NULL, 0);

  return err;
}

err_t lwip_tcp_recv_callback(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
  TCPClient* tcp_arg = (TCPClient*)arg;
  err_t ret_err = ERR_OK;

  if(err != ERR_OK) {
    lwip_tcp_connection_close(tpcb, tcp_arg);
    return err;
  }

  if(tcp_arg == NULL) {
    // Setup was not performed correctly and the arg was not setup properly
    lwip_tcp_connection_close(tpcb, tcp_arg);
    return ERR_ARG;
  }

  if (p == NULL) {
    // Remote host has closed the connection -> close from our side
    lwip_tcp_connection_close(tpcb, tcp_arg);
    return ERR_OK;
  }

  if(tcp_arg->state == TCP_CONNECTED) {
    __disable_irq();
    if (tcp_arg->p == nullptr) {
      // pbuf_ref(p);
      // DEBUG_INFO("first element in pbuf chain, refs: %u", p->ref);
      tcp_arg->p = p;
    } else {
      // DEBUG_INFO("pbuf_cat %u, %u, %X", tcp_arg->p->len, tcp_arg->p->tot_len, tcp_arg->p->next);
      // pbuf_chain(tcp_arg->p, p); // we have to use chain, because tcp_arg->p counts as a reference of the chain

      // no need to increment the references of p, since it is already 1 and the only reference is tcp_arg->p->next
      pbuf_cat(tcp_arg->p, p);
    }
    __enable_irq();


    ret_err = ERR_OK;
  }

  // DEBUG_INFO("head %08x, tot_len %6u New pbuf: %08x next %08x len %6u tot_len %6u", tcp_arg->p, tcp_arg->p->tot_len, p, p->next, p->len, p->tot_len);

  return ret_err;
}

err_t lwip_tcp_sent_callback(void* arg, struct tcp_pcb* tpcb, u16_t len) {
  TCPClient* tcp_arg = (TCPClient*)arg;
}

void lwip_tcp_connection_close(struct tcp_pcb* tpcb, struct TCPClient* tcp) {
  tcp_recv(tpcb, NULL);
  tcp_sent(tpcb, NULL);
  tcp_poll(tpcb, NULL, 0);
  tcp_err(tpcb, NULL);
  tcp_accept(tpcb, NULL);

  err_t err = tcp_close(tpcb);
  // TODO if err != ERR_OK retry, there may be memory issues
  tcp->state = TCP_CLOSING;

  if(tcp->p != nullptr) {
    // pbuf_free(tcp->p); // FIXME it happens that a pbuf, with ref == 0 is added for some reason
  }
}

// Application level Stuff
enum app_state_t: uint8_t {
  APP_STATE_NONE = 0,
  APP_STATE_LINK_UP,
  APP_STATE_LINK_DOWN,
  APP_STATE_CONNECTING,
  APP_STATE_CONNECTED,
  APP_STATE_PARSE_HEADER,
  APP_STATE_DOWNLOAD,
  APP_STATE_DOWNLOAD_FAILED,
  APP_STATE_DOWNLOAD_FINISHED,
  APP_STATE_ERROR,
  APP_STATE_RESET
};

static const char* state_strings[] = {
  "APP_STATE_NONE",
  "APP_STATE_LINK_UP",
  "APP_STATE_LINK_DOWN",
  "APP_STATE_CONNECTING",
  "APP_STATE_CONNECTED",
  "APP_STATE_PARSE_HEADER",
  "APP_STATE_DOWNLOAD",
  "APP_STATE_DOWNLOAD_FAILED",
  "APP_STATE_DOWNLOAD_FINISHED",
  "APP_STATE_ERROR",
  "APP_STATE_RESET"
};

#define APP_BUFFER_SIZE 10*1024


struct App {
  app_state_t current_state=APP_STATE_NONE;
  app_state_t prev_state=APP_STATE_NONE;

  TCPClient *tcp_client;
  uint16_t port = 8000;
  ip_addr_t server_ip;

  uint8_t buffer[APP_BUFFER_SIZE];

  size_t file_length=0;
  size_t downloaded_bytes=0;
  std::string http_header;

  // stats related variables
  uint32_t start = 0;
  uint32_t speed_start = 0;
  uint32_t speed_bytes = 0;

  // payload verification parameters
  uint32_t payload_verify_offset=0;
  uint8_t payload_verify_excess[4]={}; // this should be 3, but there are bugs
  uint8_t payload_verify_excess_len=0;
  uint32_t last_value=0;
} app;

void init_app(struct App& app) {
  app.file_length = 0;
  app.http_header = "";
  app.downloaded_bytes = 0;
  app.start = 0;
  app.payload_verify_excess_len = 0;
  app.payload_verify_offset = 0;
  app.last_value=0;
}

void reset_app(struct App& app) {
  init_app(app);

  // close the TCP connection and http session if open
  if(app.tcp_client != nullptr && app.tcp_client->state != TCP_CLOSING) {
    lwip_tcp_connection_close(app.tcp_client->pcb, app.tcp_client);
  }

  if(app.tcp_client != nullptr) {
    delete app.tcp_client;
    app.tcp_client = nullptr;
  }
}

const char* http_request = "GET /test-256M HTTP/1.1\nHost: 192.168.10.250\nConnection: close\n\n";

void application() {
  bool found = false;
  uint16_t bytes_read=0;

  switch(app.current_state) {
  case APP_STATE_NONE:
    init_app(app);

    // TODO we are not handling link connection and disconnection
    app.prev_state = app.current_state;
    app.current_state = APP_STATE_LINK_UP;
    DEBUG_INFO("State changed: to %s, from %s",
      state_strings[app.current_state],
      state_strings[app.prev_state]);
    break;

  case APP_STATE_LINK_UP:
    // The link is up we connect to the server
    app.tcp_client = new TCPClient;
    lwip_tcp_setup_stack(app.tcp_client);

    // Connection details:
    // TODO define somewhere else server address and port
    IP_ADDR4(&app.server_ip, 192, 168, 10, 250);

    lwip_tcp_connect(app.tcp_client, &app.server_ip, app.port);

    app.prev_state = app.current_state;
    app.current_state = APP_STATE_CONNECTING;
    DEBUG_INFO("State changed: to %s, from %s",
      state_strings[app.current_state],
      state_strings[app.prev_state]);
    break;

  case APP_STATE_CONNECTING:
    // do nothing, until the TCP connection is established
    // TODO handle timeout for connection and go to error state
    if(app.tcp_client->state == TCP_CONNECTED) {
      app.prev_state = app.current_state;
      app.current_state = APP_STATE_CONNECTED;
      DEBUG_INFO("State changed: to %s, from %s",
        state_strings[app.current_state],
        state_strings[app.prev_state]);
    }

    break;

  case APP_STATE_CONNECTED:
    lwip_tcp_send_buffer(app.tcp_client, (uint8_t*)http_request, strlen(http_request));
    app.start = millis();
    app.speed_start = app.start;

    app.prev_state = app.current_state;
    app.current_state = APP_STATE_PARSE_HEADER;
    DEBUG_INFO("State changed: to %s, from %s",
      state_strings[app.current_state],
      state_strings[app.prev_state]);
    break;

  case APP_STATE_PARSE_HEADER:
    bytes_read = lwip_tcp_read_buffer_until_token(app.tcp_client, app.buffer, APP_BUFFER_SIZE, "\r\n\r\n", found);

    if(bytes_read>0) {
      // put the buffer into an http header string
      std::string chunk((char*)app.buffer, bytes_read);
      app.http_header += chunk;
      app.speed_bytes += bytes_read;
    }

    if(found) { // FIXME reduce indentation level
      // we found the http terminating token, go to the next app phase if we extracted the file len
      // otherwise go in error phase

      // Parse the http header and gather information needed for the download
      // dump_buffer_char(app.buffer, APP_BUFFER_SIZE);

      std::regex content_length_regex("Content-Length: ([0-9]+)", std::regex::icase);
      std::smatch matches;

      // DEBUG_INFO(app.http_header.c_str());

      if(std::regex_search(app.http_header, matches, content_length_regex)) {
        app.file_length = stoi(matches[1].str());

        DEBUG_INFO("Download started, file length: %u", app.file_length);

        app.prev_state = app.current_state;
        app.current_state = APP_STATE_DOWNLOAD;
        DEBUG_INFO("State changed: to %s, from %s",
          state_strings[app.current_state],
          state_strings[app.prev_state]);
      } else {
        // Failed to extract the content length from the header, going into an error state
        // TODO report the reason of the error

        app.prev_state = app.current_state;
        app.current_state = APP_STATE_ERROR;
        DEBUG_INFO("State changed: to %s, from %s",
          state_strings[app.current_state],
          state_strings[app.prev_state]);
      }
    }
    break;
  case APP_STATE_DOWNLOAD:
    if(app.tcp_client->p == nullptr) { // no data available
      break;
    }
    // DEBUG_INFO("reading: tot_len %6u, offset %6u", app.tcp_client->p->tot_len, app.tcp_client->pbuf_offset);
    bytes_read = lwip_tcp_read_buffer(app.tcp_client, app.buffer, APP_BUFFER_SIZE);
    // DEBUG_INFO("read %6u", bytes_read);

    if(bytes_read > 0) {
      app.downloaded_bytes += bytes_read;
      app.speed_bytes += bytes_read;

      // dump_buffer(app.buffer, APP_BUFFER_SIZE, 4, 128);
#ifdef CHECK_PAYLOAD
      // if(!verify_buffer_sequential_4B(
      if(!verify_buffer_sequential_faster_4B(
        app.buffer,
        bytes_read,
        app.payload_verify_offset,
        app.payload_verify_excess,
        app.payload_verify_excess_len,
        false)) {

        DEBUG_INFO("Payload verification failed");
        app.prev_state = app.current_state;
        app.current_state = APP_STATE_DOWNLOAD_FAILED;
        DEBUG_INFO("State changed: to %s, from %s",
          state_strings[app.current_state],
          state_strings[app.prev_state]);
      }
#endif // CHECK_PAYLOAD
    }

    if(app.downloaded_bytes == app.file_length) {
      app.last_value =
        *(app.buffer + bytes_read - 4) << 24 |
        *(app.buffer + bytes_read - 3) << 16 |
        *(app.buffer + bytes_read - 2) << 8  |
        *(app.buffer + bytes_read - 1);

      // if the download of the counter file is correct the last value should be
      // the size of the file/4 -1
      if(app.last_value == (app.downloaded_bytes/4 - 1)) {
        app.prev_state = app.current_state;
        app.current_state = APP_STATE_DOWNLOAD_FINISHED;
        DEBUG_INFO("State changed: to %s, from %s",
          state_strings[app.current_state],
          state_strings[app.prev_state]);
      } else {
        app.prev_state = app.current_state;
        app.current_state = APP_STATE_DOWNLOAD_FAILED;
        DEBUG_INFO("State changed: to %s, from %s",
          state_strings[app.current_state],
          state_strings[app.prev_state]);
      }
    }
    break;

  case APP_STATE_DOWNLOAD_FAILED:
    // TODO report error in file download and close the connection
    app.prev_state = app.current_state;
    app.current_state = APP_STATE_ERROR;
    DEBUG_INFO("State changed: to %s, from %s",
      state_strings[app.current_state],
      state_strings[app.prev_state]);
    break;

  case APP_STATE_DOWNLOAD_FINISHED:
    DEBUG_INFO("Download finished: %uMB", app.downloaded_bytes>>20);
    DEBUG_INFO("Last value in the buffer: 0x%08X", app.last_value);
    application_final_report();

    app.prev_state = app.current_state;
    app.current_state = APP_STATE_RESET;
    DEBUG_INFO("State changed: to %s, from %s",
      state_strings[app.current_state],
      state_strings[app.prev_state]);
    break;

  case APP_STATE_ERROR:
    // The app reached an expected error state
    // TODO report this state and go in the default, status not defined handler to reset the state
  case APP_STATE_RESET:
    // in this state we reset the application and we start back from the beginning

    reset_app(app);

    app.prev_state = app.current_state;
    app.current_state = APP_STATE_LINK_UP;
    DEBUG_INFO("State changed: to %s, from %s",
      state_strings[app.current_state],
      state_strings[app.prev_state]);
    break;
  }
}

// application stats
void application_report(bool force) {
  if(force || app.current_state == APP_STATE_PARSE_HEADER || app.current_state == APP_STATE_DOWNLOAD) {

    // float speed_conversion_factor = 1e3/(1<<10);
    float speed_conversion_factor = 8*1e3/float(1<<20);
    float elapsed = millis()-app.speed_start;

    float speed = (app.speed_bytes / elapsed) * speed_conversion_factor;
    DEBUG_INFO("Application layer: %12u/%12u speed: %.2f Mbit/s", app.downloaded_bytes, app.file_length, speed);

    app.speed_start = millis();
    app.speed_bytes = 0;
  }
}

void application_final_report() {
  // float speed_conversion_factor = 10e3/(1<<10);
  float speed_conversion_factor = 1e3*8/float(1<<20);

  float speed = (app.downloaded_bytes / (millis()-app.start) ) * speed_conversion_factor;
  DEBUG_INFO("Average application layer speed: %.2f Mbit/s", speed);
}

// payload checking function
bool verify_buffer_sequential_4B(uint8_t *buffer, size_t len, uint32_t& offset, uint8_t *excess, uint8_t &excess_len, bool print) {
  size_t i=0;
  bool res = true;
  uint32_t value=0, first=0;

  if(excess_len > 0) {
    uint8_t j=0;
    for(; j<excess_len; j++) {
      value |= excess[j] << ((3-j)*8);
    }

    for(; j<4 && i<len; j++,i++) {
      value |= buffer[i] << ((3-j)*8);

      if(excess_len < 3) {
        excess[j] = buffer[i];
        excess_len++;
      }
    }

    if(value != offset) {
      DEBUG_INFO("perror %08X, %08X", value, offset);

      res = false;
    }
    offset++;
    first = value;
  }

  for(; i+4<=len; i+=4,offset++) {
    // convert buffer from big endian bytearray to uint32
    value =
      *(buffer+i)   << 24 |
      *(buffer+i+1) << 16 |
      *(buffer+i+2) << 8  |
      *(buffer+i+3);

    if(first == 0) {
      first = value;
    }
    // if(print) {
    //   DEBUG_INFO("value: %X", value);
    // }

    if(value != offset && res) {
      DEBUG_INFO("error %8X, %8X", value, offset);

      res = false;
    }
  }

  // put the bytes that exceed the modulo4 in the excess array
  excess_len = len - i;
  for(uint8_t j=0; i<len; j++,i++){
    excess[j] = buffer[i];
  }

  if(print) {
    DEBUG_INFO("packet First: %08X LAST %08X", first, value);
  }


  return res;
}

bool verify_buffer_sequential_faster_4B(uint8_t *buffer, size_t len, uint32_t& offset, uint8_t *excess, uint8_t &excess_len, bool print) {
  size_t i=0;
  bool res = true;
  uint32_t first=0;

  if(excess_len > 0) {
    // the first value needs to be taken from the excess bytes of the previous buffer and the first of this
    uint8_t j=0;
    for(; j<excess_len; j++) {
      first |= excess[j] << ((3-j)*8);
    }

    for(; j<4 && i<len; j++,i++) {
      first |= buffer[i] << ((3-j)*8);
    }
  } else {
    // the first value needs to be taken from the current buffer
    for(; i<4; i++) {
      first |= buffer[i] << ((3-i)*8);
    }
  }

  // DEBUG_INFO("verify: found %08X, expected %08X, i %1u len %8u, excess_len %1u", first, offset, i, len, excess_len);
  if(first != offset) {
    DEBUG_INFO("perror: found %08X, expected %08X", first, offset);

    res = false;
  }
  // offset++;

  // After reconstructing the first integer, we can skip the verification of the rest of the payload,
  // assuming that the issues are always caused by a missing section between buffers.
  // This means that we only need to verify the first value, and update the value for offset

  // The len of the returned excess is the following:
  uint8_t new_excess_len = (len+excess_len) % 4;
  i = len - new_excess_len;
  offset = offset + (i+excess_len)/4;

  // collect the excess for the next buffer
  for(uint8_t j=0; i<len; j++,i++){
    excess[j] = buffer[i];
  }

  excess_len = new_excess_len;

  return res;
}

// Utility functions
void dump_buffer(uint8_t* b, uint32_t len, uint8_t blocks, uint8_t cols) {

  // TODO make sure blocks is less that cols
  Serial.println("BUFFER >>>>>>>");
  for(uint8_t *p=b; p<b+len; p++) {
    if(*p < 0x10) {
      Serial.print(0);
    }
    Serial.print(*p,  HEX);

    if(cols != 0 && ((p-b)+1) % blocks == 0 && ((p-b)+1) % cols != 0){
      Serial.print(" ");
    }
    if(cols != 0 && ((p-b)+1) % cols == 0){
      Serial.println();
    }
  }
  Serial.println("\nBUFFER <<<<<<<");
}

void dump_buffer_char(uint8_t* b, uint32_t len) {
  Serial.println("BUFFER_CHAR >>>>>>>");
  for(uint8_t *p=b; p<b+len; p++) {
    Serial.print((char)*p);
  }
  Serial.println("\nBUFFER_CHAR <<<<<<<");
}
