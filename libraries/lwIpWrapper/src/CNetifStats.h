#pragma once
/*
 * This library aims to provide debug utilities for performances on Network interfaces 
 * that are being used in lwip wrapper
 * 
 * USAGE:
 * 
 * In the Net interface define the struct (it should be accessible from outside)
 * 
 * #ifdef CNETIF_STATS_ENABLED
 * struct netif_stats stats;
 * #endif
 * 
 * Initialize the struct:
 * 
 * NETIF_STATS_INIT(stats);
 *
 * Then use the MACROS defined in this file. NOTE if CNETIF_STATS_ENABLED is not defined the macros will
 * be solved as empty, thus no need to use #ifdef.
 *
 * In the sketch you need to import the symbol for the stats and define a buffer 
 * (in can be dinamically allocated, it should only require 300 chars).
 *
 * #include <CNetifStats.h>
 * #ifdef CNETIF_STATS_ENABLED
 * extern netif_stats stats;
 * char cnetif_stats_buffer[300];
 * #endif
 *
 * Then you can call the routine to print the stats:
 *
 * #ifdef CNETIF_STATS_ENABLED
 * NETIF_STATS_SPRINT_DEBUG(cnetif_stats_buffer, stats); 
 * DEBUG_INFO(cnetif_stats_buffer);
 * #endif
 *
 * You can optionally print the metrics yourself, for how to look at netif_stats_sprintf function
 */

// #define CNETIF_STATS_ENABLED
#ifdef CNETIF_STATS_ENABLED

#include <stdio.h>

struct netif_stats {
    // this metric cunts the number of times the rx interrupt routine is called by the driver
    uint32_t rx_interrupt_calls;
    // this metric count the number of time the transmit routine is invoked on the driver
    uint32_t tx_transmit_calls;
    // this metric counts the total number of failed rx calls, for whatever reason
    uint32_t rx_interrupt_failed_calls;
    // this metric count the number of times the rx routine failed allocating the buffer for the incoming packet
    uint32_t rx_pbuf_alloc_failed_calls;
    // this metric count the number of times the rx routing failed inserting the pbuf inside lwip
    uint32_t rx_ni_input_failed_calls;
    // this metric counts the number of times the tx routine failed
    uint32_t tx_transmit_failed_calls;

    // the following metrics count the size (bytes) of packets being handled in rx and tx
    uint32_t rx_bytes;
    uint32_t tx_bytes;

    // the following measure contains the size (bytes) of packets being handled in rx and tx 
    // before the reset, used to calculate avg speed
    uint32_t prev_rx_bytes;
    uint32_t prev_tx_bytes;
    time_t measure_start;

    // the following metrics are used to calculate the average time spent in rx interrupt and tx routine, measured in us
    float average_rx_time;
    uint32_t average_rx_time_counter;
    float average_tx_time;
    uint32_t average_tx_time_counter;

    // the following variables are used to hold the starting time for average a single time measurement
    time_t rx_time_start;
    time_t tx_time_start;
};

/*
 * This function initializes the counters on the netif_struct_t 
 */
inline void netif_stats_init(struct netif_stats& stats, time_t time=micros()) {
    stats.rx_interrupt_calls = 0;
    stats.rx_interrupt_failed_calls = 0;
    stats.rx_pbuf_alloc_failed_calls = 0;
    stats.rx_ni_input_failed_calls = 0;
    stats.tx_transmit_calls = 0;
    stats.tx_transmit_failed_calls = 0;

    stats.rx_bytes = 0;
    stats.tx_bytes = 0;
    stats.prev_rx_bytes = 0;
    stats.prev_tx_bytes = 0;
    stats.measure_start = time;


    stats.average_rx_time = 0;
    stats.average_rx_time_counter = 0;
    stats.average_tx_time = 0;
    stats.average_tx_time_counter = 0;
}

/*
 * This is an utility function used to calculate an average of a sequence of numbers without storing them,
 * it can accept any tipes that support *, + and / operators. 
 * This function automatically increments the counter
 * This function returns the next average
 */
template<typename T, typename S>
inline T netif_stats_streaming_average(const T& metric, const T new_value, S& counter) {
    return  ((metric*counter) + (new_value)) / (++counter);
}

/*
 * This function is used to reset the metrics that are used for averages. 
 * It is intended to be called after the prints
 */
inline void netif_stats_reset_averages(struct netif_stats& stats, time_t time=micros()) {
    stats.prev_rx_bytes = stats.rx_bytes;
    stats.prev_tx_bytes = stats.tx_bytes;

    stats.average_rx_time = 0;
    stats.average_rx_time_counter = 0;

    stats.average_tx_time = 0;
    stats.average_tx_time_counter = 0;
    stats.measure_start = time;
}

/*
 * This routine outputs a string containing a summary of the measured stats,
 * the buffer passed should be 270 bytes
 */
inline void netif_stats_sprintf(char* buffer, const struct netif_stats& stats, size_t size=500, time_t time=micros()) {
    snprintf(
        buffer,
        size,
        "RX bytes: %10u, calls: %10u, failed: %10u, failed alloc: %10u, failed inputs: %10u\n"
        "TX bytes: %10u, calls: %10u, failed: %10u\n"
        "RX time: %10.2fus speed: %10.2fKB/s\n"
        "TX time: %10.2fus speed: %10.2fKB/s\n",
        stats.rx_bytes, stats.rx_interrupt_calls, stats.rx_interrupt_failed_calls, stats.rx_pbuf_alloc_failed_calls, stats.rx_ni_input_failed_calls,
        stats.tx_bytes, stats.tx_transmit_calls, stats.tx_transmit_failed_calls,
        stats.average_rx_time, float(stats.rx_bytes - stats.prev_rx_bytes) / (time-stats.measure_start) * 10e6 / 1024, // Measured in KB/s
        stats.average_tx_time, float(stats.tx_bytes - stats.prev_tx_bytes) / (time-stats.measure_start) * 10e6 / 1024
    );
}

#define NETIF_STATS_INIT(stats) netif_stats_init(stats)
#define NETIF_STATS_RESET_AVERAGES(stats) netif_stats_reset_averages(stats)
#define NETIF_STATS_SPRINT_DEBUG(buffer, stats) netif_stats_sprintf(buffer, stats)

#define NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(stats) stats.rx_interrupt_calls++
#define NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(stats) stats.rx_interrupt_failed_calls++
#define NETIF_STATS_INCREMENT_RX_PBUF_ALLOC_FAILED_CALLS(stats) stats.rx_pbuf_alloc_failed_calls++
#define NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(stats) stats.rx_ni_input_failed_calls++
#define NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(stats) stats.tx_transmit_calls++
#define NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(stats) stats.tx_transmit_failed_calls++

#define NETIF_STATS_INCREMENT_RX_BYTES(stats, bytes) stats.rx_bytes+=bytes
#define NETIF_STATS_INCREMENT_TX_BYTES(stats, bytes) stats.tx_bytes+=bytes

#define NETIF_STATS_RX_TIME_START(stats) stats.rx_time_start = micros()
#define NETIF_STATS_RX_TIME_AVERAGE(stats) stats.average_rx_time = netif_stats_streaming_average(stats.average_rx_time, float(micros() - stats.rx_time_start), stats.average_rx_time_counter)

#define NETIF_STATS_TX_TIME_START(stats) stats.tx_time_start = micros()
#define NETIF_STATS_TX_TIME_AVERAGE(stats) stats.average_tx_time = netif_stats_streaming_average(stats.average_tx_time, float(micros() - stats.tx_time_start), stats.average_tx_time_counter)


#else // CNETIF_STATS_ENABLED

#define NETIF_STATS_INIT(stats) (void)0
#define NETIF_STATS_RESET_AVERAGES(stats) (void)0
#define NETIF_STATS_SPRINT_DEBUG(stats, buffer) (void)0

#define NETIF_STATS_INCREMENT_RX_INTERRUPT_CALLS(stats) (void)0
#define NETIF_STATS_INCREMENT_RX_INTERRUPT_FAILED_CALLS(stats) (void)0
#define NETIF_STATS_INCREMENT_RX_PBUF_ALLOC_FAILED_CALLS(stats) (void)0
#define NETIF_STATS_INCREMENT_RX_NI_INPUT_FAILED_CALLS(stats) (void)0
#define NETIF_STATS_INCREMENT_TX_TRANSMIT_CALLS(stats) (void)0
#define NETIF_STATS_INCREMENT_TX_TRANSMIT_FAILED_CALLS(stats) (void)0

#define NETIF_STATS_INCREMENT_RX_BYTES(stats, bytes) (void)0
#define NETIF_STATS_INCREMENT_TX_BYTES(stats, bytes) (void)0

#define NETIF_STATS_RX_TIME_START(stats) (void)0
#define NETIF_STATS_RX_TIME_AVERAGE(stats) (void)0

#define NETIF_STATS_TX_TIME_START(stats) (void)0
#define NETIF_STATS_TX_TIME_AVERAGE(stats) (void)0


#endif // CNETIF_STATS_ENABLED