#include <iostream>
#include <iomanip>
#include <sstream>
#include <list>

#include <ctime>

#include <string.h>
#include <stdio.h> 
#include <stdlib.h>
#include <stdint.h>

#include <getopt.h>
#include <signal.h>
#include <err.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

struct packet_data {
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;

    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
};

bool time_compare(timeval t1, timeval t2);
float time_subtract(timeval x, timeval y);

int main(int argc, char** argv);