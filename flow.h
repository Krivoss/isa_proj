#include <iostream>
#include <getopt.h>
#include <signal.h>
#include <iomanip>
#include <sstream>
#include <list>

#include <ctime>

#include <time.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void export_flow(flow f);
bool time_compare(timeval t1, timeval t2);
float time_subtract(timeval x, timeval y);

int main(int argc, char** argv);