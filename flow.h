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

bool time_compare(timeval t1, timeval t2);
float time_subtract(struct timeval x, struct timeval y);

int main(int argc, char** argv);