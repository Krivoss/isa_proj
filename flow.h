#include <iostream>
#include <iomanip>
#include <sstream>
#include <list>

#include <ctime>

#include <string.h>
#include <stdio.h> 
#include <stdlib.h>

#include <getopt.h>
#include <signal.h>
#include <err.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

bool time_compare(timeval t1, timeval t2);
float time_subtract(timeval x, timeval y);

int main(int argc, char** argv);