#include "flow.h"

using namespace std;

class prog_args {
    public:
        string file_name;
        pcap_t* file;
        string netflow_collector;
        int port;
        int active_t;
        int inactive_t;
        int flow_cache_size;

        prog_args() {
            file_name = "-";
            netflow_collector = "127.0.0.1";
            port = 2055;
            active_t = 60;
            inactive_t = 10;
            flow_cache_size = 1024;
        }

        void process_args(int argc, char** argv) {
            int c;
            string arg_s;
            while((c = getopt(argc, argv, "f:c:a:i:m:h")) != -1) { 
                switch(c) 
                {
                    case 'f':
                        file_name = optarg;
                        break;
                    case 'c':
                        // TODO get host by name
                        arg_s.assign(optarg);
                        if(arg_s.find(":") == string::npos) {
                            netflow_collector = arg_s;
                        }
                        else {
                            netflow_collector = arg_s.substr(0, arg_s.find(":"));                            
                            string port_s = (arg_s.substr(arg_s.find(":") + 1, arg_s.length()));
                            port = stoi(port_s);
                        }                        
                        break;
                    case 'a':
                        active_t = atoi(optarg);
                        break;
                    case 'i':
                        inactive_t = atoi(optarg);
                        break;
                    case 'm':
                        flow_cache_size = atoi(optarg);
                        break;
                    case 'h':
                        cerr << "usage: ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]" << endl;
                        exit(0);
                        break;
                    default:
                        cout << "Unknown parse returns: " << c << endl;
                        exit(1);
                        break; 
                } 
            }
        }

        void open_file() {
            char errbuf[PCAP_ERRBUF_SIZE];
            file = pcap_open_offline(file_name.c_str(), errbuf);
            if(file == NULL) {
                cerr << "ERROR: " << errbuf << endl;
            }

            // set filter
            struct bpf_program fcode;
            if (pcap_compile(file, &fcode, "icmp or tcp or udp", 1, 0) != 0)
            {
                cerr << "ERROR: unable to compile the packet filter. Check the syntax" << endl;
                exit(-1);
            }
            if (pcap_setfilter(file, &fcode) < 0)
            {
                cerr << "ERROR: setting the filter" << endl;
                exit(-1);
            }            
        }

        void cleanup() {
            pcap_close(file);
        }
};

class packet {
    public:
        struct pcap_pkthdr header;
	    const u_char *packet;
        string type;
        string time_s;
        string src_MAC;
        string dst_MAC;
        string src_ip;
        string dst_ip;
        u_int16_t src_port;
        u_int16_t dst_port;

        int process_packet(pcap_t *file) {
            packet = pcap_next(file, &header);
            if (packet == NULL) {
                return 1;
            }

            struct ether_header* eth_h = (struct ether_header*)(packet);
            for (int i: eth_h->ether_shost) {
                stringstream stream;
                stream << std::setfill ('0') << setw(2) << hex << i;
                src_MAC += stream.str() + ":";
            }
            src_MAC.pop_back();
            for (int i: eth_h->ether_dhost) {
                stringstream stream;
                stream << std::setfill ('0') << setw(2) << hex << i;
                dst_MAC += stream.str() + ":";
            }   
            dst_MAC.pop_back();

            switch (ntohs(eth_h->ether_type)) {
                case ETHERTYPE_IP: { // IPv4
                    const struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
                    u_short ip_header_len = (ip_header->ihl) * 4;

                    struct in_addr addr_src_bin;
                    addr_src_bin.s_addr = ip_header->saddr;
                    src_ip = inet_ntoa(addr_src_bin);

                    struct in_addr addr_dest_bin;                    
                    addr_dest_bin.s_addr = ip_header->daddr;                  
                    dst_ip = inet_ntoa(addr_dest_bin);
                    switch (ip_header->protocol) {
                        case IPPROTO_TCP: { // TCP
                            const struct tcphdr* tcp_header {(struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len)};
                            src_port = ntohs(tcp_header->source);
                            dst_port = ntohs(tcp_header->dest);                            
                            type = "TCP";
                            break;
                        }
                        case IPPROTO_UDP: { // UDP
                            const struct udphdr* udp_header {(struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header_len)};
                            src_port =  ntohs(udp_header->source);
                            dst_port = ntohs(udp_header->dest);
                            type = "UDP";
                            break;
                        }
                    }
                    break;
                }
                default: {
                    cout << "GOT NON LINKTYPE_ETHERNET PACKET" << endl;
                    exit(1);
                }
            }
            // packet_print();
            return 0;
        }

        // converts unprintable chars to dots
        string get_printable() {
            string printable = "";
            for (bpf_u_int32 i = 0; i < header.len; i++){
                char c = packet[i];
                if(c < 32 || c >= 126) {
                    printable += '.';
                } 
                else {
                    printable += c;
                }
            }
            return printable;
        }

        void get_timestamp() {
            // modified code, take from https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
            struct tm *p = localtime((const time_t*)&header.ts.tv_sec);
            char time[100];
            size_t len = strftime(time, sizeof time - 1, "%FT%T%z", p);
            // move last 2 digits
            if(len >= 0) {
                char minute[] = { time[len-2], time[len-1], '\0' };
                sprintf(time + len - 2, ":%s", minute);
            }
            // end of taken code
            time_s = time;
        }
        
        // outputs packet respresentation
        void packet_print() {
            get_timestamp();

            cout <<  "timestamp: " << time_s << endl;
            cout << "src MAC: " << src_MAC << endl;
            cout << "dst MAC: " << dst_MAC << endl;
            cout << "frame length: " << header.len << " bytes" << endl;
            // TODO
            // IPv6 is adresses are not supported
            if (type != "IPv6") {
                cout << "src IP: " << src_ip << endl;
                cout << "dst IP: " << dst_ip << endl;
            }
            if(type == "TCP" || type == "UDP") {                
                cout << "src port: " << src_port << endl;
                cout << "dst port: " << dst_port << endl << endl;
            }

            auto printable = get_printable();
            for (bpf_u_int32 i = 0; i < header.len; i++){

                printf("0x%04x ", i);
                for (int j = 0; j < 16; j++){
                    if(i + j > header.len) {
                        cout << "   ";                        
                    }
                    else {
                        printf("%02x ", packet[i+j]);
                    }
                }
                cout << " ";

                for (int j = 0; j < 16; j++){
                    if (j == 8) {
                        cout << " ";
                    }
                    if(i+j > header.len) {
                        break;
                    }                        
                    else {
                        cout<<printable[i+j];
                    }                        
                }
                i += 15;
                cout << endl;
            }
            cout << endl;
        }
};

class flow {
    public:
        string src_ip;
        string dst_ip;
        string src_port;
        string dst_port;
        string prot;

        flow(string in_src_ip, string in_dst_ip, string in_src_port, string in_dst_port, string in_prot) {
            src_ip = in_src_ip;
            dst_ip = in_dst_ip;
            src_port = in_src_port;
            dst_port = in_dst_port;
            prot = in_prot;
        }
};

int main(int argc, char** argv) {
    prog_args prog_args;
    if(argc > 1) {
        prog_args.process_args(argc, argv);
    }
    prog_args.open_file();

    int end;
    do {
        packet packet_to_process;
        end = packet_to_process.process_packet(prog_args.file);
    } while (!end);

    prog_args.cleanup();
    return 0;
}