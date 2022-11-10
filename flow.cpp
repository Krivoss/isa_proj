#include "flow.h"

#define DEBUG_PRINT_PACKETS 0

using namespace std;

class prog_args {
    public:
        string file_name;
        pcap_t* file;
        hostent* netflow_collector;
        int port;
        float active_t;
        float inactive_t;
        long unsigned int flow_cache_size;

        prog_args() {
            file_name = "-";
            netflow_collector = gethostbyname("127.0.0.1");
            port = 2055;
            active_t = 60.0;
            inactive_t = 10.0;
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
                        arg_s.assign(optarg);
                        if(arg_s.find(":") == string::npos) {
                            netflow_collector = gethostbyname(arg_s.c_str());
                        }
                        else {
                            string host = arg_s.substr(0, arg_s.find(":"));
                            netflow_collector = gethostbyname(host.c_str());                            
                            string port_s = (arg_s.substr(arg_s.find(":") + 1, arg_s.length()));
                            port = stoi(port_s);
                        }                        
                        break;
                    case 'a':
                        active_t = atof(optarg);
                        if(active_t <= 0.0) {
                            cerr << "ERROR: -a must be greater than 0" << endl;
                            exit(1);
                        }
                        break;
                    case 'i':
                        inactive_t = atof(optarg);
                        if(inactive_t <= 0.0) {
                            cerr << "ERROR: -i must be greater than 0" << endl;
                            exit(1);
                        }
                        break;
                    case 'm':
                        flow_cache_size = stoul(optarg);
                        if(atol(optarg) <= 0) {
                            cerr << "ERROR: -m must be greater than 0" << endl;
                            exit(1);
                        }
                        break;
                    case 'h':
                        cerr << "usage: ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]" << endl;
                        exit(0);
                        break;
                    default:
                        cerr << "Unknown parse returns: " << c << endl;
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
        string prot;
        timeval time_s;
        string src_MAC;
        string dst_MAC;
        string src_ip;
        string dst_ip;
        u_int16_t src_port;
        u_int16_t dst_port;
        int tos;
        uint32_t ihl; 
        u_char tcp_flag;

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

                    tos = int(ip_header->tos);
                    ihl = ntohs(ip_header->tot_len);
                                        
                    switch (ip_header->protocol) {
                        case IPPROTO_TCP: { // TCP
                            const struct tcphdr* tcp_header {(struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header_len)};
                            src_port = ntohs(tcp_header->th_sport);
                            dst_port = ntohs(tcp_header->th_dport);                            
                            prot = "TCP";
                            tcp_flag = tcp_header->th_flags;
                            break;
                        }
                        case IPPROTO_UDP: { // UDP
                            const struct udphdr* udp_header {(struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header_len)};
                            src_port = ntohs(udp_header->source);
                            dst_port = ntohs(udp_header->dest);
                            prot = "UDP";
                            break;
                        }
                        default: { // ICMP
                            src_port = 0;
                            dst_port = 0;
                            prot = "ICMP";
                        }
                    }
                    break;
                }
                default: {
                    cerr << "GOT INVALID PACKET" << endl;
                    exit(1);
                }
            }
            time_s = header.ts;
            if (DEBUG_PRINT_PACKETS) {
                packet_print();
            }
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
        
        // outputs packet respresentation
        void packet_print() {

            // cout <<  "timestamp: " << time_s << endl;
            cout << "src MAC: " << src_MAC << endl;
            cout << "dst MAC: " << dst_MAC << endl;
            cout << "frame length: " << header.len << " bytes" << endl;
            if (prot != "IPv6") {
                cout << "src IP: " << src_ip << endl;
                cout << "dst IP: " << dst_ip << endl;
            }
            if(prot == "TCP" || prot == "UDP") {                
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
        u_int16_t src_port;
        u_int16_t dst_port;
        u_int32_t dOctets;
        string prot;
        timeval first_t;
        timeval last_t;
        timeval curr_t;
        int tos;
        int packet_n;
        u_char tcp_flags;

        flow(packet p) {
            src_ip = p.src_ip;
            dst_ip = p.dst_ip;
            src_port = p.src_port;
            dst_port = p.dst_port;
            dOctets = p.ihl;
            prot = p.prot;
            tos = p.tos;
            first_t = p.time_s;
            last_t = p.time_s;
            packet_n = 1;
            if(p.prot == "TCP") {
                tcp_flags = p.tcp_flag;
            }
            else {
                tcp_flags = 0;
            }
        }
};

class exporter {
    public:
        list<flow> flow_list;
        int flow_sequence_n;
        int sock;
        timeval boot; // time of the first (oldest) packet - for sysuptime calculatin

        exporter() {
            flow_list = list<flow>();
            flow_sequence_n = 0;
            sock = 0;
        }

        void process(prog_args prog_args, packet p) {
            check_for_export(prog_args, p);
            int matched_pos;
            if((matched_pos = match_flow(p)) != -1) {
                edit_flow(p, matched_pos);
            }
            else {
                add_flow(prog_args, p);
            }

        }

        // check if any flow time havent exceded their times
        void check_for_export(prog_args p_args, packet p) {
            timeval curr_t = p.time_s;
            list<flow>::iterator i = flow_list.begin();
            while(i != flow_list.end()) {
                flow f = (*i);
                double active_t = time_subtract(curr_t, f.first_t);
                double inactive_t = time_subtract(curr_t, f.last_t);
                if((active_t >= p_args.active_t) || (inactive_t >= p_args.inactive_t)) {
                    // if flow has and exceded time export it
                    f.curr_t = curr_t;
                    export_flow(p_args, f, p);
                    i = flow_list.erase(i);
                }
                else {
                    i++;
                }
            }
        }

        // search if there are any matching flows to the packet
        int match_flow(packet p) {
            int i = 0;
            for(const auto& f : flow_list) {
                bool same_src_ip = p.src_ip == f.src_ip;
                bool same_dst_ip = p.dst_ip == f.dst_ip;
                bool same_src_port = p.src_port == f.src_port;
                bool same_dst_port = p.dst_port == f.dst_port;
                bool same_prot = p.prot == f.prot;
                bool same_tos = p.tos == f.tos;
                if(same_src_ip && same_dst_ip && same_src_port && same_dst_port && same_prot && same_tos) {
                    return i;
                }
                i++;
            }
            return -1;
        }

        // if packet matched existing flow, update this flow
        void edit_flow(packet p, int pos) {
            list<flow>::iterator it = flow_list.begin();
            advance(it, pos);
            it->packet_n++;
            it->last_t = p.time_s;
            it->dOctets += p.ihl;
            if(p.prot == "TCP") {
                it->tcp_flags |= p.tcp_flag;
            }
            // flow_list.sort([](flow lhs, flow rhs) {return time_compare(lhs.first_t, rhs.first_t);});
        }

        // if no flows matched the packet add new flow
        void add_flow(prog_args prog_args, packet p) {
            if(flow_list.size() == 0 && flow_sequence_n == 0) {
                boot = p.time_s;
            }
            if(flow_list.size() == prog_args.flow_cache_size) {
                flow_list.sort([](flow lhs, flow rhs) {return time_compare(lhs.first_t, rhs.first_t);});
                export_flow(prog_args, flow_list.front(), p);
                flow_list.pop_front();
            }
            flow f(p);
            flow_list.push_back(f);
        }

        // sending flow in udp packet
        void export_flow(prog_args p_args, flow f, packet p) {
            if(sock == 0) {
                open_client_sock(p_args);
            }
            packet_data p_data = {};
            p_data.version = htons(5);
            p_data.count = htons(1);
            p_data.SysUptime = htonl(calc_sysuptime(boot, p.time_s));
            p_data.unix_secs = htonl((uint32_t) p.time_s.tv_sec);
            p_data.unix_nsecs = htonl((uint32_t) p.time_s.tv_usec * 1000);
            p_data.flow_sequence = htonl(flow_sequence_n++);
            p_data.engine_type = 0;
            p_data.engine_id = 0;
            p_data.sampling_interval = htons(0);

            p_data.srcaddr = inet_addr(f.src_ip.c_str());
            p_data.dstaddr = inet_addr(f.dst_ip.c_str());
            p_data.nexthop = htonl(0);
            p_data.input = htons(0);
            p_data.output = htons(0);
            p_data.dPkts = htonl(f.packet_n);
            p_data.dOctets = htonl(f.dOctets);
            p_data.First = htonl(calc_sysuptime(boot, f.first_t));
            p_data.Last = htonl(calc_sysuptime(boot, f.last_t));
            p_data.srcport = htons(f.src_port);
            p_data.dstport = htons(f.dst_port);
            p_data.pad1 = 0;
            if(f.prot == "TCP") {
                p_data.prot = 6;
            }
            else if(f.prot == "UDP") {
                p_data.prot = 17;
            }
            else if(f.prot == "ICMP") {
                p_data.prot = 1;
            }
            p_data.tos = f.tos;            
            p_data.tcp_flags = f.tcp_flags;
            p_data.src_as = htons(0);
            p_data.dst_as = htons(0);
            p_data.src_mask = 0;
            p_data.dst_mask = 0;
            p_data.pad2 = htons(0);


            send(sock, &p_data, sizeof(p_data), 0);
            
        }

        // open socket for exporting flows
        void open_client_sock(prog_args p_args) {
            // modified code taken from echo-udp-client2.c by Petr Matousek
            // https://moodle.vut.cz/pluginfile.php/502893/mod_folder/content/0/udp/echo-udp-client2.c?forcedownload=1
            int s;                        // socket descriptor
            struct sockaddr_in server;       // address structures of the server and the client
            struct hostent *servent;         // network host entry required by gethostbyname()
            
            memset(&server,0,sizeof(server)); // erase the server structure
            server.sin_family = AF_INET;                   

            if ((servent = p_args.netflow_collector) == NULL) // check the first parameter
                errx(1,"gethostbyname() failed\n");

            // copy the first parameter to the server.sin_addr structure
            memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

            server.sin_port = htons(p_args.port);        // server port (network byte order)
            
            if ((s = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
                err(1,"socket() failed\n");

            // create a connected UDP socket
            if (connect(s, (struct sockaddr *)&server, sizeof(server))  == -1)
                err(1, "connect() failed");

            sock = s;
        }

        void export_all(prog_args p_args, packet p) {
            for(flow f = flow_list.front();; f = flow_list.front()) {
                export_flow(p_args, f, p);
                flow_list.pop_front();
                if(flow_list.empty()) {
                    break;
                }
            }
        }
};

// return the systemuptime = new_time - old_time
uint32_t calc_sysuptime(timeval t1, timeval t2) {
    time_t sec = t2.tv_sec - t1.tv_sec;
    time_t usec = t2.tv_usec - t1.tv_usec;
    if(usec < 1) {
        usec += 1000000;
        sec--;
    }
    return ((uint32_t) sec * 1000 + (uint32_t) usec / 1000);
}

// return the time differance between the two times
double time_subtract(timeval x, timeval y) {
    struct timeval result;
    result.tv_sec = x.tv_sec - y.tv_sec;
    
    if ((result.tv_usec = x.tv_usec - y.tv_usec) < 0) {
        result.tv_usec += 1000000;
        result.tv_sec--;
    }

    float res = result.tv_sec + (result.tv_usec / 1000000.0);
    return res;
}

// return true if first time was earlier that the second one
bool time_compare(timeval t1, timeval t2) {
    if(t1.tv_sec == t2.tv_sec) {
        return t1.tv_usec < t2.tv_usec;
    }
    else {
        return t1.tv_sec < t2.tv_sec;
    }
}

int main(int argc, char** argv) {
    prog_args p_args;
    if(argc > 1) {
        p_args.process_args(argc, argv);
    }
    p_args.open_file();

    exporter exp;

    packet p;
    while(1) {        
        // read packet from file and put it into packet objecy
        if(p.process_packet(p_args.file)) {
            break;
        }
        // send packet to exporter
        exp.process(p_args, p);
    }
    // export all remaining flows
    exp.export_all(p_args, p);

    p_args.cleanup();
    return 0;
}