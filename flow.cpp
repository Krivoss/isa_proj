#include "flow.h"

using namespace std;

class prog_args {
    public:
        FILE* file;
        string netflow_collector;
        int port;
        int active_t;
        int inactive_t;
        int flow_cache_size;

        prog_args() {
            file = stdin;
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
                        file = fopen(optarg, "rw");
                        if(file == NULL) {
                            cerr << "ERROR: invalid file was input" << endl;
                        }
                        break;
                    case 'c':
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
                        break; 
                } 
            }
        }
};

int main(int argc, char** argv) {
    prog_args prog_args;
    if(argc > 1) {
        prog_args.process_args(argc, argv);
    }

    return 0;
}