#include "util.h"
#include <string.h>

char output_file[MAXSTRLEN];

char message_type[MAXSTRLEN];
uint64_t is_list_buf;
uint64_t base_payload_len;
char serialization_format[MAXSTRLEN];


/* Sample the value using Exponential Distribution */
double sample(double lambda) {
    double u = ((double) rte_rand()) / ((uint64_t) -1);

    return -log(1 - u) / lambda;
}

/* Convert string type into int type*/
static uint32_t process_int_arg(const char *arg) {
	char *end = NULL;

	return strtoul(arg, &end, 10);
}

/* Allocate all nodes for incoming packets (+ 20%) */
void allocate_incoming_nodes() {
	uint64_t nr_elements = (rate * duration * nr_executions) * 1.2;

	incoming = (node_t*) malloc(nr_elements * sizeof(node_t));
	if(incoming == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot alloc the incoming array.\n");
	}

	incoming_idx = 0;
} 

/* Allocate and Create an array for all interarrival packets for rate specified using Exponential Distribution */
void create_interarrival_array() {
    double lambda = 1.0/(1000000.0/rate);
	uint64_t nr_elements = rate * duration * nr_executions;

    interarrival_gap = (uint64_t*) malloc(nr_elements * sizeof(uint64_t));
    if(interarrival_gap == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot alloc the interarrival_gap array.\n");
    }

    for(uint64_t i = 0; i < nr_elements; i++) {
        interarrival_gap[i] = sample(lambda) * TICKS_PER_US;
    } 
}

/* Allocate and Create an array for all flow indentier to send to the server */
void create_flow_indexes_array() {
	uint64_t nr_elements = rate * duration * nr_executions;

    flow_indexes = (uint16_t*) malloc(nr_elements * sizeof(uint16_t));
    if(flow_indexes == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot alloc the flow_indexes array.\n");
    }

	for(int i = 0; i < nr_elements; i++) {
		flow_indexes[i] = rte_rand() % nr_flows;
	}
}

/* Clean up all allocate structures */
void clean_heap() {
	free(incoming);
	free(flow_indexes);
    free(interarrival_gap);
}

/* Usage message */
static void usage(const char *prgname) {
	printf("%s [EAL options] -- \n"
		"  -r RATE: rate in pps\n"
		"  -f FLOWS: number of flows\n"
		"  -q QUEUES: number of queues\n"
		"  -s SIZE: frame size in bytes\n"
		"  -t TIME: time in seconds to send packets\n"
		"  -c FILENAME: name of configuration file\n"
		"  -o FILENAME: name of the output file\n",
		prgname
	);
}

/* Parse the argument given in the command line of the application */
int app_parse_args(int argc, char **argv) {
	int opt, ret;
	char **argvopt;
	char *prgname = argv[0];

	nr_executions = 2;

	argvopt = argv;
	while ((opt = getopt(argc, argvopt, "r:f:s:p:t:c:o:m:z:l:")) != EOF) {
		switch (opt) {
		/* rate (pps) */
		case 'r':
			rate = process_int_arg(optarg);
			break;
		/* flows (un.) */
		case 'f':
			nr_flows = process_int_arg(optarg);
			break;
		/* duration (s) */
		case 't':
			duration = process_int_arg(optarg);
			break;

		/* config file name */
		case 'c':
			/* process the config file */
			process_config_file(optarg);
			break;
		
		/* output mode */
		case 'o':
			strcpy(output_file, optarg);
			break;

		/* message type (0-"single"/1-"list") */
		case 'm': 
			strcpy(message_type, optarg);
			break;

		/* serialization format ("cf"/"fb") */
		case 'z':
			strcpy(serialization_format, optarg);
			break;

		/* base payload size (without any headers) (1024/4096) */
		case 'l':
			base_payload_len = process_int_arg(optarg);
			break;

		default:
			usage(prgname);
			rte_exit(EXIT_FAILURE, "Invalid arguments.\n");
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1;

    if (!strcmp(serialization_format, "none")) {
        tcp_payload_size = base_payload_len + 32;
        printf("Payload size: %u\n", tcp_payload_size);
    } else if (!strcmp(serialization_format, "cf") && 
			base_payload_len==1024 && 
			!strcmp(message_type, "single")) {
        tcp_payload_size = 1044 + 32;
	} else if (!strcmp(serialization_format, "cf") && 
			base_payload_len==1024 &&
			!strcmp(message_type, "list")) {
		tcp_payload_size = 1060 + 32;
	} else if (!strcmp(serialization_format, "fb") && 
			base_payload_len==1024 &&
		    !strcmp(message_type, "single")) {
        tcp_payload_size = 1052 + 32;
	} else if (!strcmp(serialization_format, "fb") && 
			base_payload_len==1024 &&
		!strcmp(message_type, "list")) {
        tcp_payload_size = 1084 + 32;
	} else if (!strcmp(serialization_format, "cf") && 
			base_payload_len==4096 &&
		!strcmp(message_type, "single")) {
		tcp_payload_size = 4116 + 32;
	} else if (!strcmp(serialization_format, "cf") && 
			base_payload_len==4096 &&
			!strcmp(message_type, "list")) {
		tcp_payload_size = 4132 + 32;
	} else if (!strcmp(serialization_format, "fb") && 
			base_payload_len==4096 &&
			!strcmp(message_type, "single")) {
		tcp_payload_size = 4124 + 32;
	} else if (!strcmp(serialization_format, "fb") && 
			base_payload_len==4096 &&
			!strcmp(message_type, "list")) {
		tcp_payload_size = 4156 + 32;
	}
    printf("Setting tcp_payload_size to %u\n", tcp_payload_size);
    frame_size = tcp_payload_size + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
    

	return ret;
}

/* Wait for the duration parameter */
void wait_timeout() {
	uint64_t t0 = rte_rdtsc();
	while((rte_rdtsc() - t0) < (duration * nr_executions * 1000000 * TICKS_PER_US)) { }

	/* wait for remaining */
	t0 = rte_rdtsc_precise();
	while((rte_rdtsc() - t0) < (5 * 1000000 * TICKS_PER_US)) { }

	/* set quit flag for all internal cores */
	quit_rx = 1;
	quit_tx = 1;
	quit_rx_ring = 1;
}

/* Compare two double values (for qsort function) */
int cmp_func(const void * a, const void * b) {
	double da = (*(double*)a);
	double db = (*(double*)b);

	return (da - db) > ( (fabs(da) < fabs(db) ? fabs(db) : fabs(da)) * EPSILON);
}

/* Print stats into output file */
void print_stats_output() {
	/* open the file */
	FILE *fp = fopen(output_file, "w");
	if(fp == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot open the output file.\n");
	}

    printf("Incoming idx: %lu\n", incoming_idx);
	/* drop the first 50% packets for warming up */
	uint64_t i = 0.5 * incoming_idx;

	/* print if there was the never_sent packets */
	node_t *prev = &incoming[i-1];
	fprintf(fp, "%lu\n", incoming[incoming_idx-1].nr_never_sent - prev->nr_never_sent);

	/* print the RTT latency in (ns) */
	node_t *cur;
	for(; i < incoming_idx; i++) {
		cur = &incoming[i];

        //fprintf(fp, "%lu,%lu\n",
          //      (uint64_t)((cur->timestamp_rx)/((double)TICKS_PER_US/1000)),
          //      (uint64_t)((cur->timestamp_tx)/((double)TICKS_PER_US/1000)));
		fprintf(fp, "%lu\n",
			((uint64_t)((cur->timestamp_rx - cur->timestamp_tx)/((double)TICKS_PER_US/1000)))
        );
	}

	/* close the file */
	fclose(fp);
}

void process_config_file(char *cfg_file) {
	/* open the file */
	struct rte_cfgfile *file = rte_cfgfile_load(cfg_file, 0);
	if(file == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n", cfg_file);
	}

	/* load ethernet addresses */
	char *entry = (char*) rte_cfgfile_get_entry(file, "ethernet", "src");
	if(entry) {
		rte_ether_unformat_addr((const char*) entry, &src_eth_addr);
	}
	entry = (char*) rte_cfgfile_get_entry(file, "ethernet", "dst");
	if(entry) {
		rte_ether_unformat_addr((const char*) entry, &dst_eth_addr);
	}

	/* load ipv4 addresses */
	entry = (char*) rte_cfgfile_get_entry(file, "ipv4", "src");
	if(entry) {
		uint8_t b3, b2, b1, b0;
		sscanf(entry, "%hhd.%hhd.%hhd.%hhd", &b3, &b2, &b1, &b0);
		src_ipv4_addr = IPV4_ADDR(b3, b2, b1, b0);
	}
	entry = (char*) rte_cfgfile_get_entry(file, "ipv4", "dst");
	if(entry) {
		uint8_t b3, b2, b1, b0;
		sscanf(entry, "%hhd.%hhd.%hhd.%hhd", &b3, &b2, &b1, &b0);
		dst_ipv4_addr = IPV4_ADDR(b3, b2, b1, b0);
	}

	/* load TCP destination port */
	entry = (char*) rte_cfgfile_get_entry(file, "tcp", "dst");
	if(entry) {
		uint16_t port;
		sscanf(entry, "%hu", &port);
		dst_tcp_port = port;
	}

	/* local server info */
	entry = (char*) rte_cfgfile_get_entry(file, "server", "nr_apps");
	if(entry) {
		uint16_t n;
		sscanf(entry, "%hu", &n);
		nr_apps = n;
	}

	/* close the file */
	rte_cfgfile_close(file);
}

/* Fill the data into packet payload properly */
inline uint64_t read_payload_pkt(struct rte_mbuf *pkt, uint32_t idx) {
	uint8_t *payload = (uint8_t*) rte_pktmbuf_mtod_offset(pkt, uint8_t*, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));

	return ((uint64_t*)payload)[idx];
}
/* Fill the data into packet payload properly */
inline void fill_payload_pkt(struct rte_mbuf *pkt, uint32_t idx, uint64_t value) {
	uint8_t *payload = (uint8_t*) rte_pktmbuf_mtod_offset(pkt, uint8_t*, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));

	((uint64_t*) payload)[idx] = value;
}
