#include "dpdk_util.h"
#include <string.h>

extern char output_file[MAXSTRLEN];

/* Initialize DPDK configuration */
void init_DPDK(uint16_t portid, uint64_t nr_queues) {
	if(rte_lcore_count() < MIN_LCORES) {
		rte_exit(EXIT_FAILURE, "No available worker core!\n");
	}

	/* init the seed for random numbers */
	rte_srand(SEED);

	/* get the number of cycles per us */
	TICKS_PER_US = rte_get_timer_hz() / 1000000;

	/* flush all flows of the NIC */
	struct rte_flow_error error;
	rte_flow_flush(portid, &error);

	/* allocate the atomic variables */
	nr_tx = rte_malloc(NULL, sizeof(rte_atomic64_t), RTE_CACHE_LINE_SIZE);
	if(nr_tx == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot alloc the experiment id.\n");
	}
	rte_atomic64_init(nr_tx);

	/* allocate the packet pool */
	char s[64];
	snprintf(s, sizeof(s), "mbuf_pool");
	pktmbuf_pool = rte_pktmbuf_pool_create(s, PKTMBUF_POOL_ELEMENTS, MEMPOOL_CACHE_SIZE, 0,	RTE_MBUF_DEFAULT_BUF_SIZE  , rte_socket_id());

	if(pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n", rte_socket_id());
	}

	/* allocate the ring to RX threads */
	snprintf(s, sizeof(s), "ring_rx");
	// rx_ring = rte_ring_create(s, RING_ELEMENTS, rte_socket_id(), RING_F_SP_ENQ|RING_F_SC_DEQ);
	rx_ring = rte_ring_create(s, RING_ELEMENTS, rte_socket_id(), RING_F_MP_RTS_ENQ|RING_F_SC_DEQ);

	if(rx_ring == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot create the ring on socket %d\n", rte_socket_id());
	}

	/* initialize the DPDK port */
	uint16_t nb_rx_queue = nr_queues;
	uint16_t nb_tx_queue = nr_queues;

	if(init_DPDK_port(portid, nb_rx_queue, nb_tx_queue, pktmbuf_pool) != 0) {
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", 0);
    }
}

/* Initialize the DPDK port */
int init_DPDK_port(uint16_t portid, uint16_t nb_rx_queue, uint16_t nb_tx_queue, struct rte_mempool *mbuf_pool) {
    /* configurable number of RX/TX ring descriptors */
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 4096;

	/* get port_conf default */
	struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = nb_rx_queue > 1 ? RTE_ETH_MQ_RX_RSS : RTE_ETH_MQ_RX_NONE,
            .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
            .split_hdr_size = 0,
            .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf = RTE_ETH_RSS_TCP,
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
            .offloads = RTE_ETH_TX_OFFLOAD_TCP_CKSUM|RTE_ETH_TX_OFFLOAD_IPV4_CKSUM|RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
        },
    };

	/* configure the NIC */
	int retval = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
	if(retval != 0) {
		return retval;
	}

	/* adjust and set up the number of RX/TX descriptors */
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if(retval != 0) {
		return retval;
	}

	/* setup the RX queues */
	for(int q = 0; q < nb_rx_queue; q++) {
		retval = rte_eth_rx_queue_setup(portid, q, nb_rxd, rte_eth_dev_socket_id(portid), NULL, mbuf_pool);
		if (retval < 0) {
			return retval;
		}
	}

	/* setup the TX queues */
	for(int q = 0; q < nb_tx_queue; q++) {
		retval = rte_eth_tx_queue_setup(portid, q, nb_txd, rte_eth_dev_socket_id(portid), NULL);
		if (retval < 0) {
			return retval;
		}
	}

	/* start the Ethernet port. */
	retval = rte_eth_dev_start(portid);
	if(retval < 0) {
		return retval;
	}

	// /* enable the promiscuous mode */
	// retval = rte_eth_promiscuous_enable(portid);
	// if(retval != 0)
	// 	return retval;

	return 0;
}

/* Print the DPDK stats */
void print_dpdk_stats(uint32_t portid) {
	struct rte_eth_stats eth_stats;
	int retval = rte_eth_stats_get(portid, &eth_stats);
	if(retval != 0) {
		rte_exit(EXIT_FAILURE, "Unable to get stats from portid\n");
    }
	
	printf("\n\nDPDK RX Stats:\n");
	printf("ipackets: %lu\n", eth_stats.ipackets);
	printf("ibytes: %lu\n", eth_stats.ibytes);
	printf("ierror: %lu\n", eth_stats.ierrors);
	printf("imissed: %lu\n", eth_stats.imissed);
	printf("rxnombuf: %lu\n", eth_stats.rx_nombuf);

	printf("\nDPDK TX Stats:\n");
	printf("opackets: %lu\n", eth_stats.opackets);
	printf("obytes: %lu\n", eth_stats.obytes);
	printf("oerror: %lu\n", eth_stats.oerrors);

	// Write json to a file too
	FILE *fp = fopen(strcat(output_file,".summary"), "w");
        if(fp == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot open the output file.\n");
        }

	fprintf(fp, "{\n"),
	fprintf(fp, "\"frame_size\": %u,\n", frame_size);
	fprintf(fp, "\"duration\": %lu,\n", duration);
	fprintf(fp, "\"ipackets\": %lu,\n", eth_stats.ipackets);
	fprintf(fp, "\"ibytes\": %lu,\n", eth_stats.ibytes);
	fprintf(fp, "\"ierror\": %lu,\n", eth_stats.ierrors);
	fprintf(fp, "\"imissed\": %lu,\n", eth_stats.imissed);
	fprintf(fp, "\"rxnombuf\": %lu,\n", eth_stats.rx_nombuf);
	fprintf(fp, "\"opackets\": %lu,\n", eth_stats.opackets);
	fprintf(fp, "\"obytes\": %lu,\n", eth_stats.obytes);
	fprintf(fp, "\"oerror\": %lu,\n", eth_stats.oerrors);
	fprintf(fp, "}\n");

        /* close the file */
        fclose(fp);	

	struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;
	static const char *stats_border = "_______";
	printf("\n\nPORT STATISTICS:\n================\n");
    int len = rte_eth_xstats_get(portid, NULL, 0);
    if(len < 0) {
        rte_exit(EXIT_FAILURE, "rte_eth_xstats_get(%u) failed: %d", portid, len);
    }

    xstats = calloc(len, sizeof(*xstats));
    if(xstats == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to calloc memory for xstats");
    }

    int ret = rte_eth_xstats_get(portid, xstats, len);
    if(ret < 0 || ret > len) {
        free(xstats);
        rte_exit(EXIT_FAILURE, "rte_eth_xstats_get(%u) len%i failed: %d", portid, len, ret);
    }

    xstats_names = calloc(len, sizeof(*xstats_names));
    if(xstats_names == NULL) {
        free(xstats);
        rte_exit(EXIT_FAILURE, "Failed to calloc memory for xstats_names");
    }

    ret = rte_eth_xstats_get_names(portid, xstats_names, len);
    if(ret < 0 || ret > len) {
        free(xstats);
        free(xstats_names);
        rte_exit(EXIT_FAILURE, "rte_eth_xstats_get_names(%u) len%i failed: %d",  portid, len, ret);
    }

    for(int i = 0; i < len; i++) {
        if (xstats[i].value > 0) {
            printf("Port %u: %s %s:\t\t%"PRIu64"\n",
				portid, stats_border,
				xstats_names[i].name,
				xstats[i].value
			);
		}
	}

    free(xstats);
    free(xstats_names);
}

/* Create and fill rte_flow to send to the NIC */
/* Basically, the NIC will forward the packets from this flow to specify queue_id
 * and tags the packets with index of the flows array
 */
void insert_flow(uint16_t portid, uint32_t i) {
	int ret;
	int act_idx = 0;
	int pattern_idx = 0;
	
	struct rte_flow_attr attr = {};
	struct rte_flow_error err = {};
	struct rte_flow_item pattern[MAX_RTE_FLOW_PATTERN] = {};
	struct rte_flow_action action[MAX_RTE_FLOW_ACTIONS] = {};

	attr.egress = 0;
    attr.ingress = 1;

	action[act_idx].type= RTE_FLOW_ACTION_TYPE_QUEUE;
	action[act_idx].conf = &tcp_control_blocks[i].flow_queue_action;
	act_idx++;

	action[act_idx].type = RTE_FLOW_ACTION_TYPE_MARK;
	action[act_idx].conf = &tcp_control_blocks[i].flow_mark_action;
	act_idx++;

	action[act_idx].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_idx].conf = NULL;
	act_idx++;

	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern_idx++;

	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[pattern_idx].spec = &tcp_control_blocks[i].flow_ipv4;
	pattern[pattern_idx].mask = &tcp_control_blocks[i].flow_ipv4_mask;
	pattern_idx++;

	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[pattern_idx].spec = &tcp_control_blocks[i].flow_tcp;
	pattern[pattern_idx].mask = &tcp_control_blocks[i].flow_tcp_mask;
	pattern_idx++;

	pattern[pattern_idx].type = RTE_FLOW_ITEM_TYPE_END;
	pattern_idx++;

	/* validate the rte_flow */
	ret = rte_flow_validate(portid, &attr, pattern, action, &err);
    if (ret < 0) {
        RTE_LOG(ERR, TCP_GENERATOR, "Flow validation failed %s\n", err.message);
        return;
    }

	/* create the flow and insert to the NIC */
    struct rte_flow *rule = rte_flow_create(portid, &attr, pattern, action, &err);
    if (rule == NULL) {
        RTE_LOG(ERR, TCP_GENERATOR, "Flow creation return %s\n", err.message);
	}
}

/* clear all DPDK structures allocated */
void clean_hugepages() {
    rte_ring_free(rx_ring);
	rte_free(tcp_control_blocks);
	rte_mempool_free(pktmbuf_pool);
}
