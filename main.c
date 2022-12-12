#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"
#include "tcp_util.h"
#include "dpdk_util.h"

/* Application parameters */
uint64_t rate;
uint64_t duration;
uint16_t nr_apps;
uint64_t nr_flows;
uint64_t nr_executions;
uint32_t frame_size;
uint32_t tcp_payload_size;

/* General variables */
uint64_t TICKS_PER_US;
uint16_t *flow_indexes;
uint64_t *interarrival_gap;

/* Heap and DPDK allocated */
node_t *incoming;
uint64_t incoming_idx;
struct rte_ring	*rx_ring;
struct rte_mempool *pktmbuf_pool;
tcp_control_block_t *tcp_control_blocks;

/* Internal threads variables */
volatile uint8_t quit_rx = 0;
volatile uint8_t quit_tx = 0;
volatile uint8_t quit_rx_ring = 0;
volatile uint32_t ack_dup = 0;
volatile uint32_t ack_empty = 0;
volatile uint64_t nr_never_sent = 0;
rte_atomic64_t *nr_tx;
lcore_param lcore_params[RTE_MAX_LCORE];

/* Connection variables */
struct rte_ether_addr dst_eth_addr;
struct rte_ether_addr src_eth_addr;
uint32_t dst_ipv4_addr;
uint32_t src_ipv4_addr;
uint16_t dst_tcp_port;

/*#define MAXSTRLEN                                       128
char message_type[MAXSTRLEN];
uint64_t base_payload_len;
char serialization_format[MAXSTRLEN];
*/
/* Process the incoming TCP packet */
int process_rx_pkt(struct rte_mbuf *pkt) {
	/* process only TCP packets*/
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	if(unlikely(ipv4_hdr->next_proto_id != IPPROTO_TCP))
		return 0;

	/* get TCP header */
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + (ipv4_hdr->version_ihl & 0x0f)*4);
	
	/* retrieve the index of the flow from the NIC (NIC tags the packet according the 5-tuple using DPDK rte_flow) */
	uint32_t flow_id = pkt->hash.fdir.hi;

	/* get control block for the flow */
	tcp_control_block_t *block = &tcp_control_blocks[flow_id];

	/* reset the connection if packets has RST flag */
	if(unlikely(tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG)) {
		rte_atomic16_set(&block->tcb_state, TCP_CLOSED);
		return 0;
	}

	/* update receive window from the packet */
    //printf("Receive window: %d\n", tcp_hdr->rx_win);
	rte_atomic16_set(&block->tcb_rwin, tcp_hdr->rx_win);

	/* update DUP ACKs counter */
	if(unlikely(block->last_ack_recv == tcp_hdr->recv_ack)) {
		ack_dup++;
	}

	/* get TCP payload size */
	uint32_t packet_data_size = rte_be_to_cpu_16(ipv4_hdr->total_length) - ((ipv4_hdr->version_ihl & 0x0f)*4) - ((tcp_hdr->data_off >> 4)*4);

	/* update EMPTY counter */
	/* do not process empty packets */
	if(unlikely(packet_data_size == 0)) {
		ack_empty++;
		return 0;
	}

	/* update ACK number in the TCP control block from the packet */
	//rte_atomic32_set(&block->tcb_next_ack, tcp_hdr->sent_seq + rte_cpu_to_be_32(packet_data_size));
	uint32_t ack_cur = rte_be_to_cpu_32(rte_atomic32_read(&block->tcb_next_ack));
	uint32_t ack_hdr = rte_be_to_cpu_32(tcp_hdr->sent_seq) + (packet_data_size);
	if(SEQ_LEQ(ack_cur, ack_hdr)) {
		rte_atomic32_set(&block->tcb_next_ack, tcp_hdr->sent_seq + rte_cpu_to_be_32(packet_data_size));
	}

	/* obtain both timestamp from the packet */
    //uint8_t *payload = rte_pktmbuf_mtod_offset(pkt, uint8_t *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
	uint8_t *payload = ((uint8_t*) tcp_hdr) + ((tcp_hdr->data_off >> 4)*4);
	uint64_t t0 = ((uint64_t*)payload)[0];
	uint64_t t = ((uint64_t*)payload)[1];
	uint64_t f_id = ((uint64_t*)payload)[2];
	uint64_t thread_id = ((uint64_t*)payload)[3];

	/* fill the node previously allocated */
	node_t *node = &(incoming[incoming_idx++]);
	node->flow_id = f_id;
	node->thread_id = thread_id;
	node->ack_dup = ack_dup;
	node->ack_empty = ack_empty;
	node->nr_tx_pkts = rte_atomic64_read(nr_tx);
    //printf("[Receive] For node %lu, timestamp rx: %lu, timestamp tx: %lu\n", incoming_idx - 1, t - t0, t0);
	node->timestamp_rx = t;
	node->timestamp_tx = t0;
	node->nr_never_sent = nr_never_sent;

	return 1;
}

/* Start the client establishing all TCP connections */
void start_client(uint16_t portid) {
	uint16_t nb_rx;
	uint16_t nb_tx;
	struct rte_mbuf *pkt;
	tcp_control_block_t *block;
	struct rte_mbuf *pkts[BURST_SIZE];

	for(int i = 0; i < nr_flows; i++) {
		/* get the TCP control block for the flow */
		block = &tcp_control_blocks[i];
		/* create the TCP SYN packet */
		struct rte_mbuf *syn_packet = create_syn_packet(i);
		/* insert the rte_flow in the NIC to retrieve the flow id for incoming packets of this flow */
		insert_flow(portid, i);

		/* send the packet */
		nb_tx = rte_eth_tx_burst(portid, 0, &syn_packet, 1);
		if(nb_tx != 1) {
			rte_exit(EXIT_FAILURE, "Error to send the TCP SYN packet.\n");
		}
        //printf("Sent syn packet\n");
		/* change the TCP state to SYN_SENT */
		rte_atomic16_set(&block->tcb_state, TCP_SYN_SENT);

		/* while not receive SYN+ACK packet and TCP state is not ESTABLISHED */
		while(rte_atomic16_read(&block->tcb_state) != TCP_ESTABLISHED) {
			/* receive TCP SYN+ACK packets from the NIC */
			nb_rx = rte_eth_rx_burst(portid, 0, pkts, BURST_SIZE);

			for(int j = 0; j < nb_rx; j++) {
				/* process the SYN+ACK packet, returning the ACK packet to send*/
                //printf("Received some packets back\n");
				pkt = process_syn_ack_packet(pkts[j]);
				
				if(pkt) {
					/* send the TCP ACK packet to the server */
					nb_tx = rte_eth_tx_burst(portid, 0, &pkt, 1);
                    //printf("Just bursted again\n");
					if(nb_tx != 1) {
						rte_exit(EXIT_FAILURE, "Error to send the TCP ACK packet.\n");
					}
				}
			}
			/* free packets */
			rte_pktmbuf_free_bulk(pkts, nb_rx);
		};
	}

	/* Discard 3-way handshake packets in the DPDK metrics */
	rte_eth_stats_reset(portid);
	rte_eth_xstats_reset(portid);
	rte_compiler_barrier();
}

/* RX processing */
static int lcore_rx_ring(void *arg) {
    //printf("Starting lcore rx loop\n");
	uint16_t nb_rx;
	struct rte_mbuf *pkts[BURST_SIZE];

	while(!quit_rx_ring) {
		/* retrieve packets from the RX core */
		nb_rx = rte_ring_sc_dequeue_burst(rx_ring, (void**) pkts, BURST_SIZE, NULL); 
		for(int i = 0; i < nb_rx; i++) {
			rte_prefetch_non_temporal(rte_pktmbuf_mtod(pkts[i], void *));
			/* process the incoming packet */
			process_rx_pkt(pkts[i]);
		}
		/* free packets */
		rte_pktmbuf_free_bulk(pkts, nb_rx);
	}

	/* process all remaining packets that are in the RX ring (not from the NIC) */
	do{
		nb_rx = rte_ring_sc_dequeue_burst(rx_ring, (void**) pkts, BURST_SIZE, NULL);
		for(int i = 0; i < nb_rx; i++) {
			rte_prefetch_non_temporal(rte_pktmbuf_mtod(pkts[i], void *));
			process_rx_pkt(pkts[i]);
		}
		/* free packets */
		rte_pktmbuf_free_bulk(pkts, nb_rx);
	} while (nb_rx != 0);

	return 0;
}

/* Main RX processing */
static int lcore_rx(void *arg) {
	lcore_param *rx_conf = (lcore_param *) arg;
	uint16_t portid = rx_conf->portid;
	uint8_t qid = rx_conf->qid;

	uint64_t now;
	uint16_t nb_rx;
	struct rte_mbuf *pkts[BURST_SIZE];
	
	while(!quit_rx) {
		/* retrieve packets from the NIC */
		nb_rx = rte_eth_rx_burst(portid, qid, pkts, BURST_SIZE);
		/* retrive the current timestamp */
		now = rte_rdtsc();
		for(int i = 0; i < nb_rx; i++) {
			/* fill the timestamp into packet payload */
			fill_payload_pkt(pkts[i], 2, now);
			/* enqueue the packet to the other core to process it */
			if(rte_ring_mp_enqueue(rx_ring, pkts[i]) != 0) {
				rte_exit(EXIT_FAILURE, "Cannot enqueue the packet to the RX thread: %s.\n", rte_strerror(errno));
			}
		}
	}

	return 0;
}

/* Main TX processing */
static int lcore_tx(void *arg) {
    printf("In lcore_tx function\n");
	lcore_param *tx_conf = (lcore_param *) arg;
	uint16_t portid = tx_conf->portid;
	uint8_t qid = tx_conf->qid;

	uint16_t n = 1;
	uint16_t nb_tx;
	uint64_t i = 0;
	uint16_t nb_pkts = 0;
	uint64_t total_tx = 0;
	uint64_t nr_elements = rate * duration * nr_executions;
	struct rte_mbuf *pkts[BURST_SIZE];
	uint64_t next_tsc = rte_rdtsc() + interarrival_gap[i];

	while(!quit_tx) { 
		/* reach the limit */
		if(unlikely(i >= nr_elements)) {
			break;
		}

		/* choose the flow to send*/
		uint16_t flow_id = flow_indexes[i];
		tcp_control_block_t *block = &tcp_control_blocks[flow_id];

		/* generate packets */
		for(; nb_pkts < n; nb_pkts++) {
			pkts[nb_pkts] = rte_pktmbuf_alloc(pktmbuf_pool);
			/* fill the packet with the flow information */
			fill_tcp_packet(flow_id, pkts[nb_pkts]);
			/* fill the payload to gather server information */
			fill_payload_pkt(pkts[nb_pkts], 1, flow_id);
		}

		/* check receive window for that flow */
		uint16_t rx_wnd = rte_atomic16_read(&block->tcb_rwin);
		while(unlikely(rx_wnd < tcp_payload_size)) { 
			rx_wnd = rte_atomic16_read(&block->tcb_rwin);
		}

		/* unable to keep up with the requested rate */
		if(unlikely(rte_rdtsc() > (next_tsc + 5*TICKS_PER_US))) {
			/* count this batch as dropped */
			nr_never_sent++;
			next_tsc += interarrival_gap[i++];
			continue;
		}

		/* fill the timestamp into the packet payload */
		for(int j = 0; j < nb_pkts; j++) {
			fill_payload_pkt(pkts[j], 0, next_tsc);
		}

		/* sleep for while */
		while (rte_rdtsc() < next_tsc) {  }

		/* send the batch */
		nb_tx = rte_eth_tx_burst(portid, qid, pkts, nb_pkts);
		if(unlikely(nb_tx != nb_pkts)) {
			rte_exit(EXIT_FAILURE, "Cannot send the target packets.\n");
		}

		/* update the counter */
		nb_pkts = 0;
		total_tx += nb_tx;
		rte_atomic64_set(nr_tx, total_tx);
		next_tsc += interarrival_gap[i++];
	}

	return 0;
}

/* main function */
int main(int argc, char **argv) {
	/* init EAL */
	int ret = rte_eal_init(argc, argv);
	if(ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	}
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = app_parse_args(argc, argv);
	if(ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");
	}

	/* initialize DPDK */
	uint16_t portid = 0;
	uint16_t nr_queues = 1;
	init_DPDK(portid, nr_queues);

	/* allocate nodes for incoming packets */
	allocate_incoming_nodes();

	/* create flow indexes array */
	create_flow_indexes_array();

	/* create interarrival array */
	create_interarrival_array();
	
	/* initialize TCP control blocks */
	init_tcp_blocks();

	/* start client (3-way handshake for each flow) */
    printf("Starting client\n");
	start_client(portid);
    printf("Done with start client\n");

	/* start the RX_ring thread for packet processing */
	uint32_t id_lcore = rte_lcore_id();	
	id_lcore = rte_get_next_lcore(id_lcore, 1, 1);
	rte_eal_remote_launch(lcore_rx_ring, NULL, id_lcore);

    printf("About to start rx and tx threadsi\n");
	/* start RX and TX threads */
	for(int i = 0; i < nr_queues; i++) {
		lcore_params[i].portid = portid;
		lcore_params[i].qid = i;

		id_lcore = rte_get_next_lcore(id_lcore, 1, 1);
		rte_eal_remote_launch(lcore_rx, (void*) &lcore_params[i], id_lcore);

		id_lcore = rte_get_next_lcore(id_lcore, 1, 1);
		rte_eal_remote_launch(lcore_tx, (void*) &lcore_params[i], id_lcore);
	}

	/* wait for duration parameter */
	wait_timeout();

	/* wait for RX/TX threads */
	uint32_t lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if(rte_eal_wait_lcore(lcore_id) < 0) {
			return -1;
		}
	}

	/* print stats */
	print_stats_output();

	/* print DPDK stats */
	print_dpdk_stats(portid);

	/* clean up */
	clean_heap();
	clean_hugepages();

	return 0;
}
