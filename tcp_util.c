#include "tcp_util.h"

extern uint64_t is_single_buf;
int single_buf_arr[1044] = {0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 4, 0, 0, 16, 0, 0, 0, 102, 79, 81, 86, 70, 75, 49, 112, 120, 120, 112, 104, 108, 66, 117, 117, 51, 97, 54, 68, 105, 113, 104, 103, 66, 89, 71, 89, 80, 71, 83, 52, 68, 75, 49, 118, 49, 114, 118, 71, 48, 109, 57, 48, 117, 103, 90, 107, 106, 114, 114, 111, 108, 85, 71, 73, 121, 57, 57, 117, 105, 98, 51, 80, 98, 109, 122, 66, 107, 76, 66, 80, 104, 121, 83, 76, 103, 113, 55, 112, 120, 73, 114, 119, 57, 103, 114, 103, 85, 105, 76, 75, 119, 89, 116, 50, 100, 97, 76, 110, 79, 68, 79, 56, 81, 82, 79, 110, 109, 52, 112, 86, 104, 122, 106, 120, 57, 73, 50, 100, 86, 77, 122, 54, 69, 109, 65, 52, 121, 83, 114, 70, 54, 119, 119, 83, 52, 71, 100, 117, 53, 90, 97, 122, 106, 48, 118, 77, 48, 113, 56, 54, 65, 106, 114, 113, 68, 119, 104, 122, 86, 81, 121, 99, 117, 73, 78, 81, 111, 71, 99, 97, 52, 82, 114, 54, 49, 70, 119, 107, 110, 76, 104, 68, 81, 119, 80, 101, 105, 76, 90, 86, 81, 73, 84, 99, 76, 48, 110, 105, 111, 69, 117, 99, 50, 72, 57, 110, 49, 70, 88, 120, 80, 97, 55, 70, 117, 120, 122, 99, 86, 85, 80, 67, 79, 57, 119, 102, 111, 84, 114, 121, 89, 71, 53, 73, 114, 50, 111, 66, 102, 57, 120, 70, 69, 65, 97, 121, 50, 121, 89, 119, 109, 78, 70, 88, 116, 99, 78, 52, 112, 68, 48, 104, 81, 121, 80, 113, 114, 117, 85, 115, 97, 115, 106, 119, 80, 86, 76, 99, 89, 87, 112, 120, 78, 73, 86, 52, 99, 106, 116, 68, 71, 101, 116, 102, 82, 55, 78, 112, 90, 115, 73, 57, 118, 80, 111, 77, 50, 116, 108, 109, 86, 82, 72, 68, 103, 112, 105, 103, 110, 70, 48, 111, 116, 83, 83, 109, 102, 66, 118, 53, 74, 122, 108, 48, 89, 66, 102, 56, 89, 73, 88, 104, 53, 54, 100, 82, 105, 66, 106, 80, 108, 102, 66, 80, 87, 71, 51, 121, 71, 54, 81, 81, 76, 101, 102, 117, 54, 80, 111, 66, 114, 67, 112, 78, 71, 71, 81, 98, 72, 86, 66, 67, 67, 104, 74, 86, 87, 66, 72, 99, 82, 107, 103, 122, 67, 67, 48, 51, 113, 115, 97, 76, 68, 53, 109, 111, 88, 56, 79, 113, 110, 108, 119, 73, 83, 51, 114, 77, 100, 57, 113, 57, 103, 99, 49, 55, 120, 54, 115, 85, 110, 81, 68, 121, 69, 76, 103, 114, 79, 54, 87, 54, 85, 89, 79, 68, 74, 67, 109, 98, 99, 57, 102, 118, 51, 118, 70, 104, 52, 108, 77, 67, 49, 56, 69, 102, 68, 78, 89, 112, 104, 72, 90, 73, 116, 83, 118, 86, 75, 119, 67, 78, 103, 118, 54, 81, 70, 89, 66, 82, 97, 120, 84, 115, 68, 107, 118, 56, 68, 108, 67, 81, 122, 104, 86, 108, 65, 55, 48, 87, 114, 69, 79, 121, 67, 103, 77, 118, 79, 81, 120, 81, 113, 113, 55, 97, 106, 109, 78, 71, 87, 71, 121, 69, 84, 51, 69, 80, 117, 86, 82, 75, 55, 120, 69, 77, 74, 109, 75, 107, 55, 88, 116, 112, 71, 83, 121, 111, 104, 87, 69, 103, 105, 109, 107, 70, 72, 71, 77, 113, 108, 106, 86, 116, 50, 77, 98, 73, 79, 117, 72, 51, 116, 89, 74, 108, 48, 118, 85, 114, 79, 57, 86, 68, 122, 57, 89, 53, 120, 104, 69, 109, 70, 84, 56, 104, 48, 76, 85, 48, 77, 50, 73, 122, 120, 68, 54, 79, 51, 54, 57, 66, 82, 65, 54, 80, 114, 104, 76, 66, 75, 49, 55, 52, 71, 48, 66, 108, 103, 122, 48, 109, 77, 111, 52, 72, 76, 118, 111, 70, 86, 76, 56, 105, 108, 107, 103, 79, 89, 76, 74, 120, 100, 57, 66, 82, 99, 84, 79, 83, 121, 52, 118, 101, 83, 67, 103, 56, 78, 105, 82, 55, 85, 55, 75, 110, 98, 55, 117, 105, 51, 73, 56, 110, 121, 82, 107, 69, 79, 77, 110, 72, 122, 52, 114, 81, 69, 84, 98, 108, 69, 110, 49, 121, 78, 76, 87, 120, 100, 79, 89, 107, 117, 113, 55, 48, 49, 78, 74, 103, 65, 114, 115, 83, 101, 98, 88, 57, 121, 115, 100, 105, 100, 65, 98, 106, 53, 90, 66, 122, 67, 85, 80, 81, 52, 110, 106, 69, 83, 75, 98, 79, 97, 49, 54, 76, 106, 111, 73, 98, 114, 50, 112, 87, 74, 109, 72, 100, 111, 108, 102, 109, 82, 90, 102, 100, 65, 103, 114, 99, 106, 114, 83, 89, 84, 110, 115, 50, 83, 81, 97, 103, 67, 67, 102, 77, 97, 87, 113, 117, 108, 76, 113, 66, 66, 97, 79, 53, 116, 102, 85, 89, 56, 108, 115, 122, 106, 114, 99, 69, 90, 82, 76, 52, 87, 100, 97, 109, 55, 122, 106, 49, 48, 68, 81, 76, 121, 103, 85, 88, 84, 83, 103, 103, 89, 105, 104, 66, 90, 49, 55, 111, 55, 80, 116, 114, 66, 69, 55, 101, 101, 73, 69, 86, 86, 72, 86, 72, 113, 107, 77, 120, 78, 83, 90, 106, 100, 81, 79, 89, 112, 57, 103, 117, 72, 82, 120, 100, 110, 116, 73, 50, 121, 86, 79, 72, 49, 90, 55, 116, 49, 55, 73, 110, 48, 69, 73, 82, 117, 52, 72, 102, 74, 103, 70, 111, 78, 56, 116, 112, 78, 99, 56, 79, 80, 81, 67, 98, 77, 104, 73, 77, 90, 52, 112, 97, 122, 120, 87, 98, 87, 79, 97, 84, 78, 87, 119, 78, 105, 99, 81, 48, 56, 48, 97, 68, 114, 52, 114, 116, 71, 90, 85, 56, 116, 97, 120, 55, 85, 82, 120, 79, 90, 68, 72, 69, 119, 56, 83, 97, 76, 68, 90, 101, 106, 69, 56, 104, 85, 87, 109, 68, 110, 72, 113, 83, 113, 50, 69, 69, 122, 98, 56, 105, 85, 86, 118, 121, 103, 50, 104, 76};

int list_2_buf_arr[1052] = {0, 1, 0, 2, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 0, 2, 0, 0, 32, 0, 0, 0, 0, 2, 0, 0, 32, 2, 0, 0, 104, 101, 122, 79, 102, 71, 81, 48, 102, 50, 72, 84, 50, 83, 102, 84, 75, 77, 112, 76, 78, 66, 51, 103, 79, 86, 103, 99, 107, 56, 83, 67, 79, 97, 48, 106, 52, 75, 57, 88, 79, 76, 98, 53, 56, 109, 56, 107, 72, 113, 49, 105, 102, 69, 98, 77, 100, 77, 48, 76, 101, 66, 73, 81, 105, 84, 83, 105, 53, 65, 108, 113, 84, 101, 76, 54, 102, 70, 97, 70, 115, 99, 52, 74, 89, 104, 105, 120, 65, 107, 121, 51, 54, 50, 87, 66, 52, 76, 112, 84, 82, 99, 69, 50, 112, 56, 119, 97, 112, 105, 114, 86, 84, 108, 88, 108, 107, 104, 87, 73, 111, 84, 106, 102, 87, 88, 71, 111, 65, 89, 121, 48, 70, 84, 98, 71, 103, 49, 74, 72, 99, 101, 108, 52, 118, 119, 71, 99, 52, 102, 99, 115, 120, 79, 71, 77, 89, 116, 114, 70, 85, 86, 72, 115, 48, 78, 109, 76, 73, 89, 119, 104, 80, 111, 56, 66, 111, 66, 107, 79, 86, 49, 80, 90, 49, 99, 55, 75, 110, 106, 54, 104, 48, 106, 55, 69, 56, 52, 118, 66, 119, 82, 52, 114, 117, 117, 99, 105, 80, 102, 70, 108, 48, 86, 65, 120, 88, 54, 69, 116, 120, 105, 109, 117, 97, 117, 120, 54, 98, 74, 85, 111, 114, 49, 84, 87, 89, 49, 81, 87, 52, 68, 122, 90, 104, 80, 118, 52, 122, 120, 83, 77, 82, 55, 110, 66, 114, 115, 119, 102, 122, 77, 84, 57, 79, 79, 80, 120, 57, 120, 98, 52, 52, 98, 75, 97, 57, 80, 56, 98, 115, 105, 56, 76, 52, 72, 53, 121, 87, 110, 79, 53, 71, 86, 101, 114, 49, 54, 115, 115, 116, 73, 69, 118, 100, 54, 88, 66, 81, 83, 108, 52, 74, 121, 120, 49, 70, 108, 102, 101, 74, 114, 79, 115, 54, 83, 51, 99, 72, 49, 74, 77, 84, 67, 101, 72, 88, 102, 118, 50, 112, 101, 119, 71, 90, 115, 115, 103, 76, 87, 70, 88, 50, 55, 48, 101, 118, 115, 109, 76, 118, 106, 74, 111, 77, 82, 66, 54, 78, 52, 75, 87, 98, 114, 116, 85, 49, 68, 104, 81, 74, 74, 120, 119, 57, 115, 106, 115, 100, 101, 107, 85, 113, 80, 69, 68, 89, 111, 67, 97, 50, 115, 110, 81, 57, 50, 77, 90, 81, 101, 103, 106, 111, 66, 79, 65, 72, 102, 113, 118, 83, 69, 110, 119, 54, 81, 112, 78, 48, 70, 112, 122, 116, 109, 83, 75, 90, 85, 53, 104, 100, 109, 57, 122, 108, 121, 114, 81, 119, 113, 110, 111, 71, 57, 68, 77, 48, 52, 114, 56, 67, 84, 115, 48, 71, 110, 115, 88, 48, 111, 121, 55, 86, 100, 55, 76, 102, 51, 66, 85, 70, 79, 76, 50, 86, 98, 90, 74, 57, 57, 104, 103, 107, 112, 80, 102, 119, 116, 104, 105, 85, 70, 104, 112, 120, 106, 52, 53, 110, 85, 52, 119, 104, 72, 113, 121, 67, 113, 90, 74, 74, 65, 106, 118, 52, 122, 67, 117, 110, 75, 103, 72, 71, 117, 114, 66, 49, 52, 49, 77, 68, 55, 78, 67, 100, 65, 99, 55, 69, 116, 112, 54, 113, 100, 103, 51, 50, 55, 77, 118, 102, 55, 51, 86, 49, 107, 80, 85, 82, 74, 80, 55, 89, 106, 84, 108, 72, 67, 111, 103, 72, 100, 122, 110, 74, 118, 57, 113, 66, 57, 82, 78, 105, 54, 53, 54, 51, 101, 76, 50, 69, 87, 54, 77, 85, 71, 112, 97, 81, 110, 48, 120, 98, 57, 118, 71, 54, 69, 118, 52, 56, 73, 104, 88, 86, 78, 75, 105, 115, 108, 74, 121, 57, 80, 100, 119, 79, 55, 48, 113, 80, 65, 116, 89, 70, 118, 103, 87, 76, 104, 83, 86, 77, 120, 111, 104, 85, 115, 83, 115, 109, 110, 112, 51, 113, 102, 83, 82, 107, 113, 72, 71, 108, 101, 117, 111, 82, 67, 117, 90, 107, 70, 88, 78, 48, 51, 104, 121, 100, 119, 105, 113, 54, 121, 67, 65, 99, 81, 55, 83, 80, 50, 70, 118, 105, 68, 115, 103, 70, 113, 88, 52, 70, 84, 105, 75, 101, 48, 101, 118, 120, 86, 79, 84, 108, 98, 98, 79, 114, 66, 73, 82, 118, 48, 75, 85, 71, 88, 71, 50, 106, 53, 50, 113, 86, 82, 69, 101, 82, 79, 71, 114, 86, 105, 76, 97, 76, 89, 111, 50, 86, 77, 121, 75, 78, 53, 113, 119, 76, 121, 98, 72, 107, 107, 79, 102, 120, 83, 78, 115, 89, 83, 121, 111, 121, 57, 117, 49, 68, 90, 84, 79, 85, 116, 67, 110, 69, 108, 84, 104, 102, 69, 77, 113, 121, 76, 108, 53, 70, 106, 79, 52, 119, 119, 77, 66, 53, 98, 55, 99, 101, 53, 119, 84, 85, 57, 108, 65, 109, 54, 84, 109, 75, 111, 115, 101, 117, 86, 74, 75, 57, 101, 77, 120, 66, 109, 49, 84, 84, 109, 115, 117, 53, 70, 88, 74, 107, 105, 103, 97, 73, 67, 113, 120, 55, 49, 110, 88, 75, 85, 76, 122, 90, 82, 78, 71, 76, 69, 74, 100, 85, 55, 65, 56, 84, 83, 49, 56, 78, 115, 73, 109, 113, 112, 52, 73, 108, 110, 112, 87, 72, 75, 73, 100, 109, 49, 117, 75, 71, 68, 69, 80, 83, 108, 118, 116, 122, 101, 101, 117, 101, 108, 70, 75, 105, 66, 50, 108, 114, 74, 67, 78, 106, 69, 104, 107, 76, 108, 99, 81, 74, 121, 49, 69, 98, 85, 66, 107, 66, 104, 121, 53, 102, 121, 52, 118, 50, 121, 54, 120, 85, 77, 57, 86, 100, 52, 101, 78, 110, 55, 121, 106, 121, 84, 77, 75, 121, 121, 52, 90, 75, 70, 111, 99, 98, 89, 84, 100, 65, 80, 115, 83, 114, 56, 119, 54, 101, 87, 84, 115, 115, 122, 57, 84, 51, 54, 67, 106, 99, 120, 82, 83, 70, 106, 101, 97, 122, 57, 75, 87, 100, 118, 122, 104};


/* Shuffle the TCP source port array */
void shuffle(uint16_t* arr, uint32_t n) {
	if(n < 2) {
		return;
	}

	for(uint32_t i = 0; i < n - 1; i++) {
		uint32_t j = i + rte_rand() / (UINT64_MAX / (n - i) + 1);
		uint16_t tmp = arr[j];
		arr[j] = arr[i];
		arr[i] = tmp;
	}
}

/* Create and Initialize the TCP Control Blocks for all flows */
void init_tcp_blocks() {
	/* allocate the all control block structure previosly */
	tcp_control_blocks = (tcp_control_block_t *) rte_zmalloc("tcp_control_blocks", nr_flows * sizeof(tcp_control_block_t), RTE_CACHE_LINE_SIZE);

	/* choose TCP source port for all flows */
    uint16_t src_tcp_port;
    uint16_t ports[nr_flows];
	for(uint32_t i = 0; i < nr_flows; i++) {
		ports[i] = rte_cpu_to_be_16(i + 1);
	}
	/* shuffle port array */
	shuffle(ports, nr_flows);

	for(uint32_t i = 0; i < nr_flows; i++) {
		rte_atomic16_init(&tcp_control_blocks[i].tcb_state);
		rte_atomic16_set(&tcp_control_blocks[i].tcb_state, TCP_INIT);
		rte_atomic16_set(&tcp_control_blocks[i].tcb_rwin, 0xFFFF);

		src_tcp_port = ports[i];

        tcp_control_blocks[i].src_addr = src_ipv4_addr;
        tcp_control_blocks[i].dst_addr = dst_ipv4_addr;

        tcp_control_blocks[i].src_port = src_tcp_port;
        tcp_control_blocks[i].dst_port = rte_cpu_to_be_16(dst_tcp_port + (i % nr_apps));

		uint32_t seq = rte_rand();
		tcp_control_blocks[i].tcb_seq_ini = seq;
		tcp_control_blocks[i].tcb_next_seq = seq;

        tcp_control_blocks[i].flow_mark_action.id = i;
        tcp_control_blocks[i].flow_queue_action.index = 0;
        tcp_control_blocks[i].flow_eth.type = ETH_IPV4_TYPE_NETWORK;
        tcp_control_blocks[i].flow_eth_mask.type = 0xFFFF;
        tcp_control_blocks[i].flow_ipv4.hdr.src_addr = tcp_control_blocks[i].dst_addr;
        tcp_control_blocks[i].flow_ipv4.hdr.dst_addr = tcp_control_blocks[i].src_addr;
        tcp_control_blocks[i].flow_ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
        tcp_control_blocks[i].flow_ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
        tcp_control_blocks[i].flow_tcp.hdr.src_port = tcp_control_blocks[i].dst_port;
        tcp_control_blocks[i].flow_tcp.hdr.dst_port = tcp_control_blocks[i].src_port;
        tcp_control_blocks[i].flow_tcp_mask.hdr.src_port = 0xFFFF;
        tcp_control_blocks[i].flow_tcp_mask.hdr.dst_port = 0xFFFF;
	}
}

/* Create the TCP SYN packet */
struct rte_mbuf* create_syn_packet(uint16_t i) {
	/* allocate TCP SYN packet in the hugepages */
	struct rte_mbuf* pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	if(pkt == NULL) {
		rte_exit(EXIT_FAILURE, "Error to alloc a rte_mbuf.\n");
	}

	/* ensure that IP/TCP checksum offloadings */
	pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM);

	/* get control block for the flow */
	tcp_control_block_t *block = &tcp_control_blocks[i];

	/* fill Ethernet information */
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->dst_addr = dst_eth_addr;
	eth_hdr->src_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

	/* fill IPv4 information */
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
	ipv4_hdr->time_to_live = 255;
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->next_proto_id = IPPROTO_TCP;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->src_addr = block->src_addr;
	ipv4_hdr->dst_addr = block->dst_addr;
	ipv4_hdr->hdr_checksum = 0;

	/* fill TCP information */
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp_hdr->dst_port = block->dst_port;
	tcp_hdr->src_port = block->src_port;
	tcp_hdr->data_off = 0x50;
	tcp_hdr->sent_seq = block->tcb_seq_ini;
	tcp_hdr->recv_ack = 0;
	tcp_hdr->rx_win = 0xFFFF;
	tcp_hdr->tcp_flags = RTE_TCP_SYN_FLAG;
	tcp_hdr->tcp_urp = 0;
	tcp_hdr->cksum = 0;

	/* fill the packet size */
	pkt->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
	pkt->pkt_len = pkt->data_len;

	return pkt;
}

/* Create the TCP ACK packet */
struct rte_mbuf *create_ack_packet(uint16_t i) {
	/* allocate TCP ACK packet in the hugepages */
	struct rte_mbuf* pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	if(pkt == NULL) {
		rte_exit(EXIT_FAILURE, "Error to alloc a rte_mbuf.\n");
	}

	/* ensure that IP/TCP checksum offloadings */
	pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM);

	/* get control block for the flow */
	tcp_control_block_t *block = &tcp_control_blocks[i];

	/* fill Ethernet information */
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->dst_addr = dst_eth_addr;
	eth_hdr->src_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

	/* fill IPv4 information */
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
	ipv4_hdr->time_to_live = 255;
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->next_proto_id = IPPROTO_TCP;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->src_addr = block->src_addr;
	ipv4_hdr->dst_addr = block->dst_addr;
	ipv4_hdr->hdr_checksum = 0;

	/* set the TCP SEQ number */
	uint32_t newseq = rte_cpu_to_be_32(rte_be_to_cpu_32(block->tcb_next_seq) + 1);
	block->tcb_next_seq = newseq;

	/* fill TCP information */
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp_hdr->dst_port = block->dst_port;
	tcp_hdr->src_port = block->src_port;
	tcp_hdr->data_off = 0x50;
	tcp_hdr->sent_seq = newseq;
	tcp_hdr->recv_ack = rte_atomic32_read(&block->tcb_next_ack);
	tcp_hdr->rx_win = 0xFFFF;
	tcp_hdr->tcp_flags = RTE_TCP_ACK_FLAG;
	tcp_hdr->tcp_urp = 0;
	tcp_hdr->cksum = 0;

	/* fill the packet size */
	pkt->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
	pkt->pkt_len = pkt->data_len;

	return pkt;
}

/* Process the TCP SYN+ACK packet and return the TCP ACK */
struct rte_mbuf* process_syn_ack_packet(struct rte_mbuf* pkt) {
	/* process only IPv4 packets*/
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	if(eth_hdr->ether_type != ETH_IPV4_TYPE_NETWORK) {
		return NULL;
	}

	/* process only TCP packets*/
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	if(ipv4_hdr->next_proto_id != IPPROTO_TCP) {
		return NULL;
	}

	/* get TCP header */
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + (ipv4_hdr->version_ihl & 0x0f)*4);

	/* retrieve the index of the flow from the NIC (NIC tags the packet according the 5-tuple using DPDK rte_flow) */
	uint32_t idx = pkt->hash.fdir.hi;

	/* get control block for the flow */
	tcp_control_block_t *block = &tcp_control_blocks[idx];

	/* get the TCP control block state */
	uint8_t state = rte_atomic16_read(&block->tcb_state);

	/* process only in SYN_SENT state and SYN+ACK packet */
	if((state == TCP_SYN_SENT) && (tcp_hdr->tcp_flags == (RTE_TCP_SYN_FLAG|RTE_TCP_ACK_FLAG))) {
		/* update the TCP state to ESTABLISHED */
		rte_atomic16_set(&block->tcb_state, TCP_ESTABLISHED);

		/* get the TCP SEQ number */
		uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);

		/* update TCP SEQ and ACK numbers */
		rte_atomic32_set(&block->tcb_next_ack, rte_cpu_to_be_32(seq + 1));
		block->tcb_ack_ini = tcp_hdr->sent_seq;

		/* return TCP ACK packet */
		return create_ack_packet(idx);
	}

	return NULL;
}

/* Fill the TCP packets from TCP Control Block data */
void fill_tcp_packet(uint16_t i, struct rte_mbuf *pkt) {
	/* get control block for the flow */
	tcp_control_block_t *block = &tcp_control_blocks[i];

	/* ensure that IP/TCP checksum offloadings */
	pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM);

	/* fill Ethernet information */
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->dst_addr = dst_eth_addr;
	eth_hdr->src_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

	/* fill IPv4 information */
	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->total_length = rte_cpu_to_be_16(frame_size - sizeof(struct rte_ether_hdr));
	ipv4_hdr->time_to_live = 255;
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->next_proto_id = IPPROTO_TCP;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->src_addr = block->src_addr;
	ipv4_hdr->dst_addr = block->dst_addr;
	ipv4_hdr->hdr_checksum = 0;

	/* set the TCP SEQ number */
	uint32_t sent_seq = block->tcb_next_seq;

	/* fill TCP information */
	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp_hdr->dst_port = block->dst_port;
	tcp_hdr->src_port = block->src_port;
	tcp_hdr->data_off = 0x50;
	tcp_hdr->sent_seq = sent_seq;
	tcp_hdr->recv_ack = rte_atomic32_read(&block->tcb_next_ack);
	tcp_hdr->rx_win = 0xFFFF;
	tcp_hdr->tcp_flags = RTE_TCP_ACK_FLAG;
	tcp_hdr->tcp_urp = 0;
	tcp_hdr->cksum = 0;

	/* updates the TCP SEQ number */
	sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(sent_seq) + tcp_payload_size);
	block->tcb_next_seq = sent_seq;

	/* fill the payload of the packet */
	uint8_t *payload = ((uint8_t*)tcp_hdr) + sizeof(struct rte_tcp_hdr);
	fill_tcp_payload(payload, tcp_payload_size);

	/* fill the packet size */
	pkt->data_len = frame_size;
	pkt->pkt_len = pkt->data_len;
}

/* Fill the payload of the TCP packet */
void fill_tcp_payload(uint8_t *payload, uint32_t length) {
	if (is_single_buf) {
		length = 1044;
		for(uint32_t i = 0; i < length; i++) {
			payload[i] = (uint8_t) single_buf_arr[i];
		}
	} else {
		length = 1060;
		for(uint32_t i = 0; i < length; i++) {
			payload[i] = (uint8_t) list_2_buf_arr[i];
		}

	}
}

