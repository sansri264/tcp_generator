#include "tcp_util.h"

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
	tcp_control_blocks = (tcp_control_block_t *) rte_zmalloc("tcp_control_blocks", nr_flows * sizeof(tcp_control_block_t), RTE_CACHE_LINE_SIZE);

    uint16_t src_tcp_port;
    uint16_t ports[nr_flows];
	for(uint32_t i = 0; i < nr_flows; i++) {
		ports[i] = i + 1;
	}
	shuffle(ports, nr_flows);

	for(uint32_t i = 0; i < nr_flows; i++) {
		rte_atomic16_init(&tcp_control_blocks[i].tcb_state);
		rte_atomic16_set(&tcp_control_blocks[i].tcb_state, TCP_INIT);
		rte_atomic16_set(&tcp_control_blocks[i].tcb_rwin, 0xFFFF);

		src_tcp_port = ports[i];

        tcp_control_blocks[i].src_addr = src_ipv4_addr;
        tcp_control_blocks[i].dst_addr = dst_ipv4_addr;

        tcp_control_blocks[i].src_port = src_tcp_port;
        tcp_control_blocks[i].dst_port = dst_tcp_port;

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
	struct rte_mbuf* pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	if(pkt == NULL) {
		rte_exit(EXIT_FAILURE, "Error to alloc a rte_mbuf.\n");
	}

	pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM);
	tcp_control_block_t *block = &tcp_control_blocks[i];

	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->d_addr = dst_eth_addr;
	eth_hdr->s_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

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

	pkt->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
	pkt->pkt_len = pkt->data_len;

	return pkt;
}

/* Create the TCP ACK packet */
struct rte_mbuf *create_ack_packet(uint16_t i) {
	struct rte_mbuf* pkt = rte_pktmbuf_alloc(pktmbuf_pool);
	if(pkt == NULL) {
		rte_exit(EXIT_FAILURE, "Error to alloc a rte_mbuf.\n");
	}

	pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM);
	tcp_control_block_t *block = &tcp_control_blocks[i];

	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->d_addr = dst_eth_addr;
	eth_hdr->s_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

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

	uint32_t newseq = rte_cpu_to_be_32(rte_be_to_cpu_32(block->tcb_next_seq) + 1);
	block->tcb_next_seq = newseq;

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

	pkt->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
	pkt->pkt_len = pkt->data_len;

	return pkt;
}

/* Process the TCP SYN+ACK packet and return the TCP ACK */
struct rte_mbuf* process_syn_ack_packet(struct rte_mbuf* pkt) {
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	if(eth_hdr->ether_type != ETH_IPV4_TYPE_NETWORK)
		return NULL;

	struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	if(ipv4_hdr->next_proto_id != IPPROTO_TCP)
		return NULL;

	struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + (ipv4_hdr->version_ihl & 0x0f)*4);

	uint32_t idx = pkt->hash.fdir.hi;
	tcp_control_block_t *block = &tcp_control_blocks[idx];

	uint8_t state = rte_atomic16_read(&block->tcb_state);

	if((state == TCP_SYN_SENT) && (tcp_hdr->tcp_flags == (RTE_TCP_SYN_FLAG|RTE_TCP_ACK_FLAG))) {
		rte_atomic16_set(&block->tcb_state, TCP_ESTABLISHED);

		uint32_t seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);

		rte_atomic32_set(&block->tcb_next_ack, rte_cpu_to_be_32(seq + 1));
		block->tcb_ack_ini = tcp_hdr->sent_seq;

		return create_ack_packet(idx);
	}

	return NULL;
}

/* Fill the TCP packets from TCP Control Block data */
void fill_tcp_packet(uint16_t i, struct rte_mbuf *pkt) {
	tcp_control_block_t *block = &tcp_control_blocks[i];

	pkt->ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM);

	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_mtod(pkt, struct ether_hdr*);
	eth_hdr->d_addr = dst_eth_addr;
	eth_hdr->s_addr = src_eth_addr;
	eth_hdr->ether_type = ETH_IPV4_TYPE_NETWORK;

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

	uint32_t sent_seq = block->tcb_next_seq;

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

	sent_seq = rte_cpu_to_be_32(rte_be_to_cpu_32(sent_seq) + tcp_payload_size);
	block->tcb_next_seq = sent_seq;

	pkt->data_len = frame_size;
	pkt->pkt_len = pkt->data_len;
}