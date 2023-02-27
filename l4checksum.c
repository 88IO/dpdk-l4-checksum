#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <time.h>
#include <unistd.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define COUNT_MAX 10000000

uint64_t total_packets = 0;
uint64_t total_time = 0;

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}

static inline uint64_t 
csum64_add(uint64_t a, uint64_t b) {
	a += b;
	return a + (a < b);
}

static inline uint32_t 
csum32_add(uint32_t a, uint32_t b) {
	a += b;
	return a + (a < b);
}

static inline uint16_t 
csum16_add(uint16_t a, uint16_t b) {
	a += b;
	return a + (a < b);
}

static inline uint64_t 
csum64_sub(uint64_t a, uint64_t b) {
	return a - b - (a < b);
}

static inline uint32_t 
csum32_sub(uint32_t a, uint32_t b) {
	return a - b - (a < b);
}

static inline uint16_t 
csum16_sub(uint16_t a, uint16_t b) {
	return a - b - (a < b);
}

static inline uint32_t 
csum64_add_fold(uint64_t a) {
	return csum32_add(a >> 32, a & 0xFFFFFFFF);
}

static inline uint16_t 
csum32_add_fold(uint32_t a) {
	return csum16_add(a >> 16, a & 0xFFFF);
}

static inline uint32_t 
csum64_sub_fold(uint64_t a) {
	return csum32_sub(a >> 32, ~a | 0xFFFFFFFF00000000);
}

static inline uint16_t 
csum32_sub_fold(uint32_t a) {
	return csum16_sub(a >> 16, ~a | 0xFFFF0000);
}

static __rte_noreturn void
lcore_main(void)
{
	struct rte_mbuf *bufs[BURST_SIZE], *m;
	struct rte_ether_hdr *eth;
	struct rte_ipv4_hdr *ipv4h;
	struct rte_tcp_hdr *tcph;
	char *payload;
	uint32_t l3_payload_len;
	struct timespec start, end;
	long time;

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Main work of application loop. 8< */
	for (;;) {
		/* Get burst of RX packets, from first port of pair. */
		const uint16_t nb_rx = rte_eth_rx_burst(0, 0,
				bufs, BURST_SIZE);

		if (unlikely(nb_rx == 0))
			continue;

		long sum = 0;

		for (uint16_t j = 0; j < nb_rx; j++) {
			m = bufs[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			ipv4h = (struct rte_ipv4_hdr*)(eth + 1);
			tcph = (struct rte_tcp_hdr*)((void*)ipv4h + (ipv4h->ihl << 2));
			payload = (char*)((void*)tcph + (tcph->data_off << 2));
			l3_payload_len = rte_be_to_cpu_16(ipv4h->total_length) - (ipv4h->ihl << 2);

			// l4 checksum
			tcph->cksum = 0;
			timespec_get(&start, TIME_UTC);
			#ifdef ADD32AS64
			uint32_t *pos = tcph;
			uint64_t csum = csum32_add(
				csum32_add(ipv4h->src_addr, ipv4h->dst_addr),
				(ipv4h->next_proto_id << 24) + rte_cpu_to_be_16(l3_payload_len)
			);
			for (; l3_payload_len >= 4; l3_payload_len -= 4)
				csum += *pos++;
			if (l3_payload_len > 0)
				csum += *pos & (0xFFFFFFFF >> (8 * l3_payload_len));
			tcph->cksum = ~csum32_add_fold(csum64_add_fold(csum));
			#endif
			#ifdef ADD64
			uint64_t *pos = (uint64_t*)tcph;
			uint64_t csum = csum64_add(
				*(uint64_t*)&ipv4h->src_addr,
				(ipv4h->next_proto_id << 24) + rte_cpu_to_be_16(l3_payload_len)
			);
			for (; l3_payload_len >= 8; l3_payload_len -= 8)
				csum = csum64_add(csum, *pos++);
			if (l3_payload_len > 0)
				csum = csum64_add(csum, *pos & (0xFFFFFFFFFFFFFFFF >> (8 * l3_payload_len)));
			tcph->cksum = ~csum32_add_fold(csum64_add_fold(csum));
			#endif
			#ifdef ADD32
			uint32_t *pos = tcph;
			uint32_t csum = csum32_add(
				csum32_add(ipv4h->src_addr, ipv4h->dst_addr),
				(ipv4h->next_proto_id << 24) + rte_cpu_to_be_16(l3_payload_len)
			);
			for (; l3_payload_len >= 4; l3_payload_len -= 4)
				csum = csum32_add(csum, *pos++);
			if (l3_payload_len > 0)
				csum = csum32_add(csum, *pos & (0xFFFFFFFF >> (8 * l3_payload_len)));
			tcph->cksum = ~csum32_add_fold(csum);
			#endif
			#ifdef ADD16
			uint16_t *pos = tcph;
			uint16_t csum = csum16_add(
				csum16_add(ipv4h->src_addr >> 16, ipv4h->src_addr & 0xFFFF),
				csum16_add(ipv4h->dst_addr >> 16, ipv4h->dst_addr & 0xFFFF)
			);
			csum = csum16_add(
				csum,
				csum16_add(ipv4h->next_proto_id << 8, rte_cpu_to_be_16(l3_payload_len))
			);
			for (; l3_payload_len >= 2; l3_payload_len -= 2)
				csum = csum16_add(csum, *pos++);
			if (l3_payload_len > 0)
				csum = csum16_add(csum, *pos & 0xFF);
			tcph->cksum = ~csum;
			#endif	
			#ifdef SUB64
			uint64_t *pos = tcph;
			uint64_t csum = csum64_sub(
				(ipv4h->next_proto_id << 24) + rte_cpu_to_be_16(l3_payload_len),
				~*(uint64_t*)&ipv4h->src_addr
			);
			for (; l3_payload_len >= 8; l3_payload_len -= 8)
				csum = csum64_sub(*pos++, ~csum);
			if (l3_payload_len > 0)
				csum = csum64_sub(*pos & (0xFFFFFFFFFFFFFFFF >> (8 * l3_payload_len)), ~csum);
			tcph->cksum = ~csum32_sub_fold(csum64_sub_fold(csum));
			#endif
			#ifdef SUB32
			uint32_t *pos = tcph;
			uint32_t csum = csum32_sub(
				(ipv4h->next_proto_id << 24) + rte_cpu_to_be_16(l3_payload_len),
				~csum32_sub(ipv4h->src_addr, ~ipv4h->dst_addr)
			);
			for (; l3_payload_len >= 4; l3_payload_len -= 4)
				csum = csum32_sub(*pos++, ~csum);
			if (l3_payload_len > 0)
				csum = csum32_sub(*pos & (0xFFFFFFFF >> (8 * l3_payload_len)), ~csum);
			tcph->cksum = ~csum32_sub_fold(csum);
			#endif
			#ifdef SUB16
			uint16_t *pos = tcph;
			uint16_t csum = csum16_sub(
				csum16_sub(ipv4h->src_addr >> 16, ~(ipv4h->src_addr & 0xFFFF)),
				~csum16_sub(ipv4h->dst_addr >> 16, ~(ipv4h->dst_addr & 0xFFFF))
			);
			csum = csum16_sub(
				csum16_sub(ipv4h->next_proto_id << 8, ~rte_cpu_to_be_16(l3_payload_len)),
				~csum
			);
			for (; l3_payload_len >= 2; l3_payload_len -= 2)
				csum = csum16_sub(*pos++, ~csum);
			if (l3_payload_len > 0)
				csum = csum16_sub(*pos & 0xFF, ~csum);
			tcph->cksum = ~csum;
			#endif
			timespec_get(&end, TIME_UTC);
			
			time = (end.tv_sec - start.tv_sec) * 1000000000
						+ (end.tv_nsec - start.tv_nsec);
			sum += time;

			total_time += time;
			total_packets++;
			if (total_packets == COUNT_MAX) {
				rte_exit(EXIT_SUCCESS, "total packets = %lu, per packet = %lu ns\n", 
					total_packets, total_time / total_packets);
			}
		}

		printf("ave[tatal = %d] = %ld\n", nb_rx, sum / nb_rx);

		/* Send burst of TX packets, to second port of pair. */
		const uint16_t nb_tx = rte_eth_tx_burst(1, 0,
				bufs, nb_rx);

		if (unlikely(nb_tx < nb_rx)) {
			uint16_t buf;
			for (buf = nb_tx; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
