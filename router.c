#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define ARP_TABLE "arp_table.txt"

#define IPv4 0x0800
#define ARP 0x0806

void init_router(int argc, char **argv);
void handle_ip_packet(char packet[], size_t len, int interface);
void update_ttl(char packet[]);
struct route_table_entry *get_next_hop(uint32_t ip_dest);
struct arp_entry *get_arp_entry(uint32_t given_ip);
void check_resend_queue();

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;

queue resend_queue;

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init_router(argc, argv);

	while (1) {
		int interface;
		size_t len;

		printf("Waiting for link\n");
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		switch (ntohs(eth_hdr->ether_type)) {
		case IPv4:
			printf("IPv4\n");
			handle_ip_packet(buf, len, interface);
			break;
		case ARP:
			printf("ARP\n");
			break;
		default:
			fprintf(stderr, "- Unknown EthernetType -\nSkipping...\n");
			break;
		}
	}

	return 0;
}

void init_router(int argc, char **argv) {
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	arp_table = malloc(sizeof(struct arp_entry) * 6);

	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table(ARP_TABLE, arp_table);

	// Do not modify this line
	init(argc - 2, argv + 2);
	resend_queue = queue_create();
}

void check_resend_queue() {
	int queue_len = queue_length(resend_queue);

	for (int i = 0; i < queue_len; i++) {
		void *deq_packet = queue_deq(resend_queue);
		struct ether_header *deq_eth_hdr = (struct ether_header *) deq_packet;
		struct iphdr *deq_ip_hdr = (struct iphdr *)(deq_packet + sizeof(struct ether_header));

		struct arp_entry *check_arp = get_arp_entry(deq_ip_hdr->daddr);

		if (check_arp) {
			memcpy(deq_eth_hdr->ether_dhost, check_arp->mac, 6);
			send_to_link(get_next_hop(deq_ip_hdr->daddr)->interface, deq_packet, deq_ip_hdr->tot_len + sizeof(struct ether_header));
		} else {
			queue_enq(resend_queue, deq_packet);
		}
	}
}

void handle_ip_packet(char packet[], size_t len, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	if (strcmp((char *) &ip_hdr->daddr, get_interface_ip(interface))) {
		
	}

	if (ntohs(ip_hdr->check) != checksum((uint16_t *) ip_hdr, sizeof(struct iphdr))) {
		printf("Checksum: (GOOD)\n");
	} else {
		printf("Checksum: (BAD)\n");
		return;
	}

	if (ip_hdr->ttl <= 1) {
		printf("Time exceeded!\n");
		return;
	}

	struct route_table_entry *next_rtable_entry = get_next_hop(ip_hdr->daddr);

	if (!next_rtable_entry) {
		printf("Destination unreachable!\n");
		return;
	}

	update_ttl(packet);
	get_interface_mac(interface, eth_hdr->ether_shost);

	struct arp_entry *new_eth_dhost = get_arp_entry(next_rtable_entry->next_hop);
	if (!new_eth_dhost) {
		queue_enq(resend_queue, packet);
		send_brd_arp_request(next_rtable_entry->next_hop, next_rtable_entry->interface);
		
		printf("Packet waiting for ARP\n");
		return;
	}

	memcpy(eth_hdr->ether_dhost, new_eth_dhost->mac, 6);
	send_to_link(next_rtable_entry->interface, packet, ip_hdr->tot_len + sizeof(struct ether_header));
}

void update_ttl(char packet[]) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	ip_hdr->ttl--;

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
}

void send_brd_arp_request(uint32_t req_ip, int interface) {
	char packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
	struct ether_header *eth_hdr = (struct ether_header*) malloc(sizeof(struct ether_header));

	get_interface_mac(interface, eth_hdr->ether_shost);
	hwaddr_aton("ff.ff.ff.ff.ff.ff", eth_hdr->ether_dhost);
	eth_hdr->ether_type = htons(ARP);

	struct arp_header *arp_hdr = (struct arp_header*) malloc(sizeof(struct arp_header));
	uint16_t htype = 1;
	arp_hdr->htype = htons(htype);
	arp_hdr->ptype = htons(IPv4);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = 1;
	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	hwaddr_aton("00.00.00.00.00.00", arp_hdr->tha);
	// poate trebuie htonl !!
	arp_hdr->tpa = req_ip;

	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	free(eth_hdr);
	free(arp_hdr);

	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}

struct route_table_entry *get_next_hop(uint32_t ip_dest) {
	struct route_table_entry *next_hop = NULL;

	for (int i = 0; i < rtable_len; i++) {
		if ((rtable[i].prefix & rtable[i].mask) == (ip_dest & rtable[i].mask)) {
			if (!next_hop || ntohl(next_hop->mask) < ntohl(rtable[i].mask)) {
				next_hop = &rtable[i];
			}
		}
	}
	return next_hop;
}

struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (ntohl(arp_table[i].ip) == ntohl(given_ip)) {
			return &arp_table[i];
		}
	}
	return NULL;
}
