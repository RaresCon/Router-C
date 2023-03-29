#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define ARP_TABLE "arp_table.txt"
#define ARP_REQUEST 1
#define ARP_REPLY 2

#define IPv4 0x0800
#define ARP 0x0806

void init_router(int argc, char **argv);
void handle_ip_packet(char packet[], size_t len, int interface);
void handle_arp_packet(char packet[], size_t len, int interface);
void update_ttl(char packet[]);
struct route_table_entry *get_next_hop(uint32_t ip_dest);
struct arp_entry *get_arp_entry(uint32_t given_ip);
void add_arp_entry(uint32_t ip, uint8_t mac[]);
int check_arp_entry(uint32_t ip);
void check_resend_queue();
void send_brd_arp_request(uint32_t req_ip, int interface);

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;

queue resend_queue;

int main(int argc, char *argv[])
{
	init_router(argc, argv);

	while (1) {
		char *buf = malloc(MAX_PACKET_LEN);	
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
			handle_arp_packet(buf, len, interface);
			break;
		default:
			fprintf(stderr, "- Unknown EthernetType -\nSkipping...\n");
			break;
		}
	}

	return 1;
}

void init_router(int argc, char **argv) {
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	arp_table = malloc(1);

	rtable_len = read_rtable(argv[1], rtable);

	// Do not modify this line
	init(argc - 2, argv + 2);
	resend_queue = queue_create();
}

void handle_ip_packet(char *packet, size_t len, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	printf("Source: %d | Destination: %d\n", ntohl(ip_hdr->saddr), ntohl(ip_hdr->daddr));

	if (strcmp((char *) &ip_hdr->daddr, get_interface_ip(interface))) {
		
	}

	if (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr))) {
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

	if (!check_arp_entry(next_rtable_entry->next_hop)) {
		queue_enq(resend_queue, packet);
		send_brd_arp_request(next_rtable_entry->next_hop, next_rtable_entry->interface);

		printf("Packet waiting for ARP\n");
		return;
	}

	memcpy(eth_hdr->ether_dhost, get_arp_entry(next_rtable_entry->next_hop)->mac, 6);
	send_to_link(next_rtable_entry->interface, packet, len);
}

void handle_arp_packet(char *packet, size_t len, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));

	printf("Type %d\n", ntohs(arp_hdr->op));

	switch (ntohs(arp_hdr->op)) {
	case ARP_REQUEST:
		add_arp_entry(arp_hdr->spa, arp_hdr->sha);
		memcpy(arp_hdr->tha, arp_hdr->sha, 6);
		uint32_t tpa_copy = arp_hdr->tpa;
		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = tpa_copy;
		get_interface_mac(interface, arp_hdr->sha);
		printf("%s\n", get_interface_ip(interface));
		arp_hdr->op = htons(2);

		get_interface_mac(interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, arp_hdr->tha, 6);

		send_to_link(interface, packet, len);
	break;
	case ARP_REPLY:
		add_arp_entry(arp_hdr->spa, arp_hdr->sha);
		check_resend_queue();
	break;
	} 
}

void update_ttl(char *packet) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	ip_hdr->ttl--;

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));
}

void check_resend_queue() {
	int queue_len = queue_length(resend_queue);

	printf("queue len: %d\n", queue_len);
	for (int i = 0; i < queue_len; i++) {
		void *deq_packet = queue_deq(resend_queue);
		struct ether_header *deq_eth_hdr = (struct ether_header *) deq_packet;
		struct iphdr *deq_ip_hdr = (struct iphdr *)(deq_packet + sizeof(struct ether_header));

		printf("Source: %d | Destination: %d\n", deq_ip_hdr->saddr, deq_ip_hdr->daddr);

		struct arp_entry *check_arp = get_arp_entry(deq_ip_hdr->daddr);

		if (check_arp) {
			printf("ACUM GASESC, TRIMIT!\n");
			struct route_table_entry *next_rtable_entry = get_next_hop(deq_ip_hdr->daddr);

			memcpy(deq_eth_hdr->ether_dhost, get_arp_entry(next_rtable_entry->next_hop)->mac, 6);
			send_to_link(next_rtable_entry->interface, deq_packet, ntohs(deq_ip_hdr->tot_len) + sizeof(struct ether_header));
		} else {
			queue_enq(resend_queue, deq_packet);
		}
	}
}

void send_brd_arp_request(uint32_t req_ip, int interface) {
	char packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
	struct ether_header *eth_hdr = (struct ether_header*) malloc(sizeof(struct ether_header));

	get_interface_mac(interface, eth_hdr->ether_shost);
	hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);
	eth_hdr->ether_type = htons(ARP);

	struct arp_header *arp_hdr = (struct arp_header*) malloc(sizeof(struct arp_header));
	uint16_t htype = 1;
	arp_hdr->htype = htons(htype);
	arp_hdr->ptype = htons(IPv4);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	hwaddr_aton("00:00:00:00:00:00", arp_hdr->tha);
	// poate trebuie htonl !!
	arp_hdr->tpa = req_ip;

	memcpy(packet, eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	free(eth_hdr);
	free(arp_hdr);

	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct arp_header));
}

void add_arp_entry(uint32_t ip, uint8_t mac[]) {
	if (check_arp_entry(ip)) {
		printf("ARP entry already exists\n");
		return;
	}

	arp_table_len++;
	arp_table = realloc(arp_table, arp_table_len * sizeof(struct arp_entry));

	arp_table[arp_table_len - 1].ip = ip;
	memcpy(&arp_table[arp_table_len - 1].mac, mac, 6);

	printf("New ARP entry registered.\n");
}

int check_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (ntohl(arp_table[i].ip) == ntohl(ip)) {
			return 1;
		}
	}
	return 0;
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
