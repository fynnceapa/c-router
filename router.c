#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Address resolution protocol */
#define BROADCAST_MAC		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define ICMP_SIZE sizeof(struct icmphdr)
#define IP_SIZE sizeof(struct iphdr)
#define ETHER_SIZE sizeof(struct ether_header)
#define ARP_SIZE sizeof(struct arp_header)

struct route_table_entry *rtable;
int rtable_size;

struct arp_table_entry *arp_table;
int arp_table_size;

queue q;

int compare(const void *a, const void *b) {
	struct route_table_entry *a1 = (struct route_table_entry *)a;
	struct route_table_entry *b1 = (struct route_table_entry *)b;
	uint32_t a_masked = a1->prefix & a1->mask;
	uint32_t b_masked = b1->prefix & b1->mask;
	return (a_masked == b_masked) ? (ntohl(a1->mask) > ntohl(b1->mask)) : (ntohl(a_masked) > ntohl(b_masked));
}

int binary_search(uint32_t dest_ip) {
	//cautarea se face in 
	int left = 0;
	int right = rtable_size - 1;
	int middle;
	int index = -1;

	while (left <= right) {
		middle = (left + right) / 2;
		uint32_t dest_mask = dest_ip & ntohl(rtable[middle].mask);
		uint32_t prefix = ntohl(rtable[middle].prefix);

		if (dest_mask == prefix) {
			index = middle;

			//continui cautarea pentru a gasi cea mai specifica ruta
			left = middle + 1;
		} else if (dest_mask < prefix) {
			right = middle - 1;
		} else {
			left = middle + 1;
		}
	}

	return index;
}

struct route_table_entry *get_best_route(uint32_t dest_ip) {
	dest_ip = ntohl(dest_ip);
	int index = binary_search(dest_ip);

	if (index == -1) {
		return NULL;
	}

	return &rtable[index];
}

int binary_search_arp(uint32_t ip) {
	int left = 0;
	int right = arp_table_size - 1;
	int middle;
	int index = -1;

	while (left <= right) {
		middle = (left + right) / 2;
		if (arp_table[middle].ip == ip) {
			index = middle;
			break;
		} else if (arp_table[middle].ip < ip) {
			left = middle + 1;
		} else {
			right = middle - 1;
		}
		
	}
	return index;
}

struct arp_table_entry *check_arp_table(uint32_t ip) {
	int index = binary_search_arp(ip);
	if (index == -1) {
		return NULL;
	}
	return &arp_table[index];
}

void send_arp_request(char *buf, int interface, size_t len) {
	char *packet = malloc(len);
	memcpy(packet, buf, len);
	struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_SIZE);
	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
	queue_enq(q, packet);
	len = ETHER_SIZE + ARP_SIZE;
	if (check_arp_table(best_route->next_hop) != NULL) {
		return;
	}
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ETHER_SIZE);
	uint8_t broadcast[6] = BROADCAST_MAC;
	memcpy(eth_hdr->ether_dhost, broadcast, 6);
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	get_interface_mac(best_route->interface, arp_hdr->sha);
	arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
	arp_hdr->tpa = best_route->next_hop;
	
	send_to_link(best_route->interface, buf, len);
}

void arp_request(char *buf, int interface, size_t len) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ETHER_SIZE);
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
		get_interface_mac(interface, eth_hdr->ether_shost);
		arp_hdr->op = htons(2);
		arp_hdr->htype = htons(1);
		arp_hdr->ptype = htons(ETHERTYPE_IP);
		arp_hdr->hlen = 6;
		arp_hdr->plen = 4;
		memcpy(arp_hdr->tha, arp_hdr->sha, 6);
		memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = inet_addr(get_interface_ip(interface));
		send_to_link(interface, buf, len);
}

void add_arp_entry(uint32_t ip, uint8_t *mac) {
	if (arp_table_size == 0) {
		arp_table[0].ip = ip;
		memcpy(arp_table[0].mac, mac, 6);
		arp_table_size++;
		return;
	}
	//caut pozitia unde trebuie inserat elementul
	//sortez tabela arp in ordine crescatoare dupa ip
	int i = 0;
	while (i < arp_table_size && arp_table[i].ip < ip) {
		i++;
	}
	for (int j = arp_table_size; j > i; j--) {
		arp_table[j].ip = arp_table[j - 1].ip;
		memcpy(arp_table[j].mac, arp_table[j - 1].mac, 6);
	}
	arp_table[i].ip = ip;
	memcpy(arp_table[i].mac, mac, 6);
	arp_table_size++;
}

void arp_reply(char *buf, int interface, size_t len) {
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ETHER_SIZE);

	add_arp_entry(arp_hdr->spa, arp_hdr->sha);

	while (!queue_empty(q)) {
		char *packet = queue_deq(q);
		struct ether_header *eth_hdr = (struct ether_header *) packet;
		struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_SIZE);
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		//daca nu am gasit o ruta inseamna ca nu am cum sa trimit pachetul
		//pun pachetul inapoi in coada si ma opresc
		if (check_arp_table(best_route->next_hop) == NULL) {
			queue_enq(q, packet);
			break;
		}

		memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
		get_interface_mac(interface, eth_hdr->ether_shost);

		send_to_link(interface, packet, len);
	}
}

void send_icmp(char *buf, int interface, size_t *len, uint8_t type) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + ETHER_SIZE);
	struct icmphdr *icmp = (struct icmphdr *)(buf + ETHER_SIZE + IP_SIZE);

	memcpy((uint8_t *)icmp + ICMP_SIZE, (uint8_t *)ip_hdr + IP_SIZE, 64);
	
	ip_hdr->protocol = IPPROTO_ICMP;
	*len += ICMP_SIZE;
	ip_hdr->tot_len = htons((*len) - ETHER_SIZE);

	icmp->type = type;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->checksum = htons(checksum(((uint16_t *)icmp), *len - ETHER_SIZE - IP_SIZE));

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	eth_hdr->ether_type = htons(ETHERTYPE_IP);
	send_to_link(interface, buf, *len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	printf("Router started\n");

	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "malloc");
	arp_table = malloc(sizeof(struct arp_table_entry) * 80000);
	DIE(arp_table == NULL, "malloc");

	arp_table_size = 0;

	rtable_size = read_rtable(argv[1], rtable);
	DIE(rtable_size < 0, "read_rtable");

	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare);

	q = queue_create();
	DIE(q == NULL, "queue_create");

	for(;;) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		printf("Received packet from interface %d\n", interface);
		uint8_t mac[6];
		get_interface_mac(interface, mac);
		uint8_t broadcast[6] = BROADCAST_MAC;
		if ((memcmp(eth_hdr->ether_dhost, mac, 6) != 0) && (memcmp(eth_hdr->ether_dhost, broadcast, 6) != 0)) {
			continue;
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			printf("Received IP packet\n");
			struct iphdr *ip_hdr = (struct iphdr *)(buf + ETHER_SIZE);
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				if (ip_hdr->protocol == IPPROTO_ICMP) {
					struct icmphdr *icmp = (struct icmphdr *)(buf + ETHER_SIZE + IP_SIZE);
					if (icmp->type == 8) {
						printf("Received ICMP echo request\n");
						send_icmp(buf, interface, &len, 0);
					}
				}
				continue;
			}

			uint16_t sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			if (checksum(((uint16_t *)ip_hdr), IP_SIZE) != sum) {
				printf("Checksum error\n");
				continue;
			}

			if (ip_hdr->ttl <= 1) {
    			printf("TTL expired\n");
				send_icmp(buf, interface, &len, 11);
				continue;
			}

			ip_hdr->ttl--;

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL) {
				printf("Destination unreachable\n");
				send_icmp(buf, interface, &len, 3);
				continue;
			}
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum(((uint16_t *)ip_hdr), IP_SIZE));
			struct arp_table_entry *arpentry = check_arp_table(best_route->next_hop);
			if (arpentry == NULL) {
				printf("Sending ARP request\n");
				send_arp_request(buf, interface, len);
				continue;
			}
			memcpy(eth_hdr->ether_shost, mac, 6);
			memcpy(eth_hdr->ether_dhost, arpentry->mac, 6);

			interface = best_route->interface;
			send_to_link(interface, buf, len);

		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			printf("Received ARP packet\n");
			struct arp_header *arp_hdr = (struct arp_header *)(buf + ETHER_SIZE);

			if (ntohs(arp_hdr->op) == 1) {
				printf("Received ARP request\n");
				arp_request(buf, interface, len);

			} else if (ntohs(arp_hdr->op) == 2) {
				printf("Received ARP reply\n");
				arp_reply(buf, interface, len);
			}
		}
	}
	free(rtable);
	free(arp_table);
	return 0;
}

