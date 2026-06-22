#include <string.h>
#include <arpa/inet.h>

#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "trie.h"

struct unsend_packet
{
	char *buf;
	size_t len;
	struct route_table_entry *best;
};

#define MAX_TABLE_ENTRIES 100000
#define IPv4 0x0800
#define ARP 0x0806
#define REQUEST 1
#define REPLY 2

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	int nr_interfaces = argc - 2; // numarul de interfete

	// tabela de rutare
	struct route_table_entry *table_entries = malloc(MAX_TABLE_ENTRIES * sizeof(struct route_table_entry));
	int nr_entries = read_rtable(argv[1], table_entries);

	// adaugarea rutelor in trie
	struct trie *routes = create_trie();
	for (int i = 0; i < nr_entries; i++)
		insert_node(routes, &table_entries[i]);

	// cache ARP
	struct arp_table_entry *arp_entries = malloc(MAX_TABLE_ENTRIES * sizeof(struct arp_table_entry));
	int nr_arp_entries = 0;

	// coada pentru pachete in asteptare
	struct queue *waiting_queue = create_queue();
	int nr_unsend_pkg = 0;

	while (1)
	{
		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("Receive packet from interface %ld\n", interface);

		// extragem Ethernet protocol al pachetului curent
		struct ether_hdr *eth = (struct ether_hdr *)buf;

		// aflam adresa MAC a interfetei
		uint8_t mac_interface[6];
		get_interface_mac(interface, mac_interface);

		// adresa MAC de broadcast
		uint8_t broadcast[6];
		memset(broadcast, 0xFF, 6);

		if (memcmp(eth->ethr_dhost, mac_interface, 6) != 0 && memcmp(eth->ethr_dhost, broadcast, 6) != 0)
			continue; // daca pachetul nu este trimis catre router, il aruncam

		// IP protocol
		if (ntohs(eth->ethr_type) == IPv4)
		{
			printf("Internet protocol\n");

			// IP antet
			struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			// verificare checksum
			uint16_t checksum_recv = ntohs(ip->checksum);
			ip->checksum = 0;

			u_int16_t csum = checksum((uint16_t *)(buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr));

			if (csum != checksum_recv)
			{
				printf("Wrong checksum\n");
				continue; // daca checksum-ul e diferit, aruncam pachetul
			}

			printf("Correct checksum\n");

			// ECHO REQUEST
			int ok_icmp = 0;
			if (ip->proto == 1)
			{
				printf("Echo request\n");

				for (int i = 0; i < nr_interfaces; i++)
				{
					if (ip->dest_addr == inet_addr(get_interface_ip(i)))
					{
						struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
						if (icmp->mtype == 8)
						{
							icmp->mtype = 0;

							// setam adresele IP
							uint32_t aux_ip = ip->source_addr;
							ip->source_addr = ip->dest_addr;
							ip->dest_addr = aux_ip;

							// calculam checksum-ul pentru ICMP si IP
							icmp->check = 0;
							icmp->check = htons(checksum((u_int16_t *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));
							ip->checksum = 0;
							ip->checksum = htons(checksum((u_int16_t *)(buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr)));

							// setam adresele MAC
							uint8_t aux_mac[6];
							memcpy(aux_mac, eth->ethr_dhost, 6);
							memcpy(eth->ethr_dhost, eth->ethr_shost, 6);
							memcpy(eth->ethr_shost, aux_mac, 6);

							// trimitem ECHO REPLY
							send_to_link(len, buf, interface);

							// daca am trimis un ECHO REPLY trecem la urmatorul pachet
							ok_icmp = 1;
							continue;
						}
					}
				}
			}

			if (ok_icmp)
				continue;

			// TIME EXCEEDED
			if (ip->ttl <= 1)
			{
				printf("Time exceeded\n");

				// salvam vechiul protocol IP
				char *old_ip = malloc(MAX_PACKET_LEN);
				memcpy(old_ip, buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr) + 8);

				char *new_buf = malloc(MAX_PACKET_LEN);

				// setam noul Ethernet protocol
				struct ether_hdr *new_eth = (struct ether_hdr *)new_buf;
				new_eth->ethr_type = htons(IPv4);
				memcpy(new_eth->ethr_dhost, eth->ethr_shost, 6);
				memcpy(new_eth->ethr_shost, mac_interface, 6);

				// setam noul Internet protocol
				struct ip_hdr *new_ip = (struct ip_hdr *)(new_buf + sizeof(struct ether_hdr));
				new_ip->ver = 4;
				new_ip->ihl = 5;
				new_ip->tos = 0;
				new_ip->id = 4;
				new_ip->frag = 0;
				new_ip->ttl = 64;
				new_ip->proto = 1; // ICMP
				new_ip->dest_addr = ip->source_addr;
				new_ip->source_addr = inet_addr(get_interface_ip(interface));
				new_ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				new_ip->checksum = 0;

				// setam ICMP protocol
				struct icmp_hdr *new_icmp = (struct icmp_hdr *)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				new_icmp->mtype = 11;
				new_icmp->mcode = 0;
				new_icmp->check = 0;

				// mutam vechiul IP + 8 bytes din payload
				memcpy(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), old_ip, sizeof(struct ip_hdr) + 8);

				// calculam checksum pt ICMP
				uint16_t check_icmp = checksum((uint16_t *)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				new_icmp->check = htons(check_icmp);

				// calculam checksum pt IP
				uint16_t check_ip = checksum((uint16_t *)(new_buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr));
				new_ip->checksum = htons(check_ip);

				// lungimea totala
				size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;

				// trimitem pachetul
				send_to_link(total_len, new_buf, interface);

				// eliberam memoria
				free(old_ip);
				free(new_buf);

				// trecem la urmatorul pachet
				continue;
			}

			// decrementam Time to Live
			ip->ttl--;

			// cautam cea mai buna ruta
			struct route_table_entry *best = search(routes, ip->dest_addr);

			// DESTINATION UNREACHABLE
			if (best == NULL)
			{
				printf("Destination unreachable\n");

				// salvam vechiul protocol IP
				char *old_ip = malloc(MAX_PACKET_LEN);
				memcpy(old_ip, buf + sizeof(struct ether_hdr), sizeof(struct ip_hdr) + 8);

				char *new_buf = malloc(MAX_PACKET_LEN);

				// setam noul Ethernet protocol
				struct ether_hdr *new_eth = (struct ether_hdr *)new_buf;
				new_eth->ethr_type = htons(IPv4);
				memcpy(new_eth->ethr_dhost, eth->ethr_shost, 6);
				memcpy(new_eth->ethr_shost, mac_interface, 6);

				// setam noul Internet protocol
				struct ip_hdr *new_ip = (struct ip_hdr *)(new_buf + sizeof(struct ether_hdr));
				new_ip->ver = 4;
				new_ip->ihl = 5;
				new_ip->tos = 0;
				new_ip->id = 4;
				new_ip->frag = 0;
				new_ip->ttl = 64;
				new_ip->proto = 1; // ICMP
				new_ip->dest_addr = ip->source_addr;
				new_ip->source_addr = inet_addr(get_interface_ip(interface));
				new_ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				new_ip->checksum = 0;

				// setam ICMP protocol
				struct icmp_hdr *new_icmp = (struct icmp_hdr *)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				new_icmp->mtype = 3;
				new_icmp->mcode = 0;
				new_icmp->check = 0;

				// mutam vechiul IP + 8 bytes din payload
				memcpy(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), old_ip, sizeof(struct ip_hdr) + 8);

				// calculam checksum pt ICMP
				uint16_t check_icmp = checksum((uint16_t *)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)), sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				new_icmp->check = htons(check_icmp);

				// calculam checksum pt IP
				uint16_t check_ip = checksum((uint16_t *)(new_buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr));
				new_ip->checksum = htons(check_ip);

				// lungimea totala
				size_t total_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;

				// trimitem pachetul
				send_to_link(total_len, new_buf, interface);

				// eliberam memoria
				free(old_ip);
				free(new_buf);

				// trecem la urmatorul pachet
				continue;
			}

			// recalculam checksum dupa decrementarea ttl
			ip->checksum = 0;
			uint16_t new_csum = checksum((uint16_t *)(buf + sizeof(struct ether_hdr)), sizeof(struct ip_hdr));
			ip->checksum = htons(new_csum);

			uint8_t mac_d[6], mac_s[6];

			// cautam adresa MAC destinatie
			int ok = 0;
			for (int i = 0; i < nr_arp_entries; i++)
				if (arp_entries[i].ip == best->next_hop)
				{
					memcpy(mac_d, arp_entries[i].mac, 6);
					ok = 1;
				}

			// daca nu o gasim, adaugam pachetul intr-o coada
			// ARP REQUEST
			if (ok == 0)
			{
				printf("Arp request\n");

				// stocam pachetul impreuna cu lungimea si interfata unde trebuie trimis
				struct unsend_packet *unsend = malloc(sizeof(struct unsend_packet));
				unsend->buf = malloc(len);
				memcpy(unsend->buf, buf, len);

				unsend->len = len;
				unsend->best = best;

				// adaugam pachetul in coada
				queue_enq(waiting_queue, unsend);
				nr_unsend_pkg++;

				char *arp_request = malloc(MAX_PACKET_LEN);

				// setam Ethernet protocol pentru ARP request
				struct ether_hdr *eth_arp = (struct ether_hdr *)arp_request;
				// tipul protocolului
				eth_arp->ethr_type = htons(ARP);

				// adresa MAC sursa
				uint8_t mac_arp[6];
				get_interface_mac(best->interface, mac_arp);
				memcpy(eth_arp->ethr_shost, mac_arp, 6);

				// adresa MAC destinatie
				memcpy(eth_arp->ethr_dhost, broadcast, 6);

				// setam ARP protocol
				struct arp_hdr *arp = (struct arp_hdr *)(arp_request + sizeof(struct ether_hdr));
				arp->hw_type = htons(1); // Ethernet
				arp->proto_type = htons(IPv4);
				arp->hw_len = 6;
				arp->proto_len = 4;
				arp->opcode = htons(REQUEST);
				memcpy(arp->shwa, mac_arp, 6);
				arp->sprotoa = inet_addr(get_interface_ip(best->interface));
				memset(arp->thwa, 0, 6);
				arp->tprotoa = best->next_hop;

				// trimitem pachetul si trecem la urmatorul
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_request, best->interface);
				free(arp_request);
				continue;
			}

			// setam adresele MAC si trimitem pachetul mai departe
			memcpy(eth->ethr_dhost, mac_d, 6);

			get_interface_mac(best->interface, mac_s);

			memcpy(eth->ethr_shost, mac_s, 6);

			send_to_link(len, buf, best->interface);

			printf("Sent successfully\n");
		}
		// ARP protocol
		else if (ntohs(eth->ethr_type) == ARP)
		{
			printf("ARP protocol\n");

			// extragem protocolul ARP
			struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			// ARP REQUEST
			if (ntohs(arp->opcode) == REQUEST)
			{
				printf("ARP request\n");

				for (int i = 0; i < nr_interfaces; i++)
				{
					// cautam interfata target
					if (arp->tprotoa == inet_addr(get_interface_ip(i)))
					{
						// setam adresele IP si MAC
						memcpy(arp->thwa, arp->shwa, 6);
						arp->tprotoa = arp->sprotoa;
						memcpy(arp->shwa, mac_interface, 6);
						arp->sprotoa = inet_addr(get_interface_ip(interface));

						arp->opcode = htons(REPLY); // pachetul este ARP REPLY

						// setam adresele MAC pentru antetul Ethernet
						memcpy(eth->ethr_dhost, eth->ethr_shost, 6);
						memcpy(eth->ethr_shost, mac_interface, 6);

						// trimitem pachetul ARP REPLY
						send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);
					}
				}
			}
			// ARP REPLY
			else if (ntohs(arp->opcode) == REPLY)
			{
				printf("ARP reply\n");

				// adaugam adresele in tabela ARP
				arp_entries[nr_arp_entries].ip = arp->sprotoa;
				memcpy(arp_entries[nr_arp_entries].mac, arp->shwa, 6);
				nr_arp_entries++;

				int total = nr_unsend_pkg;
				int i = 0;

				// cautam pachetele care au umatorul hop sursa pachetului si le trimitem
				while (i < total)
				{
					struct unsend_packet *packet = queue_deq(waiting_queue);
					struct ether_hdr *eth = (struct ether_hdr *)(packet->buf);

					if (packet->best->next_hop == arp->sprotoa)
					{
						memcpy(eth->ethr_dhost, arp->shwa, 6);

						uint8_t mac_src[6];
						get_interface_mac(packet->best->interface, mac_src);
						memcpy(eth->ethr_shost, mac_src, 6);

						send_to_link(packet->len, packet->buf, packet->best->interface);

						nr_unsend_pkg--;
					}
					else
					{
						queue_enq(waiting_queue, packet);
					}

					i++;
				}
			}
		}
	}
}
