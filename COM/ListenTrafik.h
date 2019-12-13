
#include <iostream>
#include <ctime>
#include <WinSock2.h>
#include <Windows.h>
#include <thread>
#include <vector>
#include "SwitchingTable.h"
#include <pcap/pcap.h>
#include <map>
#pragma comment(lib, "wsock32.lib")

pcap_if_t *devices_1;
pcap_if_t *devices_2;
pcap_t *fp1;
pcap_t *fp2;
char errbuf[PCAP_ERRBUF_SIZE];
std::vector<SwitchingTable::SwitchingTable> table;

std::map <std::string, std::pair<pcap_if_t*,time_t> > tqw;

int time_to_live;
namespace Lib {

	typedef struct ethernet_header
	{
		u_char dest[6];
		u_char source[6];
		u_short type;
	}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

	void initialize_ttl(int ttl) {
		time_to_live = ttl;
	}

	void initialize_devices(pcap_if_t *dev1, pcap_if_t *dev2) {
		devices_1 = dev1;
		devices_2 = dev2;
		fp1=pcap_open(devices_1->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
		fp2 = pcap_open(devices_2->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 0, NULL, errbuf);
	}

	void add_record(u_char sourse[6],time_t times, pcap_if_t* devices) {
		if (table.empty()) {
			table.push_back(SwitchingTable::SwitchingTable(sourse, devices, times));
		}
		else {
			bool flag = FALSE;
			for (auto it = table.begin(); it != table.end(); it++) {
				if ((*it).compare_sourse(sourse) == TRUE && (*it).compare_device(devices) == TRUE) {
					flag = TRUE;
					break;
				}
			}
			if(flag == FALSE)
				table.push_back(SwitchingTable::SwitchingTable(sourse, devices, times));
		}
	}

	void control_TTL() {
		while (TRUE) {
			int i = 0;
			for (auto it = table.begin(); it != table.end(); it++) {
				time_t time_now = time(NULL);
				if (abs((double)(time_now) / 3600 - (double)((*it).get_time_t()) / 3600) > time_to_live) {
					table.erase(it);
					break;
				}	
			}
		}
	}

	void printl_SwitchingTable() {
		while (TRUE) {
			system("cls");
			for (auto it = tqw.begin(); it != tqw.end(); it++) {
				std::cout << (*it).first << "/t" << (*it).second.first->name << std::endl;
			}
			Sleep(2200);
		}

	}
	void send_message(pcap_if_t *devices,const u_char *pkt_data, int len) {
		pcap_t *fp;
		if (devices->description == devices_1->description) {
			fp = fp2;
		}
		else {
			fp = fp1;
		}
		if (fp != NULL) {
			if (pcap_sendpacket(fp, pkt_data, len/* size */) != 0)
			{
				fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
			}
		}
	}

	void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
	{
		struct tm ltime;
		char timestr[16];
		time_t local_tv_sec;
		pcap_if_t *devices = (pcap_if_t*)param;
		pcap_t *fp;
		//12.11
		ethernet_header *ether;
		ether = (ethernet_header*)(pkt_data);
		std::string tmp = std::to_string(ether->source[0]) + std::to_string(ether->source[1]) + std::to_string(ether->source[2]) + std::to_string(ether->source[3]) + std::to_string(ether->source[4]) + std::to_string(ether->source[5]);
		if (tqw.count(tmp) > 0 && ((std::string)((*tqw.find(tmp)).second.first->name) != (std::string)(devices->name))) {
			if (devices->name == devices_1->name) {
				if (pcap_sendpacket(fp2, pkt_data, header->len/* size */) != 0)
				{
					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp2));
				}
			}
			else {
				if (pcap_sendpacket(fp1, pkt_data, header->len/* size */) != 0)
				{
					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp1));
				}
			}
			tqw[tmp] = std::make_pair(devices, time(NULL));
		}
		else
		{	
			tqw[tmp] = std::make_pair(devices, time(NULL));
			if (devices->description == devices_1->description) {
				fp = fp2;
			}
			else {
				fp = fp1;
			}
			if (fp != NULL) {
				if (pcap_sendpacket(fp, pkt_data, header->len/* size */) != 0)
				{
					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
				}
			}
		}
	}

	int receiver(LPVOID *devices) {
		pcap_if_t *d = (pcap_if_t*)devices;

		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *adhandle;
		u_int netmask;
		//char packet_filter[] = "ip and udp and icmp and igmp or arp or ip";
		char packet_filter[] = "ip and icmp or arp";
		struct bpf_program fcode;

		if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
		{
			return -1;
		}

		if (pcap_datalink(adhandle) != DLT_EN10MB)
		{
			fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
			return -1;
		}

		if (d->addresses != NULL)
			netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			netmask = 0xffffff;

		//compile the filter
		if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
		{
			fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			return -1;
		}

		//set the filter
		if (pcap_setfilter(adhandle, &fcode) < 0)
		{
			fprintf(stderr, "\nError setting the filter.\n");
			return -1;
		}
		printf("\nlistening on %s...\n", d->description);
		printf("%d/n", 0);
		pcap_loop(adhandle, 0, packet_handler, (u_char *)d);
	}

	typedef struct tcp_header
	{
		unsigned short source_port; // source port
		unsigned short dest_port; // destination port
		unsigned int sequence; // sequence number - 32 bits
		unsigned int acknowledge; // acknowledgement number - 32 bits

		unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
		unsigned char reserved_part1 : 3; //according to rfc
		unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
		This indicates where the data begins.
		The length of the TCP header is always a multiple
		of 32 bits.*/

		unsigned char fin : 1; //Finish Flag
		unsigned char syn : 1; //Synchronise Flag
		unsigned char rst : 1; //Reset Flag
		unsigned char psh : 1; //Push Flag
		unsigned char ack : 1; //Acknowledgement Flag
		unsigned char urg : 1; //Urgent Flag

		unsigned char ecn : 1; //ECN-Echo Flag
		unsigned char cwr : 1; //Congestion Window Reduced Flag

		////////////////////////////////

		unsigned short window; // window
		unsigned short checksum; // checksum
		unsigned short urgent_pointer; // urgent pointer
	} TCP_HDR;

	/* 4 байт IP-адрес */
	typedef struct ip_address {
		u_char byte1;
		u_char byte2;
		u_char byte3;
		u_char byte4;
	}ip_address;


	typedef struct arp_header {
		u_short Ethtype;
		u_short type;
		u_char lentgh_mac;
		u_char lenthg_ip;
		u_short proto;
		u_char destAddr[6];
		u_char  sorceAddr[6];
	}arp_header;
	/* IPv4 header */
	typedef struct ip_header {
		u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
		u_char  tos;            // Type of service 
		u_short tlen;           // Total length 
		u_short identification; // Identification
		u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
		u_char  ttl;            // Time to live
		u_char  proto;          // Protocol
		u_short crc;            // Header checksum
		ip_address  saddr;      // Source address
		ip_address  daddr;      // Destination address
		u_int   op_pad;         // Option + Padding
	}ip_header;

	/* UDP header*/
	typedef struct udp_header {
		u_short sport;          // Source port
		u_short dport;          // Destination port
		u_short len;            // Datagram length
		u_short crc;            // Checksum
	}udp_header;
	/* прототип обработчика пакетов */
	int number = 0;


	/* Callback function invoked by libpcap for every incoming packet */
}

//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
//{
//	struct tm ltime;
//	char timestr[16];
//	time_t local_tv_sec;
//	pcap_if_t *devices = (pcap_if_t*)param;
//	pcap_t *fp;
//	//12.11
//	ethernet_header *ether;
//	ether = (ethernet_header*)(pkt_data);
//
//	//add_record(ether->source, time(NULL), devices);
//	std::string tmp = std::to_string(ether->source[0]) + std::to_string(ether->source[1]) + std::to_string(ether->source[2]) + std::to_string(ether->source[3]) + std::to_string(ether->source[4]) + std::to_string(ether->source[5]);
//	tqw[tmp] = std::make_pair(devices, time(NULL));
//	table.push_back(SwitchingTable::SwitchingTable(ether->source, devices, time(NULL)));
//	if (table.size() == 1) {
//		if (devices->description == devices_1->description) {
//			fp = fp2;
//		}
//		else {
//			fp = fp1;
//		}
//		if (fp != NULL) {
//			if (pcap_sendpacket(fp, pkt_data, header->len/* size */) != 0)
//			{
//				fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
//			}
//		}
//	}
//	else {
//		bool flag = FALSE;
//		SwitchingTable::SwitchingTable *work = NULL;
//		pcap_if_t* host_dev = NULL;
//		for (auto it = table.begin(); it != table.end(); it++) {
//			if ((*it).compare_sourse(ether->dest)) {
//				//work = new SwitchingTable::SwitchingTable(*it);
//				host_dev = (*it).get_pcap_if_devices();
//				break;
//			}
//		}
//		if (host_dev == NULL || host_dev->description != devices->description) {
//			if (devices->description == devices_1->description) {
//				fp = fp2;
//			}
//			else {
//				fp = fp1;
//			}
//			if (fp != NULL) {
//				if (pcap_sendpacket(fp, pkt_data, header->len/* size */) != 0)
//				{
//					fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
//				}
//			}
//		}
//	}
//
//}