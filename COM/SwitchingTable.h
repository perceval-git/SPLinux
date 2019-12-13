#pragma once
#include <iostream>
#include <Windows.h>
#include <pcap.h>
#include <ctime>
#include <thread>
#include <string>
namespace SwitchingTable {
	class SwitchingTable {
	private:
		
		u_char source[6];
		time_t time_receiot;
		pcap_if_t *d;
		time_t TTL;
	public:
		SwitchingTable() {
		}
		SwitchingTable(u_char *Source, pcap_if_t *devices, time_t ttl) {
			for (int i = 0; i < 6; i++) {
				source[i] = Source[i];
			}
			d = devices;
			this->TTL = ttl;
		}
		~SwitchingTable() {
		}
	public:
		void get_information() {
			printf("%x.%x.%x.%x.%x.%x\t%s\t%d\n", source[0], source[1], source[2], source[3], source[4], source[5],d->description,time_receiot/3600);
		}
		bool compare_sourse(u_char *Sourse) {
			for (int i = 0; i < 6; i++) {
				if (this->source[i] != Sourse[i])
					return FALSE;
			}
			return TRUE;
		}

		pcap_if_t* get_pcap_if_devices() {
			return this->d;
		}

		bool compare_description(pcap_if_t *device) {
			int size = std::strlen(d->description);
			for (int i = 0; i < size; i++) {
				if (d->description[i] != device->description[i])
					return FALSE;
			}
			return TRUE;
		}
		bool compare_device(pcap_if_t *device) {
			if (this->d->description != device->description)
				return FALSE;
			return TRUE;
		}
		
		time_t get_time_t() {
			return this->TTL;
		}
	};
}