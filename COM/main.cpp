#include <iostream>
#include <thread>
#include "ListenTrafik.h"
#include <pcap/pcap.h>
#include <vector>

using namespace std;

void print_menu() {
    Sleep(5000);
    bool flag = TRUE;
    char menu;
    while (flag) {
        std::cout << "мусор: ";
        cin >> menu;
        switch (menu)
        {
            case '1': {
                Lib::printl_SwitchingTable();
                break;
            }
            case '2': {
                flag = FALSE;
                break;
            }
            default:
                break;
        }
    }
}
int main() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_if_t *d_1;
    int inum;
    int inum_1;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    HANDLE hThread_dev1;
    HANDLE hThread_dev2;
    DWORD dIdThread_dev1;
    DWORD dIdThread_dev2;
    setlocale(LC_ALL, "rus");
    /* ��������� ������ ��������� */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface �1 number (1-%d):", i);
    scanf_s("%d", &inum);
    printf("Enter the interface �2 number (1-%d):", i);
    scanf_s("%d", &inum_1);
    std::vector<string> tmp;
    if ((inum < 1 || inum > i) || (inum_1 < 1 || inum_1 > i))
    {
        printf("\nInterface number out of range.\n");
        /* ������������ ������ ��������� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ������� � ���������� �������� */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    for (d_1 = alldevs, i = 0; i < inum_1 - 1; d_1 = d_1->next, i++);

    int ttl;
    std::cout << "����� ����� ������: ";
    std::cin >> ttl;

    Lib::initialize_ttl(ttl);
    Lib::initialize_devices(d, d_1);

    std::thread th(Lib::receiver,(LPVOID*)d);
    std::thread th1(Lib::receiver, (LPVOID*)d_1);
    std::thread th2(Lib::printl_SwitchingTable);
    //std::thread th2(Lib::control_TTL);
    //std::thread menu_print(print_menu);
    //th2.join();
    th.join();
    th1.join();
    th2.join();
    //menu_print.join();


    return 0;
}