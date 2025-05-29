#include "ip_util.h" // gateway IP ve aktif arayüz IP’sini bulan fonksiyonların prototiplerini içerir
#include "arp_parse.h" // ARP tablosunu çözümleyen fonksiyonların prototiplerini içerir
#define MAX_ARP_ENTRIES 256 // ARP tablosunda maksimum girdi sayısı sabiti

#ifdef OS_LINUX // Eğer sistem Linux ise aşağıdaki kütüphaneler ve fonksiyonlar dahil edilir
#include <ifaddrs.h> // Ağ arayüz bilgilerini almak için
#include <netinet/in.h> // sockaddr_in yapısını tanımlar
#include <arpa/inet.h> // inet_ntop gibi IP dönüşüm fonksiyonları için
#include <string.h> // strcmp, strncpy vb. için
#include <stdio.h> // printf, FILE vb. için
#include <net/if.h> // Arayüz türleri ve bayraklar için

int get_active_ip(char *buffer, size_t size) { // Aktif wireless IP adresini döner
    struct ifaddrs *ifaddr, *ifa; // Tüm arayüzleri tutan liste ve geçici işaretçi
    buffer[0] = '\0'; // buffer'ı boşalt

    if (getifaddrs(&ifaddr) == -1) { // Arayüz listesini alamazsa
        return 0; // başarısız
    }

    int success = 0; // başarı bayrağı
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) { // tüm arayüzleri döner
        if (!ifa->ifa_addr) continue; // adresi olmayanları atla

        if (ifa->ifa_addr->sa_family == AF_INET // IPv4 ise
            && !(ifa->ifa_flags & IFF_LOOPBACK) // loopback değilse
            && strncmp(ifa->ifa_name, "wl", 2) == 0) { // ismi "wl" (wireless) ile başlıyorsa

            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr; // IPv4 adresi al
            inet_ntop(AF_INET, &(sa->sin_addr), buffer, size); // string IP adresine çevir
            success = 1; // başarılı
            break;
        }
    }

    freeifaddrs(ifaddr); // belleği temizle
    return success; // 1 ise bulundu, 0 ise bulunamadı
}
#endif

#ifdef OS_WINDOWS // Windows ortamı için:
#include <winsock2.h> // temel soket tanımları
#include <ws2tcpip.h> // inet_ntop gibi modern IP yardımcıları
#include <iphlpapi.h> // GetAdaptersAddresses için
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib") // Otomatik kütüphane bağlama
#pragma comment(lib, "ws2_32.lib")
#endif

int get_active_ip(char *buffer, size_t size) { // Windows'ta aktif wireless IP'yi bul
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX; // adres ön eklerini dahil et
    ULONG family = AF_INET; // IPv4 ailesi
    PIP_ADAPTER_ADDRESSES adapters = NULL; // adaptör listesi
    ULONG outBufLen = 15000; // buffer uzunluğu
    DWORD dwRetVal = 0; // sonuç kodu

    buffer[0] = '\0'; // buffer’ı temizle

    adapters = (IP_ADAPTER_ADDRESSES *) malloc(outBufLen); // ilk tahmini belleği ayır
    if (adapters == NULL) return 0;

    dwRetVal = GetAdaptersAddresses(family, flags, NULL, adapters, &outBufLen); // adaptörleri al
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) { // eğer buffer küçükse yeniden ayır
        free(adapters);
        adapters = (IP_ADAPTER_ADDRESSES *) malloc(outBufLen);
        if (adapters == NULL) return 0;
        dwRetVal = GetAdaptersAddresses(family, flags, NULL, adapters, &outBufLen);
    }
    if (dwRetVal != NO_ERROR) { // hâlâ başarısızsa
        free(adapters);
        return 0;
    }

    PIP_ADAPTER_ADDRESSES adapter = adapters; // ilk adaptörü al
    while (adapter) {
        if (adapter->OperStatus == IfOperStatusUp // çalışır durumda mı
            && adapter->IfType == IF_TYPE_IEEE80211) { // wireless mı

            PIP_ADAPTER_UNICAST_ADDRESS ua = adapter->FirstUnicastAddress; // ilk IP adresi
            while (ua) {
                SOCKADDR_IN *sa_in = (SOCKADDR_IN *)ua->Address.lpSockaddr;

                if (sa_in->sin_addr.S_un.S_addr == htonl(INADDR_LOOPBACK)) { // loopback’i atla
                    ua = ua->Next;
                    continue;
                }

                char ip_str[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &(sa_in->sin_addr), ip_str, sizeof(ip_str)); // IP’yi string’e çevir

                strncpy(buffer, ip_str, size - 1); // buffer’a kopyala
                buffer[size - 1] = '\0'; // null-terminator

                free(adapters); // bellek temizle
                return 1; // başarı
            }
        }
        adapter = adapter->Next; // sonraki adaptöre geç
    }

    free(adapters); // bellek temizle
    return 0; // başarısız
}
#endif

char* get_default_gateway_ip() { // Varsayılan gateway IP’sini döner
    FILE *fp;
    char buffer[256];
    char *gateway_ip = NULL;
    int found_ipx = 0;

#ifdef OS_WINDOWS
    fp = _popen("ipconfig", "r"); // Windows komutu
#else
    fp = popen("ip route", "r"); // Linux komutu
#endif

    if (fp == NULL) {
        return NULL; // komut çalışmazsa
    }

#ifdef OS_WINDOWS
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, "ipx") != NULL) { // ipx satırından sonrası ilgisiz
            found_ipx = 1;
            break;
        }

        if (strstr(buffer, "Default Gateway") != NULL) { // ilgili satır
            char *token = strrchr(buffer, ':'); // son iki nokta
            if (token != NULL) {
                token++;
                while (*token == ' ') token++; // boşlukları geç
                if (*token != '\0' && *token != '\n') {
                    gateway_ip = malloc(strlen(token) + 1);
                    if (gateway_ip) {
                        strcpy(gateway_ip, token); // IP’yi al
                        gateway_ip[strcspn(gateway_ip, "\r\n")] = '\0'; // newline temizle
                    }
                }
            }
        }
    }

    _pclose(fp); // Windows’ta kapatma

#else
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strncmp(buffer, "default", 7) == 0) { // default route satırı
            char *via = strstr(buffer, "via ");
            if (via) {
                via += 4;
                char *end = strchr(via, ' ');
                if (end) *end = '\0';
                gateway_ip = malloc(strlen(via) + 1);
                if (gateway_ip) strcpy(gateway_ip, via); // gateway IP’yi al
            }
            break;
        }
    }

    pclose(fp); // Linux’ta kapatma
#endif

    return gateway_ip; // sonucu döndür
}
