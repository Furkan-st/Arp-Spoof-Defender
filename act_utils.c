#include "conf.h"          // Platforma özel tanımlar (örneğin OS_WINDOWS)
#include "act_utils.h"     // Bu dosyadaki fonksiyonlar: ensure_admin_rights, clear_arp_spoofers
#include "ip_util.h"       // Gateway IP almak için kullanılan get_default_gateway_ip fonksiyonu
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_WINDOWS
#include <windows.h>       // Windows API için gerekli başlık
#endif

#include <stdio.h>
#include <stdlib.h>        // system(), exit() gibi fonksiyonlar için

#ifdef OS_WINDOWS
#include <shellapi.h>      // ShellExecuteA fonksiyonu için gerekli

// Windows için admin kontrol fonksiyonu
int ensure_admin_rights(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    // Admin grubunun SID’sini al
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {

        // Kullanıcının admin olup olmadığını kontrol et
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }

    // Eğer admin değilse kendini tekrar admin olarak çalıştır
    if (!isAdmin) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH); // Çalışan .exe dosyasının yolu
        ShellExecuteA(NULL, "runas", exePath, NULL, NULL, SW_SHOWNORMAL); // Yönetici olarak çalıştır
        exit(0); // Eski (admin olmayan) işlem sonlandırılır
    }

    return 1;
}
#else
#include <unistd.h>

// Linux için admin kontrol fonksiyonu
int ensure_admin_rights(int argc, char *argv[]) {
    // root değilse (UID != 0), sudo ile yeniden başlat
    if (geteuid() != 0) {
        printf("Yönetici olarak çalıştırılmadı. Tekrar root olarak başlatılıyor...\n");

        char command[1024] = "sudo ";
        for (int i = 0; i < argc; i++) {
            strcat(command, argv[i]);
            strcat(command, " ");
        }

        system(command); // sudo ile tekrar çalıştır
        exit(0); // Eski işlem sonlandırılır
    }

    return 1;
}
#endif

// Tespit edilen ARP saldırganlarını temizler
void clear_arp_spoofers(const ArpEntry *entries, int count) {
    char *gateway_ip = get_default_gateway_ip(); // Varsayılan ağ geçidi IP’si alınır
    if (!gateway_ip) {
        fprintf(stderr, "Gateway IP alınamadı.\n");
        return;
    }

    const char *broadcast_mac = "ff-ff-ff-ff-ff-ff"; // Broadcast adresi kontrol için

    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].mac, broadcast_mac) == 0) continue; // Broadcast MAC atlanır

        int is_spoof = 0;

        // MAC adresi başka bir IP ile eşleşiyorsa spoof olabilir
        for (int j = 0; j < count; j++) {
            if (j == i) continue;
            if (strcmp(entries[i].mac, entries[j].mac) == 0 &&
                strcmp(entries[i].ip, entries[j].ip) != 0) {
                is_spoof = 1;
                break;
            }
        }

        // Eğer spoof ve gateway IP değilse sistemden silinir
        if (is_spoof && strcmp(entries[i].ip, gateway_ip) != 0) {
            char cmd[128];

#ifdef OS_WINDOWS
            // Windows: ARP girdisini sil
            snprintf(cmd, sizeof(cmd), "arp -d %s", entries[i].ip);
            FILE *arp_proc = _popen(cmd, "r");
            if (arp_proc) _pclose(arp_proc);
#else
            // Linux: ARP girdisini sil
            snprintf(cmd, sizeof(cmd), "arp -d %s", entries[i].ip);
            FILE *arp_proc = popen(cmd, "r");
            if (arp_proc) pclose(arp_proc);
#endif

            // Kullanıcıya bilgi ver
            printf("[!] ARP Spoofer IP silindi: %s\n", entries[i].ip);
        }
    }

    free(gateway_ip); // Bellek temizliği
}


