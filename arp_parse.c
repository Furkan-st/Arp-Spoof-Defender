#include "arp_parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

// MAC adresinin geçerli olup olmadığını kontrol eder
static bool is_valid_mac(const char *mac){
    int len = strlen(mac);
    if(len != 17) return false; // MAC adresi 17 karakter olmalı (örn: 00:11:22:33:44:55)
    for(int i = 0; i < len; i++){
        if((i+1) % 3 == 0){ // Her 3. karakter ayırıcı olmalı
            if(mac[i] != ':' && mac[i] != '-') return false;
        } else {
            if(!isxdigit(mac[i])) return false; // Ayırıcı olmayanlar hex karakter olmalı
        }
    }
    return true;
}

// IPv4 adresinin geçerli olup olmadığını kontrol eder
static bool is_valid_ip(const char *ip) {
    int nums[4];
    // Adres 4 parçadan oluşmalı, her biri 0-255 aralığında
    if(sscanf(ip, "%d.%d.%d.%d", &nums[0], &nums[1], &nums[2], &nums[3]) != 4)
        return false;
    for(int i = 0; i < 4; i++) {
        if(nums[i] < 0 || nums[i] > 255)
            return false;
    }
    return true;
}

// ARP tablosunu dosyadan okuyarak entries dizisine yazar
int read_arp_table(const char *filename, ArpEntry *entries, int max_size){
    FILE *fp = fopen(filename, "r");
    if(!fp) return -1; // Dosya açılamazsa hata döner
    char line[256];
    int count = 0;

    while(fgets(line, sizeof(line), fp) && count < max_size){
        char ip[40] = {0};
        char mac[20] = {0};

        // Başlık, boşluk ya da arayüz bilgisi satırlarını atla
        if(strncmp(line, "Interface:", 10) == 0) continue;
        if(strstr(line, "Internet Address") != NULL) continue;
        if(line[0] == '\n' || line[0] == '\r') continue;

        // Satırı boşluk, tab, newline'a göre parçala
        char *token = strtok(line, " \t\n");
        if(!token) continue;

        // İlk token IP adresi olmalı, doğruluğunu kontrol et
        if(!is_valid_ip(token)) continue;
        strncpy(ip, token, sizeof(ip)-1);

        // MAC adresini aramak için kalan token'ları tara
        while((token = strtok(NULL, " \t\n"))){
            if(strlen(token) == 17 && is_valid_mac(token)){
                strncpy(mac, token, sizeof(mac)-1);
                break;
            }
        }

        // Geçerli IP ve MAC adresleri varsa diziye ekle
        if(ip[0] != '\0' && mac[0] != '\0'){
            strncpy(entries[count].ip, ip, sizeof(entries[count].ip)-1);
            entries[count].ip[sizeof(entries[count].ip)-1] = '\0';

            strncpy(entries[count].mac, mac, sizeof(entries[count].mac)-1);
            entries[count].mac[sizeof(entries[count].mac)-1] = '\0';

            count++;
        }
    }
    fclose(fp);
    return count; // Toplam okunan kayıt sayısı döner
}

// ARP anomalisini kontrol eder
bool check_arp_anomaly(const ArpEntry *entries, int count){
    const char *broadcast_mac = "ff-ff-ff-ff-ff-ff"; // Yayın adresi

    for(int i = 0; i < count; i++){
        if(strcmp(entries[i].mac, broadcast_mac) == 0) continue; // Broadcast MAC varsa atla

        for(int j = i + 1; j < count; j++){
            // Aynı MAC adresi birden fazla farklı IP'ye atanmışsa, bu anomali sayılır
            if(strcmp(entries[i].mac, entries[j].mac) == 0 && strcmp(entries[i].ip, entries[j].ip) != 0){
                return true; // Anomali tespit edildi
            }
        }
    }
    return false; // Her şey normalse false döner
}
