#pragma once // Bu dosyanın birden fazla kez dahil edilmesini önler

#ifndef ARP_PARSE_H // Eğer ARP_PARSE_H tanımlı değilse başlat
#define ARP_PARSE_H

#include <stdbool.h> // bool türü ve true/false sabitleri için
#include "conf.h" // Platforma özel tanımların bulunduğu konfigürasyon dosyası

// ARP tablosundaki bir girdiyi temsil eden yapı
typedef struct {
    char ip[40];   // IP adresi (IPv4 için yeterli, IPv6 için genişletilmiş)
    char mac[20];  // MAC adresi (örnek: "00:11:22:33:44:55")
    char type[16]; // Girdi türü (statik, dinamik vs. gibi bilgiler için)
} ArpEntry;

// Belirtilen dosyadan ARP tablosunu okur ve entries dizisine yazar
// max_size ile kaç girdi alınabileceği belirlenir
int read_arp_table(const char *filename, ArpEntry *entries, int max_size);

// ARP girdilerinde anomali olup olmadığını kontrol eder
// MAC-IP eşleşmelerindeki tutarsızlıkları tespit etmek için kullanılır
bool check_arp_anomaly(const ArpEntry *entries, int count);

#endif // ARP_PARSE_H sonu
