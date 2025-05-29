#pragma once  //tanımlamaların birer kez yapıldığından emin olmak için
#ifndef CONF_H
#define CONF_H

#if defined(_WIN32) || defined(_WIN64)//işletim sistemi windows ise ilgili arp komut preseti kullanılır
    #ifndef OS_WINDOWS
    #define OS_WINDOWS
    #endif
    #define TABLE_COMMAND "arp -a -N"
#elif defined(__linux__)//işletim sistemi linux ise ilgli arp komut preseti kullanılır
    #ifndef OS_LINUX
    #define OS_LINUX
    #endif
    #define TABLE_COMMAND "arp -a"
#else
    #error "Unsupported platform"//desteklenmeyen os
#endif

#define ARP_TABLE_FILE "arp_table.txt"//arp tablosu tanımı
#define ACTIVE_IP_FILE "active_ip.txt"//aktif interface ipsi tanımı

#endif // CONF_H
