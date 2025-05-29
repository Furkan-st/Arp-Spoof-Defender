#pragma once//tanımlamalar birer kez yapılsın diye
#include "conf.h"//conf.h tanımı
#include "arp_parse.h"//arp_parse.h tanımı

#ifndef IP_UTIL_H
#define IP_UTIL_H

char* get_default_gateway_ip(void);//korunan bilgisayarın bağlı olduğu ağın gateway ipsini bulan fonksiyonun beyanı
#ifdef OS_LINUX//os linux ise ilgili kütüphaneleri dahil et
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

void get_active_ip(char *buffer, size_t size);//sonrasında linux için olan aktif interface ip bulma kodu şematiği beyan edilir
#elif defined(OS_WINDOWS)//os windows ise ilgili kütüphaneleri dahil et ve aktif interface ip bulma kodunun windows halini beyan et
#include <winsock2.h>
#include <iphlpapi.h>
int get_active_ip(char *buffer, size_t size);

#endif

#endif //dosya sonu
