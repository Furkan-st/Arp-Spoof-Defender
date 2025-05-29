#pragma once  // Bu başlık dosyasının birden fazla kez dahil edilmesini önler (modern yöntem).

#ifndef ACT_UTILS_H  // Eğer ACT_UTILS_H tanımlı değilse,
#define ACT_UTILS_H  // tanımla ve bu bloğun içindeki kodu derlemeye dahil et.

// Sistem ve platforma özel yapılandırmaları içeren başlık dosyası
#include "conf.h"

// ARP tablosunu okuma ve anomali kontrolü için tanımlı yapılar ve fonksiyonlar
#include "arp_parse.h"

// ARP spoofing tespit edildiyse, ilgili IP'leri veya MAC adreslerini sistemden temizlemeye yönelik fonksiyon.
// entries: ARP girdilerini içeren dizi
// count: dizi içindeki kayıt sayısı
void clear_arp_spoofers(const ArpEntry *entries, int count);

// Programın gerekli işlemleri yapabilmesi için yönetici (admin/root) yetkisine sahip olup olmadığını kontrol eden fonksiyon.
// Gerekirse kullanıcıdan yönetici yetkisi talep edebilir.
int ensure_admin_rights(void);

#endif  // ACT_UTILS_H
