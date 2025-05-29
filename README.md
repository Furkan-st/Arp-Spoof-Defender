# Arp-Spoof-Defender
ARP SPOOF Protection service/daemon
Programın amacı Linux/Windows OS kullanan PC'lerde bir daemon/service aracılığı ile arp spoof saldırılarını engellemektir.

Bunu yapma yöntemi kabaca Gateway ip adresini belirleyip, onun mac adresini kullanan diğer ipleri arp tablosundan sürekli olarak silmektir. Bir nevi kaba kuvvet saldırısı olarak sayılabilecek arp spoofa aynı dozda kaba kuvvet ile karşılık verilip arp zehirlenmesini önlemektir programın yöntemi.

Adımlar olarak;

1-Korunacak bilgisayarın aktif wireless ağ arayüzünden loopback olmayan ipv4 ilk ip adresi ki bu kendi ip adresidir, alınır . 

2-Bu ip adresi active_ip.txt isimli dosyaya kaydedilir ve yine kullanım için programda saklanır.

3-Gateway ip'si öğrenilir, bilgisayarımızın arp tablosuna dış komutlar vasıtası ile ulaşılır ve o da arp_tables.txt türevi bir dosyada saklanır.

4-Daha sonrasında bu tablodan yapılan okumalarda mac adresleri aynı olan ipleri farklı olan ve Macleri ff-ff-ff-ff-ff-ff yani broadcast olmayan cihazlar sonraki aşama için mercek altına alınır, eğer ki bu şüpheli cihazlardan ipsi Gateway ile aynı olan varsa derhal arp tablosundan silinir ve bu program linuxta daemon windowsta service yapısında olduğu için sürekli çalışır, 


windowsta servis haline getirmek adına powershellden şu komut tarafımca kullanılmıştır; 


 sc create ArpGuard binPath= "C:\Users\furka\OneDrive\Masaüstü\sketCspace\anti_arp_spoof\arp_protect.exe" start= auto


Tarafımca programın en büyük kusuru Proxy arp enable ağlarda çok fazla false positive vakasının yaşanması ve belki bazı optimizasyon kaynaklı sorunların meydana gelmesi olabilir, ilk problemin çözümlemesini programı geliştirirken yapmayı planlıyorum.


Döküman~Kodu conf.h , arp_parse.h , arp_parse.c , act_utils.h , act_utils.c , ip_util.c , ip_util.h , main.c ve de makefile dosyalarından oluşmaktadır .
