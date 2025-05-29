#include "ip_util.h"
#include "arp_parse.h"
#include "act_utils.h"
#include "conf.h"

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#if defined(OS_WINDOWS)
    #include <windows.h>
    #include <process.h>
    #define THREAD_RETURN unsigned __stdcall
    #define THREAD_HANDLE HANDLE

    SERVICE_STATUS g_ServiceStatus = {0};
    SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
    HANDLE g_ServiceStopEvent = NULL;

#else
    #include <pthread.h>
    #include <unistd.h>
    #define THREAD_RETURN void*
    #define THREAD_HANDLE pthread_t
#endif

#define MAX_ARP_ENTRIES 256
#define SLEEP_SECONDS 10  // Log yavaşlatıldı

static volatile bool running = true;

#if defined(OS_WINDOWS)
// Windows servis prototipleri
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD ctrlCode);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

SERVICE_TABLE_ENTRY ServiceTable[] = {
    { (LPSTR)"ArpSecureService", (LPSERVICE_MAIN_FUNCTION)ServiceMain },
    { NULL, NULL }
};
#endif

// Sinyal yakalayıcı (Linux için)
void handle_signal(int sig) {
    (void)sig;
    running = false;
#if defined(OS_WINDOWS)
    if (g_ServiceStopEvent)
        SetEvent(g_ServiceStopEvent);
#endif
}

// Thread fonksiyonu (ortak)
THREAD_RETURN thread_func(void* arg) {
    (void)arg;

    while (running) {
        char active_ip[100];
        if (!get_active_ip(active_ip, sizeof(active_ip))) {
            // Log hatası dosyaya yazılacak
            FILE *log_fp = fopen("log.txt", "a");
            if (log_fp) {
                time_t now = time(NULL);
                char *timestamp = ctime(&now);
                if (timestamp) timestamp[strcspn(timestamp, "\n")] = '\0';
                fprintf(log_fp, "[%s] Aktif IP alınamadı.\n", timestamp);
                fclose(log_fp);
            }
            goto sleep_and_continue;
        }

        if (strncmp(active_ip, "127.", 4) == 0) {
            FILE *log_fp = fopen("log.txt", "a");
            if (log_fp) {
                time_t now = time(NULL);
                char *timestamp = ctime(&now);
                if (timestamp) timestamp[strcspn(timestamp, "\n")] = '\0';
                fprintf(log_fp, "[%s] Loopback IP atlandı: %s\n", timestamp, active_ip);
                fclose(log_fp);
            }
            goto sleep_and_continue;
        }

        FILE* ip_fp = fopen(ACTIVE_IP_FILE, "w");
        if (ip_fp) {
            fprintf(ip_fp, "%s\n", active_ip);
            fclose(ip_fp);
        }

        char command[1024];
        snprintf(command, sizeof(command), "%s %s > %s", TABLE_COMMAND, active_ip, ARP_TABLE_FILE);

#if defined(OS_WINDOWS)
        FILE* cmd = _popen(command, "r");
#else
        FILE* cmd = popen(command, "r");
#endif
        if (cmd) {
#if defined(OS_WINDOWS)
            _pclose(cmd);
#else
            pclose(cmd);
#endif
        }

        ArpEntry entries[MAX_ARP_ENTRIES];
        int count = read_arp_table(ARP_TABLE_FILE, entries, MAX_ARP_ENTRIES);

        time_t now = time(NULL);
        char *timestamp = ctime(&now);
        if (timestamp) timestamp[strcspn(timestamp, "\n")] = '\0';

        FILE *log_fp = fopen("log.txt", "a");
        if (count > 0 && check_arp_anomaly(entries, count)) {
            if (log_fp) fprintf(log_fp, "[%s] ARP SPOOF TESPİT EDİLDİ!\n", timestamp);
            clear_arp_spoofers(entries, count);
        } else {
                    }
        if (log_fp) fclose(log_fp);

    sleep_and_continue:
#if defined(OS_WINDOWS)
        Sleep(SLEEP_SECONDS * 1000);
#else
        sleep(SLEEP_SECONDS);
#endif
    }

#if defined(OS_WINDOWS)
    return 0;
#else
    return NULL;
#endif
}

#if defined(OS_WINDOWS)

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    (void)argc; (void)argv;

    g_StatusHandle = RegisterServiceCtrlHandler("ArpSecureService", ServiceCtrlHandler);
    if (g_StatusHandle == NULL) return;

    SERVICE_STATUS serviceStatus = {0};
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &serviceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &serviceStatus);
        return;
    }

    serviceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &serviceStatus);

    HANDLE thread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (thread == NULL) {
        CloseHandle(g_ServiceStopEvent);
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &serviceStatus);
        return;
    }

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    running = false;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    CloseHandle(g_ServiceStopEvent);

    serviceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &serviceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch(ctrlCode) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            if (g_ServiceStopEvent) SetEvent(g_ServiceStopEvent);
            break;
        default:
            break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    (void)lpParam;
    thread_func(NULL);
    return 0;
}

#endif

#if defined(OS_LINUX)
void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (chdir("/") < 0) exit(EXIT_FAILURE);

    umask(0);

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
}
#endif

int main(int argc, char *argv[]) {
    ensure_admin_rights();

#if defined(OS_LINUX)
    setlocale(LC_ALL, "tr_TR.UTF-8");
#else
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL,"Turkish_Turkey.1254");
#endif

#if defined(OS_LINUX)
    daemonize();
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);

#elif defined(OS_WINDOWS)
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        // Servis olarak çalıştırılmıyor, hemen çık
        return 1;
    }
#endif

    return 0;
}

