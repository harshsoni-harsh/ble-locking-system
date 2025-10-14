#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#define MAX_CONNECTIONS 10
#define POLLING_INTERVAL_US 200000 // 200ms = 5 polls per second

// Creates a formatted timestamp string with milliseconds
void get_timestamp(char *buffer, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    strftime(buffer, len, "%H:%M:%S", tm_info);
    int ms = tv.tv_usec / 1000;
    snprintf(buffer + 8, len - 8, ".%03d", ms);
}

// Struct to hold info about a connected device
struct connected_device {
    uint16_t handle;
    bdaddr_t addr;
    uint8_t addr_type;
};

// Global state
static int sock = -1;
static volatile int running = 1;
struct connected_device connection_list[MAX_CONNECTIONS];
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper to add a connection to our list
void add_connection(uint16_t handle, bdaddr_t *addr, uint8_t type) {
    char ts[20];
    get_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&list_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connection_list[i].handle == 0) { // Find empty slot
            connection_list[i].handle = handle;
            bacpy(&connection_list[i].addr, addr);
            connection_list[i].addr_type = type;
            char addr_str[18];
            ba2str(addr, addr_str);
            printf("%s >> DEVICE CONNECTED: Handle %d, Address %s\n", ts, handle, addr_str);
            fflush(stdout);
            break;
        }
    }
    pthread_mutex_unlock(&list_mutex);
}

// Helper to remove a connection from our list
void remove_connection(uint16_t handle) {
    char ts[20];
    get_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&list_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connection_list[i].handle == handle) {
            char addr_str[18];
            ba2str(&connection_list[i].addr, addr_str);
            printf("%s << DEVICE DISCONNECTED: Handle %d, Address %s\n", ts, handle, addr_str);
            fflush(stdout);
            memset(&connection_list[i], 0, sizeof(struct connected_device));
            break;
        }
    }
    pthread_mutex_unlock(&list_mutex);
}

// The background thread for polling RSSI
void *rssi_poll_thread(void *arg) {
    char ts[20];
    get_timestamp(ts, sizeof(ts));
    printf("%s RSSI polling thread started.\n", ts);
    fflush(stdout);

    while (running) {
        // More robust timer to maintain a consistent rate
        struct timeval start_time, end_time;
        gettimeofday(&start_time, NULL);

        pthread_mutex_lock(&list_mutex);
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (connection_list[i].handle != 0) {
                int8_t rssi;
                if (hci_read_rssi(sock, connection_list[i].handle, &rssi, 1000) < 0) {
                    get_timestamp(ts, sizeof(ts));
                    // Don't use perror as it goes to stderr, which might not be visible
                    printf("%s [ERROR] Failed to read RSSI for handle %d: %s\n", ts, connection_list[i].handle, strerror(errno));
                    fflush(stdout);
                    continue;
                }
                
                char addr_str[18];
                ba2str(&connection_list[i].addr, addr_str);
                get_timestamp(ts, sizeof(ts));
                printf("%s    [RSSI] %s -> %d dBm\n", ts, addr_str, rssi);
                fflush(stdout);
            }
        }
        pthread_mutex_unlock(&list_mutex);

        gettimeofday(&end_time, NULL);
        long elapsed_us = (end_time.tv_sec - start_time.tv_sec) * 1000000L + (end_time.tv_usec - start_time.tv_usec);
        
        if (elapsed_us < POLLING_INTERVAL_US) {
            usleep(POLLING_INTERVAL_US - elapsed_us);
        }
    }
    get_timestamp(ts, sizeof(ts));
    printf("%s RSSI polling thread finished.\n", ts);
    fflush(stdout);
    return NULL;
}

void cleanup(int sig) {
    printf("\nCleaning up...\n");
    running = 0;
    if (sock >= 0) {
        pthread_mutex_lock(&list_mutex);
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (connection_list[i].handle != 0) {
				printf("Disconnecting handle %d...\n", connection_list[i].handle);
				fflush(stdout);
                hci_disconnect(sock, connection_list[i].handle, HCI_OE_USER_ENDED_CONNECTION, 1000);
            }
        }
        pthread_mutex_unlock(&list_mutex);
        close(sock);
    }
    exit(0);
}

int main() {
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    memset(connection_list, 0, sizeof(connection_list));

    int dev_id = hci_get_route(NULL);
    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Failed to open HCI socket");
        exit(1);
    }

    struct hci_filter flt;
    hci_filter_clear(&flt);
    hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
    hci_filter_set_event(EVT_LE_META_EVENT, &flt);
    hci_filter_set_event(EVT_DISCONN_COMPLETE, &flt);
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
        perror("Failed to set HCI filter");
        close(sock);
        exit(1);
    }

    pthread_t poll_thread_id;
    if (pthread_create(&poll_thread_id, NULL, rssi_poll_thread, NULL)) {
        perror("Failed to create RSSI poll thread");
        close(sock);
        exit(1);
    }

    char ts[20];
    get_timestamp(ts, sizeof(ts));
    printf("%s Listening for LE connection events...\n", ts);
    fflush(stdout);

    while (running) {
        unsigned char buf[HCI_MAX_EVENT_SIZE];
        int len = read(sock, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("HCI read failed");
            break;
        }

        if (buf[0] != HCI_EVENT_PKT) continue;
        
        get_timestamp(ts, sizeof(ts));
        hci_event_hdr *hdr = (hci_event_hdr *)(buf + 1);
        printf("%s Received HCI Event: 0x%02X\n", ts, hdr->evt);
        fflush(stdout);

        switch (hdr->evt) {
            case EVT_LE_META_EVENT: {
                evt_le_meta_event *meta = (evt_le_meta_event *)(buf + 1 + HCI_EVENT_HDR_SIZE);
                if (meta->subevent == EVT_LE_CONN_COMPLETE || meta->subevent == 0x0A) {
                    evt_le_connection_complete *cc = (evt_le_connection_complete *)meta->data;
                    if (cc->status == 0) {
                        add_connection(btohs(cc->handle), &cc->peer_bdaddr, cc->peer_bdaddr_type);
                    }
                } 
                break;
            }
            case EVT_DISCONN_COMPLETE: {
                evt_disconn_complete *dc = (evt_disconn_complete *)(buf + 1 + HCI_EVENT_HDR_SIZE);
                if (dc->status == 0) {
                    remove_connection(btohs(dc->handle));
                }
                break;
            }
        }
    }

    pthread_join(poll_thread_id, NULL);
    cleanup(0);
    return 0;
}
