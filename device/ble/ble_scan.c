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
#include <zmq.h>

int sock = -1;
struct hci_filter old_filter, new_filter;
static void *context = NULL;
static void *publisher = NULL;

void cleanup(int sig) {
    if (sock >= 0) {
        // Disable scanning
		hci_le_set_scan_enable(sock, 0x00, 0x00, 1000);
        // Restore old filter
        setsockopt(sock, SOL_HCI, HCI_FILTER, &old_filter, sizeof(old_filter));
        close(sock);
    }
    if (publisher) zmq_close(publisher);
    if (context) zmq_ctx_destroy(context);
    printf("\nSocket closed, scanning stopped (signal %d).\n", sig);
    exit(0);
}

char *get_device_name(const uint8_t *data, size_t length) {
	size_t offset = 0;
    static char name[256]; // static buffer for simplicity
    memset(name, 0, sizeof(name));

    while (offset < length) {
        uint8_t field_len = data[offset];
        if (field_len == 0) break;  // no more fields

        if (offset + field_len >= length) break; // safety check

        uint8_t ad_type = data[offset + 1];

        if (ad_type == 0x09 || ad_type == 0x08) { // complete or short name
            memcpy(name, &data[offset + 2], field_len - 1);
            name[field_len - 1] = '\0';
            return name;
        }

        offset += field_len + 1; // move to next field
    }

    return NULL; // no name found
}

int main() {
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    int dev_id;
    socklen_t olen;

    // 1. Get the first available Bluetooth adapter
    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("No Bluetooth Adapter Available");
        exit(1);
    }

    // 2. Open a raw HCI socket to the adapter
    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("HCI device open failed");
        exit(1);
    }

    // 3. Save the current socket filter (so we can restore it later)
    olen = sizeof(old_filter);
    if (getsockopt(sock, SOL_HCI, HCI_FILTER, &old_filter, &olen) < 0) {
        perror("Could not get socket options");
        close(sock);
        exit(1);
    }

    // 4. Set new HCI filter: we only want LE Meta Events
    hci_filter_clear(&new_filter);
    hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
    hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &new_filter, sizeof(new_filter)) < 0) {
        perror("Could not set socket options");
        close(sock);
        exit(1);
    }

    // 5. Set scan parameters (active scan, interval, window)
    if (hci_le_set_scan_parameters(sock, 0x01, 0x10, 0x10, 0x00, 0x00, 1000) < 0) {
        perror("Set scan parameters failed");
        close(sock);
        exit(1);
    }

    // 6. Enable scanning
    if (hci_le_set_scan_enable(sock, 0x01, 0x00, 1000) < 0) {
        perror("Enable scan failed");
        close(sock);
        exit(1);
    }

    printf("Scanning for BLE devices...\n");

	// ZeroMQ publisher
    context = zmq_ctx_new();
    publisher = zmq_socket(context, ZMQ_PUB);
    zmq_bind(publisher, "tcp://127.0.0.1:5556");
    printf("Publishing BLE devices on tcp://127.0.0.1:5556 ...\n");

    // 7. Read events in a loop
    unsigned char buf[HCI_MAX_EVENT_SIZE];
    while (1) {
        int len = read(sock, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("Read failed");
            break;
        }

        // 8. Extract LE Meta Event
        evt_le_meta_event *meta = (evt_le_meta_event *)(buf + (1 + HCI_EVENT_HDR_SIZE));
        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) continue;

        // 9. Parse advertising reports
        uint8_t reports_count = meta->data[0];
        le_advertising_info *info = (le_advertising_info *)(meta->data + 1);

        for (int i = 0; i < reports_count; i++) {
            char addr[18];
            ba2str(&info->bdaddr, addr);
            int8_t rssi = (int8_t)info->data[info->length];

            char msg[64];
            snprintf(msg, sizeof(msg), "%s %d", addr, rssi);

            zmq_send(publisher, msg, strlen(msg), 0);
            printf("Sent: %s\n", msg);

            // Move to next report in case of multiple
            info = (le_advertising_info *)((uint8_t *)info + info->length + 2 + 1);
        }
    }

    cleanup(0);
    return 0;
}
