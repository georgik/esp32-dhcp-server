#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_vfs.h"
#include "esp_littlefs.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "cJSON.h"
#include "lwip/ip_addr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "CUSTOM_DHCP_SERVER";

#define MAX_RESERVATIONS 10

/* Reservation table entry: client MAC and reserved IP */
typedef struct {
    uint8_t mac[6];
    ip4_addr_t reserved_ip;
} dhcp_reservation_t;

static dhcp_reservation_t reservation_table[MAX_RESERVATIONS];
static int reservation_count = 0;

#define WIFI_CONFIG_FILE "/assets/wifi_config.json"
#define DHCP_RESERVATIONS_FILE "/assets/dhcp_reservations.json"

/* Wi‑Fi credentials structure */
typedef struct {
    char ssid[32];
    char password[64];
} wifi_config_data_t;

static wifi_config_data_t wifi_config_data = {
    .ssid = "Default_SSID",
    .password = "Default_Password"
};

/* Mount LittleFS from partition "assets" at /assets */
static esp_err_t mount_littlefs(void)
{
    esp_vfs_littlefs_conf_t conf = {
        .base_path = "/assets",
        .partition_label = "assets",
        .format_if_mount_failed = false,
        .dont_mount = false,
    };

    esp_err_t ret = esp_vfs_littlefs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount LittleFS: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "LittleFS mounted successfully");
    }
    return ret;
}

/* Load Wi‑Fi configuration from JSON file */
static esp_err_t load_wifi_config(void)
{
    FILE *f = fopen(WIFI_CONFIG_FILE, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open %s, using default config", WIFI_CONFIG_FILE);
        return ESP_FAIL;
    }
    char buffer[256];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
    buffer[bytes_read] = '\0';
    fclose(f);

    ESP_LOGI(TAG, "WiFi config file content: %s", buffer);
    cJSON *json = cJSON_Parse(buffer);
    if (json == NULL) {
        ESP_LOGE(TAG, "Error parsing WiFi config JSON");
        return ESP_FAIL;
    }

    cJSON *ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
    cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");

    if (cJSON_IsString(ssid) && (ssid->valuestring != NULL)) {
        strncpy(wifi_config_data.ssid, ssid->valuestring, sizeof(wifi_config_data.ssid) - 1);
    }
    if (cJSON_IsString(password) && (password->valuestring != NULL)) {
        strncpy(wifi_config_data.password, password->valuestring, sizeof(wifi_config_data.password) - 1);
    }

    cJSON_Delete(json);
    ESP_LOGI(TAG, "Loaded WiFi config: SSID=%s, Password=%s", wifi_config_data.ssid, wifi_config_data.password);
    return ESP_OK;
}

/* Parse a MAC address string (format "aa:bb:cc:dd:ee:ff") into a 6-byte array */
static esp_err_t parse_mac_string(const char *mac_str, uint8_t mac[6])
{
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Load DHCP reservations (MAC-to-IP mapping) from JSON file */
static esp_err_t load_dhcp_reservations(void)
{
    FILE *f = fopen(DHCP_RESERVATIONS_FILE, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", DHCP_RESERVATIONS_FILE);
        return ESP_FAIL;
    }
    char buffer[512];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
    buffer[bytes_read] = '\0';
    fclose(f);

    ESP_LOGI(TAG, "DHCP reservations file content: %s", buffer);
    cJSON *json = cJSON_Parse(buffer);
    if (json == NULL) {
        ESP_LOGE(TAG, "Error parsing DHCP reservations JSON");
        return ESP_FAIL;
    }

    cJSON *reservations = cJSON_GetObjectItemCaseSensitive(json, "reservations");
    if (!cJSON_IsArray(reservations)) {
        ESP_LOGE(TAG, "Reservations is not an array");
        cJSON_Delete(json);
        return ESP_FAIL;
    }

    reservation_count = 0;
    cJSON *reservation = NULL;
    cJSON_ArrayForEach(reservation, reservations) {
        if (reservation_count >= MAX_RESERVATIONS) {
            ESP_LOGW(TAG, "Maximum reservations reached");
            break;
        }
        cJSON *mac = cJSON_GetObjectItemCaseSensitive(reservation, "mac");
        cJSON *ip = cJSON_GetObjectItemCaseSensitive(reservation, "ip");
        if (cJSON_IsString(mac) && (mac->valuestring != NULL) &&
            cJSON_IsString(ip) && (ip->valuestring != NULL)) {

            if (parse_mac_string(mac->valuestring, reservation_table[reservation_count].mac) == ESP_OK) {
                if (inet_aton(ip->valuestring, (struct in_addr *)&reservation_table[reservation_count].reserved_ip)) {
                    ESP_LOGI(TAG, "Loaded reservation: MAC=%s, IP=%s", mac->valuestring, ip->valuestring);
                    reservation_count++;
                } else {
                    ESP_LOGE(TAG, "Invalid IP format: %s", ip->valuestring);
                }
            } else {
                ESP_LOGE(TAG, "Invalid MAC format: %s", mac->valuestring);
            }
        }
    }
    cJSON_Delete(json);
    return ESP_OK;
}

/* This function is called by the DHCP server task to check for a reserved IP
   for a given client MAC address. Returns the reserved IP if found, or 0.0.0.0 otherwise. */
ip4_addr_t get_reserved_ip_for_client(const uint8_t *client_mac)
{
    ip4_addr_t reserved_ip;
    IP4_ADDR(&reserved_ip, 0, 0, 0, 0);
    for (int i = 0; i < reservation_count; i++) {
        if (memcmp(client_mac, reservation_table[i].mac, 6) == 0) {
            ESP_LOGI(TAG, "Reservation match for client %02X:%02X:%02X:%02X:%02X:%02X: Reserved IP = " IPSTR,
                     client_mac[0], client_mac[1], client_mac[2],
                     client_mac[3], client_mac[4], client_mac[5],
                     IP2STR(&reservation_table[i].reserved_ip));
            return reservation_table[i].reserved_ip;
        }
    }
    return reserved_ip;
}

/* DHCP packet structure (RFC 2131) */
typedef struct __attribute__((packed)) {
    uint8_t op;       /* Message op code: 1 = BOOTREQUEST, 2 = BOOTREPLY */
    uint8_t htype;    /* Hardware address type */
    uint8_t hlen;     /* Hardware address length */
    uint8_t hops;
    uint32_t xid;     /* Transaction ID */
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    char sname[64];
    char file[128];
    uint8_t options[312]; // Options field (variable length in reality)
} dhcp_packet_t;

/* DHCP Message Types */
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPACK      5

/* Parse DHCP Message Type (Option 53) from options.
   Expects that the first 4 bytes of options are the magic cookie. */
static int get_dhcp_message_type(const uint8_t *options, size_t length) {
    if (length < 4) {
        ESP_LOGE(TAG, "Options length too short");
        return -1;
    }
    /* Check for magic cookie: 0x63, 0x82, 0x53, 0x63 */
    if (!(options[0] == 0x63 && options[1] == 0x82 &&
          options[2] == 0x53 && options[3] == 0x63)) {
        ESP_LOGE(TAG, "Magic cookie not found in DHCP options");
        return -1;
    }
    size_t i = 4;
    while (i < length) {
        uint8_t option_type = options[i];
        if (option_type == 255) break; // End option
        if (option_type == 0) { i++; continue; } // Padding
        if (i + 1 >= length) break;
        uint8_t option_len = options[i+1];
        if (option_type == 53 && option_len == 1) {
            return options[i+2];
        }
        i += 2 + option_len;
    }
    return -1;
}

/* Build a DHCP reply packet based on the request, offered IP, and reply type */
static void build_dhcp_reply(const dhcp_packet_t *request, dhcp_packet_t *reply, uint32_t offered_ip, uint8_t dhcp_msg_type) {
    reply->op = 2; // BOOTREPLY
    reply->htype = request->htype;
    reply->hlen = request->hlen;
    reply->hops = 0;
    reply->xid = request->xid;
    reply->secs = 0;
    reply->flags = request->flags;
    reply->ciaddr = 0;
    reply->yiaddr = offered_ip;
    reply->siaddr = inet_addr("192.168.4.1"); // Server IP
    reply->giaddr = 0;
    memcpy(reply->chaddr, request->chaddr, 16);
    memset(reply->sname, 0, sizeof(reply->sname));
    memset(reply->file, 0, sizeof(reply->file));
    uint8_t *opt = reply->options;
    /* Insert magic cookie */
    memcpy(opt, "\x63\x82\x53\x63", 4);
    opt += 4;
    /* DHCP Message Type Option */
    *opt++ = 53; *opt++ = 1; *opt++ = dhcp_msg_type;
    /* Server Identifier Option */
    *opt++ = 54; *opt++ = 4;
    uint32_t server_ip = inet_addr("192.168.4.1");
    memcpy(opt, &server_ip, 4); opt += 4;
    /* IP Address Lease Time Option */
    *opt++ = 51; *opt++ = 4;
    uint32_t lease_time = htonl(3600);
    memcpy(opt, &lease_time, 4); opt += 4;
    /* Subnet Mask Option */
    *opt++ = 1; *opt++ = 4;
    uint32_t subnet_mask = inet_addr("255.255.255.0");
    memcpy(opt, &subnet_mask, 4); opt += 4;
    /* Router Option */
    *opt++ = 3; *opt++ = 4;
    memcpy(opt, &server_ip, 4); opt += 4;
    /* End Option */
    *opt++ = 255;
}

/* Global dynamic IP counter (in network byte order) */
static uint32_t dynamic_ip_current;

/* Custom DHCP server task: listens on UDP port 67, processes DHCP requests, and replies */
static void dhcp_server_task(void *pvParameters) {
    int sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    dhcp_packet_t packet;
    char offered_ip_str[16];
    int header_size = 236; // Size of DHCP header (up to options)

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket");
        vTaskDelete(NULL);
        return;
    }
    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(67);
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind socket");
        close(sock);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "Custom DHCP server started");

    while (1) {
        int len = recvfrom(sock, &packet, sizeof(packet), 0,
                           (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0) {
            ESP_LOGE(TAG, "Failed to receive packet");
            continue;
        }
        if (len < header_size) {
            ESP_LOGE(TAG, "Received packet too short: %d bytes", len);
            continue;
        }
        size_t options_len = len - header_size;
        int msg_type = get_dhcp_message_type(packet.options, options_len);
        if (msg_type < 0) {
            ESP_LOGE(TAG, "DHCP message type not found");
            continue;
        }
        uint8_t *client_mac = packet.chaddr;
        ESP_LOGI(TAG, "Received DHCP message type %d from %02X:%02X:%02X:%02X:%02X:%02X",
                 msg_type,
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);

        uint32_t offered_ip = 0;
        ip4_addr_t reserved = get_reserved_ip_for_client(client_mac);
        if (!ip4_addr_isany_val(reserved)) {
            offered_ip = reserved.addr;
        } else {
            offered_ip = dynamic_ip_current;
            dynamic_ip_current = htonl(ntohl(dynamic_ip_current) + 1);
        }

        dhcp_packet_t reply;
        memset(&reply, 0, sizeof(reply));
        uint8_t reply_type = (msg_type == DHCPDISCOVER) ? DHCPOFFER : DHCPACK;
        build_dhcp_reply(&packet, &reply, offered_ip, reply_type);

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(68);
        dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

        sendto(sock, &reply, sizeof(reply), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        ESP_LOGI(TAG, "Sent DHCP reply with offered IP: %s", inet_ntop(AF_INET, &offered_ip, offered_ip_str, sizeof(offered_ip_str)));
    }
    close(sock);
    vTaskDelete(NULL);
}

/* Initialize Wi‑Fi in AP mode and stop built-in DHCP server */
static void wifi_init_softap(void) {
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.ap.ssid, wifi_config_data.ssid, sizeof(wifi_config.ap.ssid));
    wifi_config.ap.ssid_len = strlen(wifi_config_data.ssid);
    strncpy((char *)wifi_config.ap.password, wifi_config_data.password, sizeof(wifi_config.ap.password));
    wifi_config.ap.channel = 1;
    wifi_config.ap.max_connection = 4;
    wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
    if (strlen(wifi_config_data.password) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "SoftAP started. SSID: %s, Password: %s", wifi_config_data.ssid, wifi_config_data.password);

    /* Stop built-in DHCP server so our custom server can use port 67 */
    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
    ESP_LOGI(TAG, "Built-in DHCP server stopped.");
}

/* Main entry point */
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    if (mount_littlefs() != ESP_OK) {
        ESP_LOGE(TAG, "LittleFS mount failed");
    }
    load_wifi_config();
    load_dhcp_reservations();

    wifi_init_softap();

    /* Initialize dynamic IP pool starting at 192.168.4.2 */
    dynamic_ip_current = inet_addr("192.168.4.2");

    /* Start the custom DHCP server task */
    xTaskCreate(dhcp_server_task, "dhcp_server_task", 4096, NULL, 5, NULL);
}
