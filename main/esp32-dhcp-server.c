#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
#include "lwip/inet.h"

static const char *TAG = "ESP32_DHCP_SERVER";

#define MAX_RESERVATIONS 10

typedef struct {
    uint8_t mac[6];
    ip4_addr_t reserved_ip;
} dhcp_reservation_t;

static dhcp_reservation_t reservation_table[MAX_RESERVATIONS];
static int reservation_count = 0;

#define WIFI_CONFIG_FILE "/assets/wifi_config.json"
#define DHCP_RESERVATIONS_FILE "/assets/dhcp_reservations.json"

typedef struct {
    char ssid[32];
    char password[64];
} wifi_config_data_t;

static wifi_config_data_t wifi_config_data = {
    .ssid = "Default_SSID",
    .password = "Default_Password"
};

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

static esp_err_t parse_mac_string(const char *mac_str, uint8_t mac[6])
{
    // Expected format: "aa:bb:cc:dd:ee:ff"
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

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
                // Convert IP string to ip4_addr_t using inet_aton
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

static void wifi_init_softap(void)
{
    // Create default AP netif
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

    // The built-in DHCP server automatically starts in AP mode.
    ESP_LOGI(TAG, "DHCP server started with dynamic allocation.");
}

void app_main(void)
{
    // Initialize NVS (credentials and reservation data could be stored in NVS in production)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize network stack
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Mount LittleFS and load configuration files
    if (mount_littlefs() != ESP_OK) {
        ESP_LOGE(TAG, "LittleFS mount failed");
    }
    load_wifi_config();
    load_dhcp_reservations();

    // Initialize WiFi in AP mode using loaded configuration
    wifi_init_softap();
}
