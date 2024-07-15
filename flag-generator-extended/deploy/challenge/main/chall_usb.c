#include <stdint.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/ip4_addr.h"
#include "tinyusb.h"
#include "tinyusb_net.h"


static const char *TAG = "usb";

#define STATIC_IP_ADDR "10.11.12.2"
#define DEFAULT_GATEWAY "10.11.12.1"
#define DEFAULT_NETMASK "255.255.255.0"

static esp_netif_t *s_netif = NULL;

esp_err_t usb_ncm_send(void *buffer, uint16_t len, void *buff_free_arg) {
    return tinyusb_net_send_sync(buffer, len, buff_free_arg, pdMS_TO_TICKS(100));
}

static void l2_free(void *h, void *buffer) {
    free(buffer);
}

static esp_err_t netif_transmit (void *h, void *buffer, size_t len) {
    if (usb_ncm_send(buffer, len, NULL) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to send buffer to USB!");
    }
    return ESP_OK;
}

static esp_err_t netif_recv_callback(void *buffer, uint16_t len, void *ctx) {
    if (s_netif) {
        void *buf_copy = malloc(len);
        if (!buf_copy) {
            return ESP_ERR_NO_MEM;
        }
        memcpy(buf_copy, buffer, len);
        return esp_netif_receive(s_netif, buf_copy, len, NULL);
    }
    return ESP_OK;
}

esp_err_t usb_ncm_init(void) {
    // ip address for interface
    ip4_addr_t ip;
    ip4_addr_t gw;
    ip4_addr_t netmask;
    ip4addr_aton(STATIC_IP_ADDR, &ip);
    ip4addr_aton((const char *)DEFAULT_GATEWAY, &gw);
    ip4addr_aton((const char *)DEFAULT_NETMASK, &netmask);

    // Convert to esp_netif_ip_info_t
    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(esp_netif_ip_info_t));
    ip_info.ip.addr = ip.addr;
    ip_info.gw.addr = gw.addr;
    ip_info.netmask.addr = netmask.addr;

    const tinyusb_net_config_t net_config = {
        // locally administrated address for the ncm device as it's going to be used internally
        // for configuration only
        .mac_addr = {0x02, 0x02, 0x11, 0x22, 0x33, 0x01},
        .on_recv_callback = netif_recv_callback,
    };

    esp_err_t ret = tinyusb_net_init(TINYUSB_USBDEV_0, &net_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Cannot initialize USB Net device");
        return ret;
    }

    // with OUI range MAC to create a virtual netif running http server
    // this needs to be different to usb_interface_mac (==client)
    uint8_t lwip_addr[6] =  {0x02, 0x02, 0x11, 0x22, 0x33, 0x02};

    // Definition of
    // 1) Derive the base config (very similar to IDF's default WiFi AP with DHCP server)
    esp_netif_inherent_config_t base_cfg =  {
        .flags = ESP_NETIF_FLAG_EVENT_IP_MODIFIED | ESP_NETIF_FLAG_AUTOUP | ESP_NETIF_DHCP_SERVER,
        .ip_info = &ip_info,
        .get_ip_event = IP_EVENT_ETH_GOT_IP,
        .lost_ip_event = IP_EVENT_ETH_LOST_IP,
        .if_key = "usb_eth",
        .if_desc = "usb ncm config device",
        .route_prio = 10
    };

    // 2) Use static config for driver's config pointing only to static transmit and free functions
    esp_netif_driver_ifconfig_t driver_cfg = {
        .handle = (void *)1,                // not using an instance, USB-NCM is a static singleton (must be != NULL)
        .transmit = netif_transmit,         // point to static Tx function
        .driver_free_rx_buffer = l2_free    // point to Free Rx buffer function
    };

    // Config the esp-netif with:
    //   1) inherent config (behavioural settings of an interface)
    //   2) driver's config (connection to IO functions -- usb)
    //   3) stack config (using lwip IO functions -- derive from eth)
    esp_netif_config_t cfg = {
        .base = &base_cfg,
        .driver = &driver_cfg,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH, // USB-NCM is an Ethernet netif from lwip perspective, we already have IO definitions for that:
    };

    s_netif = esp_netif_new(&cfg);
    if (s_netif == NULL) {
        return ESP_FAIL;
    }
    esp_netif_set_mac(s_netif, lwip_addr);

    // start the interface manually (as the driver has been started already)
    esp_netif_action_start(s_netif, 0, 0, 0);
    return ESP_OK;
}

esp_err_t init_usb() {
    esp_err_t ret;
    ESP_LOGI(TAG, "USB initialization");
    const tinyusb_config_t tusb_cfg = {
        .device_descriptor = NULL,
        .string_descriptor = NULL,
        .external_phy = false,
        .configuration_descriptor = NULL,
    };

    ret = tinyusb_driver_install(&tusb_cfg);
    if (ret != ESP_OK) {
        return ret;
    }
    ret = usb_ncm_init();
    if (ret != ESP_OK) {
        return ret;
    }
    ESP_LOGI(TAG, "USB initialization DONE");
    return ESP_OK;
}
