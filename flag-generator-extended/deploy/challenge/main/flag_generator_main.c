#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

#include "chall_usb.h"
#include "chall_webserver.h"

static const char *TAG = "flag_generator";

void app_main(void) {
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(init_usb());
    start_webserver();
    ESP_LOGI(TAG, "Webserver started, waiting for connections");
}

