#include <string.h>

#include "esp_log.h"
#include "esp_check.h"
#include "esp32s3/rom/ets_sys.h"
#include "projdefs.h"
#include "ulp_common.h"
#include "ulp_fsm_common.h"
#include "ulp_fsm_main.h"
#include "FreeRTOS.h"

#include "chall_decrypt.h"

static const char *TAG = "ulp_fsm";

const TickType_t max_block_time = pdMS_TO_TICKS(1000);

extern const uint8_t ulp_fsm_bin_start[] asm("_binary_ulp_fsm_main_bin_start");
extern const uint8_t ulp_fsm_bin_end[]   asm("_binary_ulp_fsm_main_bin_end");

void ulp_fsm_interrupt(void *arg) {
    TaskHandle_t task = (TaskHandle_t) arg;
    ets_printf("ULP FSM interrupt triggered\n");
    vTaskNotifyGiveFromISR(task, NULL);
}

esp_err_t ulp_fsm_init_program(void) {
    esp_err_t err = ulp_load_binary(0, ulp_fsm_bin_start, (ulp_fsm_bin_end - ulp_fsm_bin_start) / sizeof(uint32_t));
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_load_binary");

    err = ulp_isr_register(ulp_fsm_interrupt, xTaskGetCurrentTaskHandle());
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_isr_register");

    // Set ULP wake up period to T = 1ms.
    err = ulp_set_wakeup_period(0, 1000);
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_set_wakeup_period");
    return ESP_OK;
}

esp_err_t ulp_fsm_run_program(void) {
    /* Start the program */
    esp_err_t err = ulp_run(&ulp_entry - RTC_SLOW_MEM);
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_run");

    // Wait for program to finish
    uint32_t notification_value = ulTaskNotifyTake(pdTRUE, max_block_time);

    // disable timer just in case the program didn't work
    ulp_timer_stop();

    ulp_isr_deregister(ulp_fsm_interrupt, xTaskGetCurrentTaskHandle());

    if (notification_value == 1) {
        return ESP_OK;
    } else {
        return ESP_ERR_TIMEOUT;
    }
}

esp_err_t decrypt_finite(char* key, char* iv, char* data, int len) {
    if (len > MAX_DEC_SIZE) {
        ESP_LOGE(TAG, "Decryption len (%d) larger than max (%d)", len, MAX_DEC_SIZE);
        return ESP_ERR_INVALID_ARG;
    }
    ESP_ERROR_CHECK(ulp_fsm_init_program());

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
    memcpy(&ulp_key, key, KEY_LEN);
    memcpy(&ulp_iv, iv, IV_LEN);
    memcpy(&ulp_data, data, len);
#pragma GCC diagnostic pop
    ulp_data_len = len / 4;

    ESP_ERROR_CHECK(ulp_fsm_run_program());

    memcpy(data, &ulp_data, len);
    return ESP_OK;
}
