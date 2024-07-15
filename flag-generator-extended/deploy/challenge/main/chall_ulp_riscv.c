#include <string.h>

#include "esp_log.h"
#include "esp_check.h"
#include "esp32s3/rom/ets_sys.h"
#include "esp_err.h"
#include "ulp_riscv.h"
#include "ulp_riscv_main.h"
#include "FreeRTOS.h"

#include "chall_decrypt.h"

static const char *TAG = "ulp_riscv";

const TickType_t ulp_riscv_max_block_time = pdMS_TO_TICKS(1000);

extern const uint8_t ulp_riscv_bin_start[] asm("_binary_ulp_riscv_main_bin_start");
extern const uint8_t ulp_riscv_bin_end[]   asm("_binary_ulp_riscv_main_bin_end");

void ulp_riscv_interrupt(void *arg) {
    TaskHandle_t task = (TaskHandle_t) arg;
    ets_printf("ULP RISCV interrupt triggered\n");
    vTaskNotifyGiveFromISR(task, NULL);
}

esp_err_t ulp_riscv_init_program(void) {
    esp_err_t err = ulp_riscv_load_binary(ulp_riscv_bin_start, (ulp_riscv_bin_end - ulp_riscv_bin_start));
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_riscv_load_binary");

    err = ulp_riscv_isr_register(ulp_riscv_interrupt, xTaskGetCurrentTaskHandle(), ULP_RISCV_SW_INT);
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_riscv_isr_register");

    // Set ULP wake up period to T = 1ms.
    ulp_set_wakeup_period(0, 1000);
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_set_wakeup_period");
    return ESP_OK;
}

esp_err_t ulp_riscv_run_program(void) {
    /* Start the program */
    esp_err_t err = ulp_riscv_run();
    ESP_RETURN_ON_ERROR(err, TAG, "ulp_riscv_run");

    // Wait for program to finish
    uint32_t notification_value = ulTaskNotifyTake(pdTRUE, ulp_riscv_max_block_time);

    // disable timer just in case the program didn't work
    ulp_timer_stop();

    ulp_riscv_isr_deregister(ulp_riscv_interrupt, xTaskGetCurrentTaskHandle(), ULP_RISCV_SW_INT);

    if (notification_value == 1) {
        return ESP_OK;
    } else {
        return ESP_ERR_TIMEOUT;
    }
}

esp_err_t decrypt_riscy(char* key, char* iv, char* data, int len) {
    if (len > MAX_DEC_SIZE) {
        ESP_LOGE(TAG, "Decryption len (%d) larger than max (%d)", len, MAX_DEC_SIZE);
        return ESP_ERR_INVALID_ARG;
    }
    ESP_ERROR_CHECK(ulp_riscv_init_program());

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
    memcpy(&ulp_riscv_key, key, KEY_LEN);
    memcpy(&ulp_riscv_iv, iv, IV_LEN);
    memcpy(&ulp_riscv_data, data, len);
#pragma GCC diagnostic pop
    ulp_riscv_data_len = len;

    ESP_ERROR_CHECK(ulp_riscv_run_program());

    memcpy(data, &ulp_riscv_data, len);
    return ESP_OK;
}
