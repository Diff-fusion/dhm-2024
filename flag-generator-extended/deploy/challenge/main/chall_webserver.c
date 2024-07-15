#include "string.h"
#include "stdlib.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "mbedtls/base64.h"
#include "chall_decrypt.h"
#include "chall_ulp_fsm.h"
#include "chall_ulp_riscv.h"

static const char *TAG = "webserver";

static esp_err_t js_get_handler(httpd_req_t *req) {
    extern const unsigned char js_start[] asm("_binary_sha256_min_js_start");
    extern const unsigned char js_end[]   asm("_binary_sha256_min_js_end");
    const size_t js_size = (js_end - js_start);
    httpd_resp_set_type(req, "text/javascript");
    httpd_resp_send(req, (const char *)js_start, js_size);
    return ESP_OK;
}

static const httpd_uri_t js_uri = {
    .uri       = "/sha256.min.js",
    .method    = HTTP_GET,
    .handler   = js_get_handler,
};

static esp_err_t css_get_handler(httpd_req_t *req) {
    extern const unsigned char css_start[] asm("_binary_simple_min_css_start");
    extern const unsigned char css_end[]   asm("_binary_simple_min_css_end");
    const size_t css_size = (css_end - css_start);
    httpd_resp_set_type(req, "text/css");
    httpd_resp_send(req, (const char *)css_start, css_size);
    return ESP_OK;
}

static const httpd_uri_t css_uri = {
    .uri       = "/simple.min.css",
    .method    = HTTP_GET,
    .handler   = css_get_handler,
};

static esp_err_t index_get_handler(httpd_req_t *req) {
    extern const unsigned char index_start[] asm("_binary_index_html_start");
    extern const unsigned char index_end[]   asm("_binary_index_html_end");
    const size_t index_size = (index_end - index_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)index_start, index_size);
    return ESP_OK;
}

static const httpd_uri_t index_uri = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
};

static esp_err_t favicon_get_handler(httpd_req_t *req) {
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const unsigned char favicon_ico_end[]   asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_set_type(req, "image/x-icon");
    httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size);
    return ESP_OK;
}

static const httpd_uri_t favicon_uri = {
    .uri       = "/favicon.ico",
    .method    = HTTP_GET,
    .handler   = favicon_get_handler,
};

static void decode_url(char *url) {
    char *match;
    while ((match = strstr(url, "%3D")) != 0) {
        match[0] = '=';
        memmove(match+1, match+3, strlen(match+3)+1);
    }
}

static esp_err_t decrypt_handler(httpd_req_t *req) {
    char key[32], iv[32], type[32];
    int query_buf_len = httpd_req_get_url_query_len(req) + 1;
    if (query_buf_len == 0) {
        ESP_LOGI(TAG, "No query string in decrypt request");
        return ESP_ERR_INVALID_ARG;
    }

    char *query_buf = malloc(query_buf_len);
    if (!query_buf) {
        ESP_LOGE(TAG, "Out of memory");
        return ESP_ERR_NO_MEM;
    }
    if (httpd_req_get_url_query_str(req, query_buf, query_buf_len) != ESP_OK) {
        ESP_LOGI(TAG, "Invalid query string in decrypt request");
        free(query_buf);
        return ESP_ERR_INVALID_ARG;
    }

    if (httpd_query_key_value(query_buf, "type", type, sizeof(type)) != ESP_OK) {
        ESP_LOGI(TAG, "Invalid `type` parameter for query string in decrypt request");
        free(query_buf);
        return ESP_ERR_INVALID_ARG;
    }

    if (httpd_query_key_value(query_buf, "key", key, sizeof(key)) != ESP_OK) {
        ESP_LOGI(TAG, "Invalid `key` parameter for query string in decrypt request");
        free(query_buf);
        return ESP_ERR_INVALID_ARG;
    }
    decode_url(key);
    size_t olen;
    if (mbedtls_base64_decode((unsigned char*)key, sizeof(key), &olen, (unsigned char*)key, strlen(key)) != 0 || olen != KEY_LEN) {
        ESP_LOGI(TAG, "Invalid `key` parameter: can't decode buf: %s olen: %zu", key, olen);
        free(query_buf);
        return ESP_ERR_INVALID_ARG;
    }

    if (httpd_query_key_value(query_buf, "iv", iv, sizeof(iv)) != ESP_OK) {
        ESP_LOGI(TAG, "Invalid `iv` parameter for query string in decrypt request");
        free(query_buf);
        return ESP_ERR_INVALID_ARG;
    }
    decode_url(iv);
    if (mbedtls_base64_decode((unsigned char*)iv, sizeof(iv), &olen, (unsigned char*)iv, strlen(iv)) != 0 || olen != IV_LEN) {
        ESP_LOGI(TAG, "Invalid `iv` parameter: can't decode");
        free(query_buf);
        return ESP_ERR_INVALID_ARG;
    }
    free(query_buf);

    int total_len = req->content_len;
    if (total_len > MAX_DEC_SIZE) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    char *buf = malloc(total_len);
    int cur_len = 0, received = 0;
    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len - cur_len);
        if (received <= 0) {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to recieve post value");
            free(buf);
            return ESP_FAIL;
        }
        cur_len += received;
    }

    ESP_LOGD(TAG, "Successfully received decryption request");
    ESP_LOGD(TAG, "Type: %s", type);
    ESP_LOGD(TAG, "Key:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, key, KEY_LEN, ESP_LOG_DEBUG);
    ESP_LOGD(TAG, "IV:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, iv, IV_LEN, ESP_LOG_DEBUG);
    ESP_LOGD(TAG, "Data:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, buf, total_len, ESP_LOG_DEBUG);

    if (strcmp(type, "extended") == 0) {
        ESP_LOGI(TAG, "Starting decryption of type `extended`");
        decrypt_extended(key, iv, buf, total_len);
    } else if (strcmp(type, "finite") == 0) {
        ESP_LOGI(TAG, "Starting decryption of type `finite`");
        decrypt_finite(key, iv, buf, total_len);
    } else if (strcmp(type, "riscy") == 0) {
        ESP_LOGI(TAG, "Starting decryption of type `riscy`");
        decrypt_riscy(key, iv, buf, total_len);
    } else {
        ESP_LOGI(TAG, "Unknown encryption type %s", type);
    }
    ESP_LOGI(TAG, "Decryption done!");

    ESP_LOGD(TAG, "Decrypted data:");
    ESP_LOG_BUFFER_HEXDUMP(TAG, buf, total_len, ESP_LOG_DEBUG);

    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_send(req, buf, total_len);
    free(buf);
    return ESP_OK;
}

static const httpd_uri_t decrypt_uri = {
    .uri       = "/decrypt",
    .method    = HTTP_POST,
    .handler   = decrypt_handler,
};

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

httpd_handle_t start_webserver(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &index_uri);
        httpd_register_uri_handler(server, &decrypt_uri);
        httpd_register_uri_handler(server, &css_uri);
        httpd_register_uri_handler(server, &js_uri);
        httpd_register_uri_handler(server, &favicon_uri);
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http_404_error_handler);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

esp_err_t stop_webserver(httpd_handle_t server) {
    return httpd_stop(server);
}
