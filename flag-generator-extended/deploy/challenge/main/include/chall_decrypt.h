#include "esp_err.h"

#define MAX_DEC_SIZE 4096
#define KEY_LEN 16
#define IV_LEN 16

esp_err_t decrypt_extended(char* key, char* iv, char* data, int len);
