#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char* gmf_run_once_mobile(const char* api, const char* client_id, const char* api_key, int32_t lease_seconds);
void  gmf_string_free(char* s);

#ifdef __cplusplus
}
#endif
