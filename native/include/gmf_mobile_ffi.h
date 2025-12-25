#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int gmf_register_device(const char* api, const char* device_id, const char* platform, const char* topics, int64_t ram_mb, int64_t disk_mb);
int gmf_tick(const char* api, const char* device_id, const char* platform, const char* topics);
const char* gmf_mobile_ffi_header(void);
#ifdef __cplusplus
}
#endif
