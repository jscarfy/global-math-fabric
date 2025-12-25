#pragma once
#ifdef __cplusplus
extern "C" {
#endif

char* gmf_run_job(const char* input_json);
void  gmf_free(void* p);

// compatibility
char* gmf_ios_run_job(const char* input_json);
void  gmf_ios_free(void* p);

#ifdef __cplusplus
}
#endif
