void app_exe_file_stem(void* user_data, void(*)(void*, FfiResult*, char*));
void login(char* account_locator, char* account_password, void* user_data, void(*)(void*), void(*)(void*, FfiResult*, Authenticator*));
void create_acc(char* account_locator, char* account_password, char* invitation, void* user_data, void(*)(void*), void(*)(void*, FfiResult*, Authenticator*));
void auth_set_additional_search_path(char const* new_path, void* user_data, void (*o_cb)(void* user_data, FfiResult const* result));
