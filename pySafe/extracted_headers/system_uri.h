void open_uri(char* uri, void* user_data, void (*o_cb)(void* user_data, FfiResult* result));
void install(char* bundle, char* vendor, char* name, char* exec_args, uint_least64_t exec_args_len, char* icon, char* schemes, void* user_data, void (*o_cb)(void* user_data, FfiResult* result));
