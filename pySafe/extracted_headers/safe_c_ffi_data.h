typedef int int32_t;
typedef struct {
    int32_t error_code;
    char* description;
} FfiResult;
typedef struct {
    void* core_tx;
    void* _core_joiner;
} Authenticator;