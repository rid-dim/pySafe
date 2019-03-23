# Fundamental behaviour
GLOBAL_DEFAULT_TIMEOUT = 10         # default seconds to wait for ffi calls.  Overridden by classes calling bind_method
GLOBAL_DEFAULT_ENCODING = 'utf-8'   # affects how strings are passed to ffi
GLOBAL_BINPATH = None               # Hand code a path to the binaries.  Left alone, bins from ../compiled_binaries/

# Logging.. Really mostly for dev stuff.  Turn top two to false, and everything is disabled
GLOBAL_AUTO_INIT_LOGGING  = False    # If true, logging will happen without an explicit call to logutil.setup_logger()
GLOBAL_ENABLE_FILE_LOGGING = True   # Writes a detailed log to /logs/log.txt
GLOBAL_ENABLE_STD_LOGGING = True    # Writes log to stdout
GLOBAL_LOGGER_NAME        = 'pySafe'

GLOBAL_MASTER_HIGHPASS    = 'debug' # Logs of lower level will be dropped entirely
GLOBAL_FILE_LOG_HIGHPASS  = 'debug' # Logs less serious than this will be dropped from file stream
GLOBAL_STD_LOG_HIGHPASS   = 'debug' # Logs less serious than this will be dropped from stout strem
GLOBAL_FILE_LOG_FORMAT    = 'debug' # debug, deluxe, simple
GLOBAL_STD_LOG_FORMAT     = 'debug' # debug, deluxe, simple