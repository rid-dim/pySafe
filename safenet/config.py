GLOBAL_DEFAULT_TIMEOUT = 10        # default seconds to wait for ffi calls.  Overridden by classes calling bind_method
GLOBAL_DEFAULT_ENCODING = 'utf-8'  # affects how strings are passed to ffi
GLOBAL_BINPATH = None              # put it in if you want to hand code a path to the binaries.  Will be autodiscovered
                                   #   by localization if it's in the repo.