
# coding: utf-8

# ### this is the Authenticator-Class containing all important methods that an authenticator needs to work

# In[1]:

from cffi import FFI
ffi = FFI()


# In[2]:

import SafeDataTypes_Concept as dataTypes


# some fake definitions for testing

# In[3]:

ffi.cdef('''
typedef int int32_t;
typedef struct {
    int32_t error_code;
    char* description;
} FfiResult;
typedef struct {
    int32_t error_code;
    FfiResult* result;
} RandomStruct;
typedef struct {
    RandomStruct* randomData;
    FfiResult* result;
} RandomOtherStruct;
typedef struct {
    void* core_tx;
    void* _core_joiner;
} Authenticator;
''')


# In[4]:

ffi.cdef('''
void login(char* account_locator, char* account_password, void* user_data, void(*)(void*), void(*)(void*, FfiResult*, Authenticator*));
void create_acc(char* account_locator, char* account_password, char* invitation, void* user_data, void(*)(void*), void(*)(void*, FfiResult*, Authenticator*));
''')


# In[5]:

class Auth:
    def __init__(self,
            name='noAuth',
            version='0.0.0',
            vendor='rid',
            libLocation= '../compiled_binaries/libsafe_authenticator.so',
            addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.lib = ffi.dlopen(libLocation)
        
    def defaultFfiResult(self,result, actionDescription):
    
        if result.error_code == 0:
            print('successfully ' + actionDescription)
        else:
            print('an Error occured - Error Code: ' + str(result.error_code))
            print('Error description: ' + str(dataTypes.SafeUtils.getCString(result.description)))
            
    def toByteIfString(self,parameter,encoding):
        if type(parameter) == str:
            return parameter.encode()
        else:
            return parameter


# #### the login function needs to know at least the two first arguments to work

# In[6]:

def login(self,account_locator,account_password,user_data=None,disconnect_notifier_cb=None,cb=None,encoding='utf-8'):
    ''' string/bytes, string/bytes, [any], [function], [function], [encoding]
        char* account_locator, char* account_password, void* user_data
        
        > return values of the callback functions:
        disconnect_notifier_cb - void* user_data
        cb - void* user_data, FfiResult* result, Authenticator* authenticator
    ''' 
    
    @ffi.callback("void(void*)")
    def o_disconnect_notifier_cb(user_data):
        
        if disconnect_notifier_cb:
            disconnect_notifier_cb(user_data)
        else:
            pass
    
    @ffi.callback("void(void*,FfiResult*,Authenticator*)")
    def o_cb(user_data,result,authenticator):
        
        if cb:
            cb(user_data,result,authenticator)
        else:
            self.defaultFfiResult(result,'logged into the SAFE Network')
    
    account_locator = ffi.new('char[]',self.toByteIfString(account_locator,encoding))
    password = ffi.new('char[]',self.toByteIfString(account_password,encoding))
    if user_data:
        userData = ffi.new_handle(user_data)
    else:
        userData = ffi.NULL
    
    self.lib.login(account_locator,password,userData,o_disconnect_notifier_cb,o_cb)
    
    
Auth.login = login
del(login)


# parameters for account creation
# 
# account_locator | account_password | invitation | user_data
# --- | --- | --- | ---
# important; your first login string | important; your second login string | random string in mock routing | no clue
# 

# In[7]:

def create_acc(self,account_locator,account_password,invitation,user_data=None,disconnect_notifier_cb=None,cb=None,encoding='utf-8'):
    ''' string/bytes, string/bytes, string/bytes, [any], [function], [function], [encoding]
        char* account_locator, char* account_password, char* invitation, void* user_data
        
        > return values of the callback functions:
        disconnect_notifier_cb - void* user_data
        cb - void* user_data, FfiResult* result, Authenticator* authenticator
    ''' 
    
    @ffi.callback("void(void*)")
    def o_disconnect_notifier_cb(user_data):
        
        if disconnect_notifier_cb:
            disconnect_notifier_cb(user_data)
        else:
            pass
    
    
    @ffi.callback("void(void*,FfiResult*,Authenticator*)")
    def o_cb(user_data,result,authenticator):
        
        if cb:
            cb(user_data,result,authenticator)
        else:
            self.defaultFfiResult(result,'created new SAFE Network Account')
    
    account_locator = ffi.new('char[]',self.toByteIfString(account_locator,encoding))
    password = ffi.new('char[]',self.toByteIfString(account_password,encoding))
    invitation = ffi.new('char[]',self.toByteIfString(invitation,encoding))
    if user_data:
        userData = ffi.new_handle(user_data)
    else:
        userData = ffi.NULL
    
    self.lib.create_acc(account_locator,password,invitation,userData,o_disconnect_notifier_cb,o_cb)
    
    
Auth.create_acc = create_acc
del(create_acc)


# In[ ]:




# au=Auth()

# au.create_acc('test','test2','noInvite')

# au.login('test','test2')

# In[ ]:



