
# coding: utf-8

# ### this is the Authenticator-Class containing all important methods that an authenticator needs to work

# In[1]:


from cffi import FFI
ffi = FFI()


# In[2]:


import SafeDataTypes_Concept as dataTypes


# In[3]:


ffi.cdef(dataTypes.SafeUtils().datattypes)


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
            libLocation='../../safe_client_libs/target/debug/libsafe_authenticator.so',
            addr='http://localhost'):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.url = addr
        self.lib = ffi.dlopen(libLocation)


# #### the login function needs to know at least the two first arguments to work

# In[16]:


def login(self,account_locator,account_password,user_data=b''):
    ''' char* account_locator, char* account_password, void* user_data ''' 
    
    @ffi.callback("void(void*)")
    def o_disconnect_notifier_cb(user_data):
        pass
    
    
    @ffi.callback("void(void*,FfiResult*,Authenticator*)")
    def o_cb(user_data,result,authenticaor):
        
        if result.error_code == 0:
            print('successfully logged into the SAFE Network')
        else:
            print('an Error occured - Error Code: ' + str(result.error_code))
            print('Error description: ' + str(dataTypes.SafeUtils.getCString(result.description)))
    
    account_locator = dataTypes.cstr(account_locator)
    password = dataTypes.cstr(account_password)
    userData = dataTypes.cstr(user_data)
    
    self.lib.login(account_locator.entity,password.entity,userData.entity,o_disconnect_notifier_cb,o_cb)
    
    
Auth.login = login
del(login)


# parameters for account creation
# 
# account_locator | account_password | invitation | user_data
# --- | --- | --- | ---
# important; your first login string | important; your second login string | random string in mock routing | no clue
# 

# In[12]:


def create_acc(self,account_locator,account_password,invitation,user_data=b''):
    ''' char* account_locator, char* account_password, char* invitation, void* user_data ''' 
    
    @ffi.callback("void(void*)")
    def o_disconnect_notifier_cb(user_data):
        pass
    
    
    @ffi.callback("void(void*,FfiResult*,Authenticator*)")
    def o_cb(user_data,result,authenticator):
        
        if result.error_code == 0:
            print('successfully created new SAFE Network Account')
        else:
            print('an Error occured - Error Code: ' + str(result.error_code))
            print('Error description: ' + str(dataTypes.SafeUtils.getCString(result.description)))
    
    account_locator = dataTypes.cstr(account_locator)
    password = dataTypes.cstr(account_password)
    invitation = dataTypes.cstr(invitation)
    userData = dataTypes.cstr(user_data)
    
    self.lib.create_acc(account_locator.entity,password.entity,invitation.entity,userData.entity,o_disconnect_notifier_cb,o_cb)
    
    
Auth.create_acc = create_acc
del(create_acc)


# newAuth = Auth()

# newAuth.create_acc(b'hallihalloetest',b'hallihalloetest',b'hallihalloetest')

# newAuth.create_acc(b'hallihalloetest',b'hallihalloetest',b'hallihalloetest')

# newAuth.login(b'hallihalloetest',b'hallihalloetest')
