## For development use, utilities to instrospect ffi functions
from inspect import signature

def stump_code_for_overriding_ffi_calls(obj, f=None):
    if f is not None: return stump_code_for_overriding_ffi_call(obj,f)
    result=[]
    for f,timeout in obj.ffi_auth_methods.items():
        code=stump_code_for_overriding_ffi_call(obj,f)
        result.append(code)
        result.append('')
    for f,timeout in obj.ffi_app_methods.items():
        code=stump_code_for_overriding_ffi_call(obj,f)
        result.append(code)
        result.append('')
    return '\n'.join(result)

def stump_code_for_overriding_ffi_call(obj,f):
    code = f'Could not introspect func: {f} in {obj.__name__} as the underyling is not bound'
    ffif = f'_{f}'
    if hasattr(obj,ffif):
        func=getattr(obj,ffif)
        ffif_docstr=func.__doc__.split('\n')
        doc=['    """']
        doc.append(f'    {ffif_docstr[1]}')
        doc.append(f'    {ffif_docstr[2]}')
        doc.append(f'    """"')
        doc="\n".join(doc)
        sig=signature(func)
        definition = f'def {f}{str(sig)}:'
        call = f'    self.{ffif}({",".join(signature(func).parameters)})'
        code='\n'.join([definition,doc,call])
    return code

def generate_used_bindings_variable(obj):
    app_listing='","'.join([item for item in obj.ffi_app_methods.keys()])
    auth_listing='","'.join([item for item in obj.ffi_auth_methods.keys()])
    string1=f'ffi_auth_methods = ["{auth_listing}"]'
    string2=f'ffi_auth_methods = ["{app_listing}"]'
    return '\n'.join([string1,string2])


if __name__ == '__main__':
    #Get authenticator methods
    import safenet.authenticator as auth
    A=auth.Authenticator()
    print(stump_code_for_overriding_ffi_calls(A))

    # Generate _IDATA
    #import safenet.app as app
    #A=app.App()
    #print(generate_used_bindings_variable(A))

    # Generate _MDATA
    #import safenet.mutabledata as app
    #A=app.MutableData()
    #print(generate_used_bindings_variable(A))