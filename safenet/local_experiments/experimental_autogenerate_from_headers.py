from collections import defaultdict
from pathlib import Path
mod_path = Path(__file__).parent
INDATA=(mod_path / '../extracted_headers/safe_authenticator_datatype_declarations').resolve()
INFUNCS=(mod_path / '../extracted_headers/safe_authenticator_function_declarations').resolve()
OUTFILE='dataclass_template.py'

#   Proof of concept auto-templater
#   Super shitty code, wrote in a few hours and with very little sleep :P
#
#   .. Takes the headers, parses them to extract the relevant entities
#   .. cross checks the function signatures against the structs
#   .. discarding callbacks and userdata, funcs that only have a struct in their params
#   .. should be methods of that dataclass.
#   .. code also generates skeleton python data classes with appropriate submethods


#  PARSING FUNCTIONS ############################

def __get_file_contents(fname):
    with open(fname, 'r') as f:
        return f.read()

def __split_to_lines(data):
    return [line.strip('\r\n') for line in data.splitlines() if line]

def __getlines(fname):
    return __split_to_lines(__get_file_contents(fname))

def space_line(line):
    return ' '.join([item.strip(',') for item in line.split() if item!=''])

def yield_data_entities(lines):
    accumulator=[]
    in_struct_def = False
    for line in lines:
        accumulator.append(line.strip(';'))
        if '{' in line:
            in_struct_def=True
        elif '}' in line:
            yield ' '.join(accumulator)
            accumulator=[]
            in_struct_def=False
        elif in_struct_def is False:
            yield accumulator[0]
            accumulator = []

def fix_spacing(lines):
    return (space_line(l) for l in lines)


def group_list(l,group_size=2):
    '''
    [A,B,C,D,E] -> [(A,B), (B,C)..
    '''
    # sanity check .. the list should be in groups of two should never fail if code is correct
    assert len(l)%2==0
    # WTF: (returns the list as a list of tuples, see docstr for effect.)
    return list(zip(*(iter(l),) * group_size))

def extract_data_entities(lines):
    structs={}
    enums={}
    defs={}
    for line in lines:
        members=[]
        l=line.split()
        assigned_name=l[-1]
        if '{' not in l:
            c_keyword=' '.join(l[1:-1])
            defs[assigned_name]=c_keyword
        else:
            c_keyword=l[1]
            members=[item for item in l[2:-1] if item not in '{}']
            if c_keyword=='enum':
                enums[assigned_name]={idx:item for idx,item in enumerate(members)}
            elif c_keyword=='struct':
                members=group_list(members)
                structs[assigned_name]={n:t for (t,n) in members}
    return defs,enums,structs

def split_cbs(cb_substring):
    cbls=[]
    accumulator=[]
    funcname,sig='',''
    for item in cb_substring.split('('):
        item=item.strip(')')
        # additional callbacks will still have the ')' intact
        accumulator.append(item)
        if ')' in item:  #  Another callback
            funcname = accumulator[0]
            sig = [item.strip(')') for item in accumulator[1].split(',')[:-1]]
            cbls.append((funcname,sig))
            accumulator=[]
    cbls.append((accumulator[0],[item.strip() for item in accumulator[1].split(',')]))
    return cbls

def split_sig(funcsig):
    params=[]
    cbs=[]
    fs=funcsig.split('(',1)
    params=fs[0]
    if len(fs)>1:
        cbs=fs[1]
        params = params.split(',')[:-1]  # last is always the void preface of cb1
    else:
        params=params.split(',')

    if len(cbs)>0:
        cbs=split_cbs(cbs)
    params=[item.strip() for item in params]
    # cbs will be [] if there are no callbacks
    return params,cbs

def prep_cbs(cbs):
    result={}
    for cb in cbs:
        #print(cb)
        cbname=cb[0]
        cbparams={p.split()[1]:p.split()[0] for p in cb[1]}
        result[cbname]=cbparams
    return result

def extract_functions(functionlines):
    funcs={}
    for line in functionlines:
        l=line[:-1].split('(',1)
        funcname,rawsig=l[0].split()[-1],l[1]
        params,cbs=split_sig(rawsig)
        #print(params, rawsig)
        # at this point:
        # Params is list : [param1,param2, ..e.g 'App* app']
        # cbs is list : [(cb_name, [cb param list as above])]
        paramdict={p.split()[1]:p.split()[0] for p in params}
        cbs_dict=prep_cbs(cbs)
        #cbs_dict = {name:{name:type}}
        funcs[funcname]=(paramdict,cbs_dict, rawsig)
        #print(params,cbs)
    return funcs

def parse_data_header():
    data_header=__getlines(INDATA)
    data_entities_raw=yield_data_entities(data_header)
    data_entities=fix_spacing(data_entities_raw)
    defs,enums,structs=extract_data_entities(data_entities)
    #defs ={name : type}
    #enums = {name : {0:item1,1:item2}}
    #structs = {name : {name1:type1, etc}
    return (defs,enums,structs)

def parse_functions():
    func_header=__getlines(INFUNCS)
    func_entities_raw=yield_data_entities(func_header)
    funcs=extract_functions(func_entities_raw)
    return funcs

##  Analysis Functions #########################################

def entity_graph(defs,enums,structs,funcs, full_structure=False):
    '''
    make a graph of all named entities
    '''
    #name: id, type
    entities={}
    #idstart idend
    edges=[]
    for name,typ in defs.items():
        reftyp=None
        refname=None
        name=name.strip('*')
        typ=typ.strip('*')
        if typ not in entities:
            pass
            #reftyp=len(entities)
            #entities[typ]=(reftyp,'base')
        else:
            reftyp=entities[typ][0]
        if name not in entities and 'int' not in name:
            refname=len(entities)
            entities[name]=(refname,'safe_base')
        else:
            if 'int' not in name:
                refname=entities[name][0]
        if reftyp is not None and refname is not None:
            edges.append((refname,reftyp,'subtype'))

    for name,param_dict in structs.items():
        typs=[item.strip('*') for item in param_dict.values()]
        if name not in entities:
            refname=len(entities)
            entities[name]=(refname,'data_structure')
        else:
            refname=entities[name][0]
        for typ in typs:
            if typ not in entities and ('void' not in typ and 'int' not in typ and 'char' not in typ) or full_structure:
                reftyp=len(entities)
                entities[typ]=(reftyp,'data_structure')
            else:
                if ('void' not in typ and 'int' not in typ and 'char' not in typ) or full_structure:
                    reftyp = entities[typ][0]
            if reftyp is not None and refname is not None:
                edges.append((refname,reftyp,"contains"))

    for name,data in funcs.items():
        typs = [item.strip('*') for item in data[0].values()]
        cbtyps=set()
        for callback_dict_paramdict in data[1].values():
            cbtyps|={item.strip('*') for item in callback_dict_paramdict.values()}
        if name not in entities:
            refname=len(entities)
            entities[name]=(refname,'function')
        else:
            refname=entities[name][0]
        for typ in typs:
            if typ not in entities and ('void' not in typ and 'int' not in typ and 'char' not in typ) or full_structure:
                reftyp=len(entities)
                entities[typ]=(reftyp,'data_structure')
            else:
                if ('void' not in typ and 'int' not in typ and 'char' not in typ) or full_structure:
                    reftyp = entities[typ][0]
            if reftyp is not None and refname is not None:
                edges.append((reftyp,refname,"parameter"))
        for cbtyp in cbtyps:
            if cbtyp not in entities and ('void' not in typ and 'int' not in typ and 'char' not in typ) or full_structure:
                reftyp=len(entities)
                entities[cbtyp]=(reftyp,'safe_base')
            else:
                if ('void' not in typ and 'int' not in typ and 'char' not in typ) or full_structure:
                    reftyp = entities[cbtyp][0]
            if reftyp is not None and refname is not None:
                edges.append((refname, reftyp, "return_value"))


    return entities, edges

##  Text output Functions #########################################


def ent_dict_to_pajek(ent_dict):
    lines=[f'{v[0]+1} {k} "{v[1]}"' for k,v in ent_dict.items()]
    return [f'*Vertices {len(lines)}']+lines+['']

def ent_dict_to_gephi(ent_dict):
    lines=[f'{v[0]+1};{k};"{v[1]}"' for k,v in ent_dict.items()]
    return [f'Id;Label;Kind'] + lines

def edges_to_pajek(edges):
    edges=[f'{item[0]+1} {item[1]+1}' for item in edges]
    return [f'*Arcs {len(edges)}']+edges+['']

def edges_to_gephi(edges):
    edges=[f'{item[0]+1};{item[1]+1};Directed;{item[2]}' for item in edges]
    return [f'Source;Target;Type;Kind']+edges

def ent_dict_to_cyto(nodes):
    lines = [f'{k};{v[1]}' for k, v in nodes.items()]
    return [f'Node;NodeType']+lines

def edges_to_cyto(nodes,edges):
    node_lookup = {v[0]: f'{k}' for k, v in nodes.items()}
    lines = [f'{node_lookup[k[0]]};{node_lookup[k[1]]};{k[2]}' for k in edges]
    return [f'Source;Target;Type'] + lines

def write_pajek_graph(fname_noext, ent_dict, edges):
    nodes=ent_dict_to_pajek(ent_dict)
    edges=edges_to_pajek(edges)
    fname=fname_noext+'.net'
    with open(fname,'w') as f:
        f.write('\n'.join(nodes+edges))

def write_gephi_graph(fname_noext, ent_dict, edges):
    nodes=ent_dict_to_gephi(ent_dict)
    edges=edges_to_gephi(edges)
    fedge=fname_noext+'_edge.csv'
    fnode=fname_noext+'_node.csv'
    with open(fnode,'w') as f:
        f.write('\n'.join(nodes))
    with open(fedge, 'w') as f:
        f.write('\n'.join(edges))

def write_cyto_graph(fname_noext, ent_dict, edges):
    nodes=ent_dict_to_cyto(ent_dict)
    edges=edges_to_cyto(ent_dict,edges)
    fedge=fname_noext+'_cedge.csv'
    fnode=fname_noext+'_cnode.csv'
    with open(fnode,'w') as f:
        f.write('\n'.join(nodes))
    with open(fedge, 'w') as f:
        f.write('\n'.join(edges))

##  Main Functions #########################################

def get_elements():
    '''
    Parse and assemble the structural elements of the header
    '''
    defs,enums,structs=parse_data_header()
    #defs,enums,structs=None,None,None
    funcs=parse_functions()
    return defs,enums,structs,funcs

def write_graph_file(fname_noext='test_out', t='cyto'):
    '''
    Write the function structure of the header to various network file formats
    Pass the filestem with no extension, as the various files are generated in the corresponding function
    t-> cyto = 'cytoscape nodeinfo and edge formats', pajek='pajek format (.net)', gephi = 'gephi format'
    '''
    defs,enums,structs,funcs=get_elements()
    ent_dict, edges = entity_graph(defs, enums, structs, funcs)
    if t=='cyto':
        write_cyto_graph(fname_noext,ent_dict,edges)
    elif t=='pajek':
        write_pajek_graph(fname_noext,ent_dict,edges)
    elif t=='gephi':
        write_gephi_graph(fname_noext,ent_dict,edges)
    else:
        print('Unknown graph format',t)

def cb_params_to_python_cffi_def_string(cb_paramdict):
    return (f'@self.ffi.callback("void({",".join([item for item in cb_paramdict.values()])})")')

def cb_params_to_python_def_string(cbname, cb_paramdict, name):
    return (f'def _{name}_{cbname.strip("*")} ({cb_params_to_inner_def(cb_paramdict)}):')

def cb_params_to_inner_def(cb_paramdict):
    return ",".join([item for item in cb_paramdict.keys()])

def name_to_python_def_string(name,data,libname):
    call_params = [item.strip('*') for item in data[0].keys()]
    for cbname,callback_dict_paramdict in data[1].items():
        call_params.append(f'{cbname.strip("*")} = None')
    call_params.append(f'safenetLib = {libname}')
    return f'def _{name}({",".join(call_params)}):'


def generate_cb_templates(fname='exp_cb_templates.py', libname='self.lib.safe_authenticator'):
    defs, enums, structs, funcs = get_elements()
    unique_cbs={}
    for name, data in funcs.items():
        call_params = [item.strip('*') for item in data[0].values()]
        #print(data[2])
        for cbname,callback_dict_paramdict in data[1].items():
            #print(name, cbname, callback_dict_paramdict.items())
            print (f'parsing signature for function "{name}"')
            print('Python code:\n-------- ')
            print(def_to_python_cffi_binding(name,data,libname))
            #exit()
THREADER_LINE='@safeUtils.safeThread(timeout=timeout,queue=self.queue)'

def complete_callback_set(data,name):
    result = []
    for cbname, cb_paramdict in data[1].items():
        cbname=cbname.strip('*')
        result.append(f'    {cb_params_to_python_cffi_def_string(cb_paramdict)}')
        result.append(f'    {cb_params_to_python_def_string(cbname,cb_paramdict,name)}')
        if 'result' in cb_paramdict.keys():
            result.append(f'        safeUtils.checkResult(result,self.ffi)')
        result.append(f'        self.queue.put("gotResult")\n'
                      f'        if {cbname}:\n            {cbname}({cb_params_to_inner_def(cb_paramdict)})')
        result.append('')
    return result

def def_to_python_cffi_binding(name,data,libname):
    result=[THREADER_LINE]
    result.append(name_to_python_def_string(name,data,libname))
    result.append('\n..awaiting docstring generator..\n')
    result.extend(complete_callback_set(data, name))
    result.append(f'    safenetLib.{name}('
                  f'{",".join([item.strip("*") for item in data[0].keys()]+[cbname.strip("*") for cbname,_ in data[1].items()])})')
    result.append(f'self._{name} = _{name}')
    return '\n'.join(result)

if __name__=='__main__':
    # Write a graph file of our choice
    #write_graph_file('test_out','cyto')
    generate_cb_templates()