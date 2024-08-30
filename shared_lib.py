import re, idc, idaapi, ida_name

# base helpers
def get_start_and_len(in_: str, curr_element: str, next_element: str = ""):
    start = in_.find(curr_element)
    # only assign size if we have a next_element
    if not next_element:
        return start
    size = in_.find(next_element) - start - 1
    return (start, size)

def get_hex_as_int(in_: str):
    try:
        return int(in_, 16)
    except ValueError:
        return None
    
# Patoke @todo: maybe improve this check?
def is_mangled_name(in_: str):
    is_section = in_[0] == "."
    return in_[0:2] == "_Z" or (is_section and "._Z" in in_)

# map utils
# Patoke @todo: add support for base addresses
class c_map_format():
    # assumes the following format:
    #   "Address  Size     Align Out     In      File    Symbol"
    def __init__(self, in_map_format: str):
        self.curr_line = ""

        # read address sizes
        self.address_start, self.address_len = get_start_and_len(in_map_format, "Address", "Size") # symbol address
        self.size_start, self.size_len = get_start_and_len(in_map_format, "Size", "Align") # unused, symbol compiled size in bytes
        self.align_start, self.align_len = get_start_and_len(in_map_format, "Align", "Out") # unused, memory alignment for symbol

        # read text starts
        self.out_start = get_start_and_len(in_map_format, "Out") # where current symbol list will be exported to
        self.in_start = get_start_and_len(in_map_format, "In") # place in the out section this symbol is placed
        self.file_start = get_start_and_len(in_map_format, "File") # unused, file where this symbol was defined
        self.symbol_start = get_start_and_len(in_map_format, "Symbol") # symbol name

    # utils
    def set_curr_line(self, line: str):
        self.curr_line = line

    def debug_print(self):
        print("map format:")
        print("\taddress    : ", (self.address_start, self.address_len))
        print("\tsize       : ", (self.size_start, self.size_len))
        print("\talign      : ", (self.align_start, self.align_len))

        print("\tout idx    : ", self.out_start)
        print("\tin idx     : ", self.in_start)
        print("\tfile idx   : ", self.file_start)
        print("\tsymbol idx : ", self.symbol_start)

    # getters
    def get_address(self):
        return get_hex_as_int(self.curr_line[self.address_start:self.address_start + self.address_len])

    def get_out_section(self):
        return self.curr_line[self.out_start:]
    
    def get_in_section(self):
        return self.curr_line[self.in_start:]
    
    def get_file_location(self):
        return self.curr_line[self.file_start:]
    
    def get_symbol_name(self):
        return self.curr_line[self.symbol_start:]

# ida helpers
set_name_flags = ida_name.SN_NOCHECK | ida_name.SN_FORCE

class c_ida_handler():
    def __init__(self):
        self.curr_address = 0
        self.shim_mappings = {}

        # debug info
        self.global_variables    = 0 # global variables we wrote
        self.mangled_functions   = 0 # functions that were pre-mangled by the compiler
        self.unmangled_functions = 0 # functions which we had to mangle ourselves

        self.apply_type_info = False

    # utils
    def debug_print(self):
        print("\tglobal symbols renamed      : ", self.global_variables)
        print("\tmangled functions renamed   : ", self.mangled_functions)
        print("\tunmangled functions renamed : ", self.unmangled_functions)

        # reset counters for next call
        self.global_variables    = 0
        self.mangled_functions   = 0
        self.unmangled_functions = 0

    # setters
    def set_apply_type_info(self, value: bool):
        self.apply_type_info = value

    def set_current_address(self, address: int):
        self.curr_address = address

    def set_type_info(self, symbol_name: str, arguments: str):
        # user told us not to apply type info, return
        if not self.apply_type_info:
            return

        # symbol has no arguments, don't proceed
        if not arguments or arguments == "":
            return
        
        type_info = idc.get_tinfo(self.curr_address)
        if not type_info:
            return
        
        tif = idaapi.tinfo_t()
        tif.deserialize(None, type_info[0], type_info[1], None)

        # eg, void _Z3fooi(int);
        type_declaration = f"{tif.get_rettype()} {symbol_name}({arguments});"

        idc.apply_type(self.curr_address, idc.parse_decl(type_declaration, 0), idc.TINFO_GUESSED)

    # getters
    def get_curr_shim(self):
        out_sym_name = str()
        try:
            out_sym_name = self.shim_mappings[self.curr_address]
        # ignore KeyError since we know not all addresses contain a shim mapping
        except KeyError:
            pass
        return out_sym_name

    # adders
    def add_to_shim_map(self, symbol_name: str):
        self.shim_mappings[self.curr_address] = symbol_name

    # globally defined variable
    def add_global_variable(self, symbol_name: str):
        idc.set_name(self.curr_address, symbol_name, set_name_flags)
        self.global_variables += 1

    # Patoke @todo: unmangle arguments and pass them properly
    # pre-mangled function
    def add_mangled_function(self, symbol_name, symbol_arguments: str = ""):
        if type(symbol_name) is tuple:
            symbol_arguments = symbol_name[1]
            symbol_name = symbol_name[0]
        idc.set_name(self.curr_address, symbol_name, set_name_flags)
        self.set_type_info(symbol_name, symbol_arguments)

        self.mangled_functions += 1

    # mangled by our script
    def add_unmangled_function(self, symbol_name, symbol_arguments: str = ""):
        if type(symbol_name) is tuple:
            symbol_arguments = symbol_name[1]
            symbol_name = symbol_name[0]
        idc.set_name(self.curr_address, symbol_name, set_name_flags)
        self.set_type_info(symbol_name, symbol_arguments)

        self.unmangled_functions += 1

# name mangling library
# Patoke @note: only kept the significant literal types
literal_types = {
    "void": "v",
    "wchar_t": "w",
    "bool": "b",
    "char": "c",
    "signed char": "a",
    "unsigned char": "h",
    "short": "s",
    "unsigned short": "t",
    "int": "i",
    "unsigned int": "j",
    "long": "l",
    "unsigned long": "m",
    "long long": "x",
    "unsigned long long": "y",
    "float": "f",
    "double": "d",
    "long double": "e"
}

# returns tuple
# 0: mangled symbol name
# 1: unmangled arguments
def mangle_name(symbol_name: str):
    regex_arguments = re.search("\((.*?)\)", symbol_name)
    # if we have no arguments, don't assign arguments to void, as we actually don't have this data
    if regex_arguments == None:
        return (f"_Z{len(symbol_name)}{symbol_name}", "")

    # Patoke @note:
    #   _Z indicates the start of the mangled name
    #   this is followed by the length of the symbol name
    #   everything afterwards is an argument
    symbol_name = symbol_name[:regex_arguments.span()[0]] # remove arguments from symbol
    symbol_name = symbol_name.replace("::", ":") # ease parsing of namespaces

    # mangle namespaces
    namespaces = symbol_name.split(":")

    mangled_namespaces = ""
    for namespace in namespaces[:-1]:
        if namespace == "std": # exception to the namespace format is the std namespace
            mangled_namespaces += "St"
            continue

        mangled_namespaces += f"{len(namespace)}{namespace}"

    symbol_name = namespaces[-1:][0] # keep only the function name

    # assume complete destructor, since we don't have compiletime hints
    ctor_dtor_qualifier = ""
    if '~' in symbol_name:
        ctor_dtor_qualifier = "D0"

    # write mangled name
    if ctor_dtor_qualifier != "":
        # a ctor/dtor qualifier populates the symbol name on its own
        symbol_name = f"_ZN{mangled_namespaces}{ctor_dtor_qualifier}E"
    elif mangled_namespaces and "St" not in mangled_namespaces:
        symbol_name = f"_ZN{mangled_namespaces}{len(symbol_name)}{symbol_name}E"
    else:
        symbol_name = f"_Z{len(symbol_name)}{symbol_name}"

    # mangle arguments
    arguments = regex_arguments.group(1).split(", ")

    # Patoke @note:
    #   pointer arguments are prefixed P
    #   reference arguments are prefixed R
    #   constant arguments are prefixed K
    #   order of types for arguments is reversed
    # Patoke @todo:
    #   add support for c style variadic arguments? "(...)"
    #   for now they do show, but they're considered a namespace
    mangled_arguments = ""
    for argument in arguments:
        mangled_argument = ""
        if argument == '':
            continue

        match_point = re.findall("(.*?)([\*\&])", argument)

        # if this argument is not a pointer
        if not match_point:
            is_custom_type = argument not in literal_types

            if not is_custom_type:
                mangled_argument += literal_types[argument]
            else:
                mangled_argument += f"N{len(argument)}{argument}E"

            mangled_arguments += mangled_argument
            continue

        mangled_argument = ""
        for match in reversed(match_point):
            type_name = match[0]

            is_pointer = match[1] == '*'
            is_const = "const" in type_name
            
            type_name = type_name.replace(" const", "") # remove const keyword

            is_custom_type = type_name not in literal_types

            # if this argument is a pointer, add P
            # if this argument is not a pointer, it is a reference, add R
            mangled_argument += "P" if is_pointer else "R"

            if is_const: mangled_argument += "K"
            
            if type_name == '': continue

            if not is_custom_type:
                mangled_argument += literal_types[type_name]
            else:
                mangled_argument += f"N{len(type_name)}{type_name}E"

        mangled_arguments += mangled_argument

    # if we have arguments: add them
    # if we don't have arguments: set the argument type as void
    symbol_name += mangled_arguments if mangled_arguments != '' else 'v'

    return (symbol_name, regex_arguments.group(1) if regex_arguments else "")