from shared_lib import *
from ida_kernwin import *
import os.path

ida_handler = c_ida_handler()

# Patoke @note: this is mostly used for ShimTo functions and stuff that was never populated in the .map file
def parse_symbols_file(symbols_file):
    global ida_handler

    line = "str" # don't skip first element
    while line:
        if user_cancelled():
            break
        
        line = symbols_file.readline().replace("\n", "")

        if form.show_waiting_window.checked:
            replace_wait_box(f'''
Parsing symbols...
Processing symbols file
Global variables renamed: {ida_handler.global_variables}
Mangled functions renamed: {ida_handler.mangled_functions}
Unmangled functions renamed: {ida_handler.unmangled_functions}
            ''')

        # shims are populated in the symbols file
        if "ShimTo" in line:
            line = symbols_file.readline() # skip to next line

        if line == '':
            continue

        # assumes the following format:
        #   "0000000000000020 T __start__Zinit"
        regex_symbol = re.search("(.*?[0-9a-z]) ([tT]) (.*)", line)
        address = int(regex_symbol.group(1), 16)
        symbol_name = regex_symbol.group(3)

        ida_handler.set_current_address(address)
        
        # keep raw symbol name
        ida_handler.add_to_shim_map(symbol_name)

        if not is_mangled_name(line):
            ida_handler.add_unmangled_function(mangle_name(symbol_name))
        else:
            ida_handler.add_mangled_function(symbol_name)

def parse_map_file(map_format: c_map_format, map_file):
    global ida_handler

    current_section = str()
    line = map_file.readline() # skip second line (first line is the map format)
    while line:
        if user_cancelled():
            break
            
        line = map_file.readline().replace("\n", "")
        map_format.set_curr_line(line)
        if form.show_waiting_window.checked:
            replace_wait_box(f'''
Parsing symbols...
Processing map file
Global variables renamed: {ida_handler.global_variables}
Mangled functions renamed: {ida_handler.mangled_functions}
Unmangled functions renamed: {ida_handler.unmangled_functions}
            ''')

        # check if has address
        address = map_format.get_address()
        if address == None: continue
        ida_handler.set_current_address(address)
        
        out_section = map_format.get_out_section()
        if out_section == '': continue

        if out_section[0] == '.':
            current_section = out_section
            continue

        if out_section[0] != ' ': continue

        in_section = map_format.get_in_section()
        if in_section == '': continue
        
        # in_section will always contain the mangled name for the current symbol
        # it also includes global initializers
        # this is the case when the section also contains an extra dot
        # eg, .text._GLOBAL_filename.cpp
        if f"{current_section}." in in_section:
            ida_handler.add_mangled_function(in_section[len(current_section) + 1:])
            continue

        if in_section[0] != ' ': continue

        file_location = map_format.get_file_location()
        if file_location == '' or file_location[0] != ' ': continue

        symbol_name = map_format.get_symbol_name()
        # we don't care about shims in maps, they're not populated
        if "ShimTo" in symbol_name:
            continue
        
        # we have a mangled variant for this symbol, add it
        # Patoke @todo: 
        #   some symbols will be slightly ill formed by not including namespace tags for each namespace
        #   maybe add fix for this?
        symbol_for_shim = ida_handler.get_curr_shim()

        if symbol_for_shim:
            has_mangled_name = is_mangled_name(symbol_name)
            has_mangled_mapping = is_mangled_name(symbol_for_shim)

            if has_mangled_name or has_mangled_mapping:
                symbol_name = symbol_name if has_mangled_name else symbol_for_shim
                ida_handler.add_mangled_function(symbol_name)
                continue

        # symbol is global variable
        if "bss" in current_section or ".data" in current_section:
            ida_handler.add_global_variable(symbol_name)
            continue
        
        ida_handler.add_unmangled_function(mangle_name(symbol_name))

# UI
class input_form(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:path_map_file}
BUTTON YES* Search
GCC Load Map

<.map file                  :{path_map_file}>
<.symbols file (optional)   :{path_symbols_file}>
<##Options##Show waiting window (slower, verbose):{show_waiting_window}>
<Show debug output (no performance impact):{debug_output}>
<Apply guessed type info:{apply_types}>{check_group1}>
""", {
        'path_map_file': Form.FileInput(value = "*.map", open=True, swidth=40),
        'path_symbols_file': Form.FileInput(value = "*.symbols", open=True, swidth=40),
        'check_group1': Form.ChkGroupControl(("show_waiting_window", "debug_output", "apply_types"))
    })

def form_main(form: input_form):
    global ida_handler

    form.show_waiting_window.checked = False
    form.debug_output.checked = True
    form.apply_types.checked = True

    ok = form.Execute()
    if ok != 1: # user didn't press "Search"
        return
    
    ida_handler.set_apply_type_info(form.apply_types.checked)

    map_file_exists = os.path.isfile(form.path_map_file.value)
    symbols_file_exists = os.path.isfile(form.path_symbols_file.value)

    if not map_file_exists:
        print("[ERROR] .map file is necessary for continuing")
        return

    try:
        if form.show_waiting_window.checked:
            show_wait_box("Parsing symbols...")

        # we parse the symbols file first as this one has shim funcs which we have to map
        # this one is optional
        if symbols_file_exists:
            symbols_file = open(form.path_symbols_file.value, 'r')
            parse_symbols_file(symbols_file)

        map_file = open(form.path_map_file.value, 'r')
        map_handler = c_map_format(map_file.readline())

        if form.debug_output.checked:
            map_handler.debug_print()

        parse_map_file(map_handler, map_file)
    finally:
        if form.show_waiting_window.checked:
            hide_wait_box()
        
        if form.debug_output.checked:
            ida_handler.debug_print()

# create form
form = input_form()
form.Compile() # compile for controls
form_main(form)
form.Free()