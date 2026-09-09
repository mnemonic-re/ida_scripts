# IDA Python Plugin: Dump All Info (Cleaned & Refactored for IDA 9.3)
# Features: Basic Info, Imports, Exports, Names, Functions, Strings.

import os
import hashlib
import idaapi
import idautils
import ida_kernwin
import ida_nalt
import ida_ida
import ida_funcs
import ida_name
import ida_bytes
import ida_entry

# Optional limits (set to None for unlimited)
MAX_STRINGS = None
MAX_NAMES   = None
MAX_FUNCS   = None
MAX_IMPORTS = None
MAX_EXPORTS = None

def _safe_str(s):
    try:
        return s if isinstance(s, str) else str(s)
    except Exception:
        return "<unprintable>"

def _sha256_file(path, chunk_size=1024 * 1024):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk_size)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        return f"<sha256_failed: {e}>"

def _write_line(out, s=""):
    out.write(_safe_str(s) + "\n")

# ----------------- DUMP LOGIC -----------------

def _dump_basic_info(f, input_path):
    _write_line(f, "===== BASIC INFO =====")
    _write_line(f, f"Input File:  {input_path}")
    _write_line(f, f"Root Name:   {ida_nalt.get_root_filename()}")
    _write_line(f, f"SHA256:      {_sha256_file(input_path)}")
    _write_line(f, f"Processor:   {ida_ida.inf_get_procname()}")
    _write_line(f, f"64-bit:      {ida_ida.inf_is_64bit()}")
    _write_line(f, f"Image Base:  0x{ida_nalt.get_imagebase():X}")
    _write_line(f)

def _dump_imports(f, input_path=None):
    _write_line(f, "===== IMPORTS =====")
    count = 0
    try:
        qty = ida_nalt.get_import_module_qty()
        for i in range(qty):
            name = ida_nalt.get_import_module_name(i)
            _write_line(f, f"Module: {name}")
            def imp_cb(ea, name, ord):
                nonlocal count
                count += 1
                _write_line(f, f"  0x{ea:X}  {name or ord}")
                return True
            ida_nalt.enum_import_names(i, imp_cb)
            if MAX_IMPORTS is not None and count >= MAX_IMPORTS:
                _write_line(f, "... truncated")
                break
    except Exception as e:
        _write_line(f, f"<imports_failed: {e}>")
    _write_line(f)

def _dump_exports(f, input_path=None):
    _write_line(f, "===== EXPORTS / ENTRIES =====")
    count = 0
    try:
        qty = ida_entry.get_entry_qty()
        for i in range(qty):
            count += 1
            ord = ida_entry.get_entry_ordinal(i)
            if hasattr(ida_entry, 'get_entry_ea'):
                ea = ida_entry.get_entry_ea(ord)
            elif hasattr(ida_entry, 'get_entry_addr'):
                ea = ida_entry.get_entry_addr(ord)
            else:
                ea = ida_nalt.get_entry_ea(ord) if hasattr(ida_nalt, 'get_entry_ea') else 0
            
            name = ida_entry.get_entry_name(ord)
            _write_line(f, f"0x{ea:X}  (Ord: {ord}) {name}")
            if MAX_EXPORTS is not None and count >= MAX_EXPORTS:
                _write_line(f, "... truncated")
                break
    except Exception as e:
        _write_line(f, f"<exports_failed: {e}>")
    _write_line(f)

def _dump_names(f, input_path=None):
    _write_line(f, "===== NAMES =====")
    count = 0
    try:
        for ea, name in idautils.Names():
            count += 1
            _write_line(f, f"0x{ea:X}  {name}")
            if MAX_NAMES is not None and count >= MAX_NAMES:
                _write_line(f, "... truncated")
                break
    except Exception as e:
        _write_line(f, f"<names_failed: {e}>")
    _write_line(f)

def _dump_functions(f, input_path=None):
    _write_line(f, "===== FUNCTIONS =====")
    count = 0
    try:
        for ea in idautils.Functions():
            count += 1
            name = ida_name.get_name(ea)
            f_obj = ida_funcs.get_func(ea)
            if f_obj:
                _write_line(f, f"0x{f_obj.start_ea:X} - 0x{f_obj.end_ea:X}  {name}")
            if MAX_FUNCS is not None and count >= MAX_FUNCS:
                _write_line(f, "... truncated")
                break
    except Exception as e:
        _write_line(f, f"<funcs_failed: {e}>")
    _write_line(f)

def _dump_strings(f, input_path=None):
    _write_line(f, "===== STRINGS =====")
    count = 0
    try:
        for s in idautils.Strings():
            count += 1
            _write_line(f, f"0x{s.ea:X}  [len {s.length}] {str(s)}")
            if MAX_STRINGS is not None and count >= MAX_STRINGS:
                _write_line(f, "... truncated")
                break
    except Exception as e:
        _write_line(f, f"<strings_failed: {e}>")
    _write_line(f)

# ----------------- MAIN UI LOGIC -----------------

def main():
    input_path = ida_nalt.get_input_file_path()
    if not input_path or not os.path.exists(input_path):
        # Fallback if input path isn't directly on disk (e.g. packed/remote DB)
        dir_path = os.getcwd()
        input_path = os.path.join(dir_path, ida_nalt.get_root_filename())
    else:
        dir_path = os.path.dirname(input_path)

    btn = ida_kernwin.ask_buttons("Single", "Multiple", "Cancel", 1, "Dump Mode")
    if btn == -1: 
        return

    base_name = os.path.splitext(ida_nalt.get_root_filename())[0]

    try:
        if btn == 1: # SINGLE FILE
            default_out = os.path.join(dir_path, f"{base_name}_full_dump.txt")
            out_path = ida_kernwin.ask_file(True, default_out, "Save Full Dump")
            if not out_path: 
                return
            
            with open(out_path, "w", encoding="utf-8", errors="replace") as f:
                _dump_basic_info(f, input_path)
                _dump_imports(f, input_path)
                _dump_exports(f, input_path)
                _dump_names(f, input_path)
                _dump_functions(f, input_path)
                _dump_strings(f, input_path)
            ida_kernwin.msg(f"[ida_dump] Full dump created: {out_path}\n")
            ida_kernwin.info(f"Full dump successfully created at:\n{out_path}")

        elif btn == 0: # MULTIPLE FILES
            folder_path = os.path.join(dir_path, f"{base_name}_dump_parts")
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            
            parts = [
                ("INFO", _dump_basic_info),
                ("IMPORTS", _dump_imports),
                ("EXPORTS", _dump_exports),
                ("NAMES", _dump_names),
                ("FUNCTIONS", _dump_functions),
                ("STRINGS", _dump_strings)
            ]
            
            for suffix, func in parts:
                p = os.path.join(folder_path, f"{base_name}_{suffix}.txt")
                with open(p, "w", encoding="utf-8", errors="replace") as f:
                    func(f, input_path)
                    
            ida_kernwin.msg(f"[ida_dump] Multi-dump complete in: {folder_path}\n")
            ida_kernwin.info(f"Multi-dump successfully completed in:\n{folder_path}")

    except Exception as e:
        ida_kernwin.warning(f"Dump failed with error:\n{str(e)}")

# ----------------- PLUGIN WRAPPER -----------------

class DumpAll_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Dumps IDB info to text files"
    help = "Dumps binary metadata for external analysis"
    wanted_name = "Dump All Tabs"
    wanted_hotkey = "Alt-Shift-D"

    def init(self): return idaapi.PLUGIN_OK
    def run(self, arg): main()
    def term(self): pass

def PLUGIN_ENTRY(): return DumpAll_Plugin()

if __name__ == "__main__":
    main()