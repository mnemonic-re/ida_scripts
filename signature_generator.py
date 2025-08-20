# Signature Generator

__AUTHOR__ = '@argie'
PLUGIN_NAME = "IDA Signature Generator"
PLUGIN_HOTKEY = 'Ctrl+Shift+S'
VERSION = '1.0.0'

import idaapi
import idc
import idautils
import ida_ua
import ida_bytes
from PyQt5.Qt import QApplication
from PyQt5.QtWidgets import QInputDialog

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def PLUGIN_ENTRY():
    return sig_generator()

# ----------------- UI Hooks -----------------
class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        super().__init__()

    def finish_populating_widget_popup(self, form, popup):
        widget_title = idaapi.get_widget_title(form)
        if "IDA View" in widget_title:
            idaapi.attach_action_to_popup(
                form,
                popup,
                sig_generator.ACTION_GENERATE_SIG,
                "Generate Signature",
                idaapi.SETMENU_APP
            )
        return 0

# ----------------- Plugin Class -----------------
class sig_generator(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Generate Signature with wildcards"
    help = "Select instructions and generate signature"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    ACTION_GENERATE_SIG = "prefix:generate_signature"

    def init(self):
        self._init_action_generate_sig()
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        self._del_action_generate_sig()
        if hasattr(self, "_hooks"):
            self._hooks.unhook()
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    # ----------------- Action Registration -----------------
    def _init_action_generate_sig(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_GENERATE_SIG,
            "Generate Signature",
            IDACtxEntry(generate_signature),
            PLUGIN_HOTKEY,
            "Generate signature from selected bytes",
            31
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_generate_sig(self):
        idaapi.unregister_action(self.ACTION_GENERATE_SIG)

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()

# ----------------- Action Handler -----------------
class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# ----------------- Signature Generator -----------------
def generate_signature():
    # Ask user which output format to use
    formats = ["IDA", "x64dbg", "C Byte Array - StringMask"]
    fmt, ok = QInputDialog.getItem(None, "Signature Format", "Format:", formats, 0, False)
    if not ok:
        return

    if using_ida7api:
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idc.get_item_head(ea)
            end = idc.get_item_end(ea)
    else:
        start = idc.SelStart()
        end = idc.SelEnd()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idc.get_item_head(ea)
            end = idc.get_item_end(ea)

    instr_bytes_all = []
    wildcard_map_all = []

    for head in idautils.Heads(start, end):
        size = ida_bytes.get_item_size(head)
        instr_bytes = [ida_bytes.get_wide_byte(head + i) for i in range(size)]
        wildcard_map = [False] * size

        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, head):
            continue

        for op in insn.ops:
            if op.type in [ida_ua.o_imm, ida_ua.o_mem, ida_ua.o_near, ida_ua.o_displ]:
                op_start = op.offb
                for i in range(op_start, size):
                    wildcard_map[i] = True

        instr_bytes_all.extend(instr_bytes)
        wildcard_map_all.extend(wildcard_map)

    if fmt in ["IDA", "x64dbg"]:
        wildcard = "?" if fmt == "IDA" else "??"
        sig_bytes = [
            wildcard if w else f"{b:02X}" 
            for b, w in zip(instr_bytes_all, wildcard_map_all)
        ]
        signature = ' '.join(sig_bytes)
        print(f"Generated robust signature ({fmt} format): {signature}")
        copy_to_clip(signature)
        print(f"[Clipboard] Signature copied: {signature}")

    else:
        c_bytes = []
        mask = []
        for b, w in zip(instr_bytes_all, wildcard_map_all):
            c_bytes.append(f"\\x{b:02X}")
            mask.append('?' if w else 'x')
        c_signature = ''.join(c_bytes)
        mask_str = ''.join(mask)
        print(f"Generated robust signature ({fmt} format): {c_signature} {mask_str}")
        copy_to_clip(f"{c_signature} {mask_str}")
        print(f"[Clipboard] Signature copied: {c_signature} {mask_str}")
