# CopyOpcodes

__AUTHOR__ = '@argie'
PLUGIN_NAME = "CopyOpcodes"
PLUGIN_HOTKEY = 'Ctrl+Shift+H'
VERSION = '1.0.0'

import idaapi
import idc
import ida_bytes
import idautils
from PyQt5.Qt import QApplication, QInputDialog

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def PLUGIN_ENTRY():
    return copy_opcodes()

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
                copy_opcodes.ACTION_COPY_BYTES,
                "Copy Opcodes",
                idaapi.SETMENU_APP
            )
        return 0

# ----------------- Plugin Class -----------------
class copy_opcodes(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Copy opcodes as hex"
    help = "Select instructions, right click, and choose 'Copy Opcodes'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    ACTION_COPY_BYTES = "prefix:copy_bytes"

    def init(self):
        self._init_action_copy_bytes()
        self._init_hooks()
        idaapi.msg(f"{self.wanted_name} {VERSION} initialized...\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg(f"{self.wanted_name} cannot be run as a script.\n")

    def term(self):
        self._del_action_copy_bytes()
        if hasattr(self, "_hooks"):
            self._hooks.unhook()
        idaapi.msg(f"{self.wanted_name} terminated...\n")

    # ----------------- Action Registration -----------------
    def _init_action_copy_bytes(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY_BYTES,
            "Copy Opcodes",
            IDACtxEntry(copy_bytes),
            PLUGIN_HOTKEY,
            "Copy selected bytes as hex",
            31
        )
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_copy_bytes(self):
        idaapi.unregister_action(self.ACTION_COPY_BYTES)

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

# ----------------- Copy Bytes Function -----------------
def copy_bytes():
    # Get selection
    if using_ida7api:
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idc.get_item_head(ea)
            end = idc.get_item_end(ea)
        data = ida_bytes.get_bytes(start, end - start)
    else:
        start = idc.SelStart()
        end = idc.SelEnd()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idc.GetItemHead(ea)
            end = idc.GetItemEnd(ea)
        data = idc.GetManyBytes(start, end - start)

    if not data:
        idaapi.msg("[!] No bytes selected or failed to read.\n")
        return

    # Ask user which format to use
    formats = ["Spaced opcodes", "Continuous opcodes"]
    choice, ok = QInputDialog.getItem(None, "Copy Format", "Select format:", formats, 0, False)
    if not ok:
        return

    spaced_data = ' '.join(f"{b:02X}" for b in data)
    continuous_data = ''.join(f"{b:02X}" for b in data)

    output = spaced_data if choice == "Spaced opcodes" else continuous_data

    # Print and copy to clipboard
    print(f"Bytes copied ({choice}): {output}")
    copy_to_clip(output)
    print(f"[Clipboard] {choice} copied to clipboard.")
