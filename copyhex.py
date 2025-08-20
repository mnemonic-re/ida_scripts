# copyhex

__AUTHOR__ = '@argie'
PLUGIN_NAME = "CopyHex"
PLUGIN_HOTKEY = 'Ctrl+Shift+H'
VERSION = '1.0.0'

import os
import sys
import idc
import idaapi
import idautils
import ida_kernwin

major, minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = (major > 6)

if using_ida7api or (major == 6 and minor >= 9):
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    from PyQt5.Qt import QApplication
else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = QtGui
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    from PySide.QtGui import QApplication

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def PLUGIN_ENTRY():
    return hex_copy()

class hex_copy(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Copy Hex Bytes"
    help = "Select opcodes, right click and 'Copy Hex'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self._init_action_copy_bytes()
        self._init_hooks()
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        self._del_action_copy_bytes()
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    ACTION_COPY_BYTES = "prefix:copy_bytes"

    def _init_action_copy_bytes(self):
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY_BYTES,
            "Copy Hex",
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

class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        super().__init__()

    def finish_populating_widget_popup(self, form, popup):
        widget_title = idaapi.get_widget_title(form)
        if "IDA View" in widget_title:
            idaapi.attach_action_to_popup(form, popup, hex_copy.ACTION_COPY_BYTES, "Copy Hex", idaapi.SETMENU_APP)
        return 0

def copy_bytes():
    if using_ida7api:
        start = idc.read_selection_start()
        end = idc.read_selection_end()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idc.get_item_head(ea)
            end = idc.get_item_end(ea)

        data = idc.get_bytes(start, end - start).hex()
        spaced_data = ' '.join(data[i:i+2].upper() for i in range(0, len(data), 2))
        print("Bytes copied (spaced):", spaced_data)
        print("Bytes copied (continuous):", data.upper())
        copy_to_clip(spaced_data)
    else:
        start = idc.SelStart()
        end = idc.SelEnd()
        if idaapi.BADADDR in (start, end):
            ea = idc.here()
            start = idc.get_item_head(ea)
            end = idc.get_item_end(ea)

        data = idc.GetManyBytes(start, end-start).hex()
        spaced_data = ' '.join(data[i:i+2].upper() for i in range(0, len(data), 2))
        print("Bytes copied (spaced):", spaced_data)
        print("Bytes copied (continuous):", data.upper())
        copy_to_clip(spaced_data)
    return
