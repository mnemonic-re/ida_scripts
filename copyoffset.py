import os
import sys
import idaapi
import idc
import ida_kernwin
import idautils
from PyQt5.QtWidgets import QApplication

VERSION = '1.0.0'
__AUTHOR__ = 'argie'

PLUGIN_NAME = "Copy Address Offset"
PLUGIN_HOTKEY = "Shift+C"

def set_clipboard_text(data):
    cb = QApplication.clipboard()
    cb.setText(data)

def PLUGIN_ENTRY():
    return GetOffsetPlugin()

class GetOffsetPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Get the address offset at the cursor location."
    help = "Select a location, right-click 'Copy Offset or press Shift + C'"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self):
        super().__init__()

    def init(self):
        self._init_action_get_offset()
        self._init_hooks()
        idaapi.msg(f"{self.wanted_name} {VERSION} initialized...\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg(f"{self.wanted_name} cannot be run as a script.\n")

    def term(self):
        self._del_action_get_offset()
        idaapi.msg(f"{self.wanted_name} terminated...\n")

    ACTION_GET_OFFSET = "my:copy_offset"

    def _init_action_get_offset(self):
        if idaapi.unregister_action(self.ACTION_GET_OFFSET):
            idaapi.msg("Warning: action was already registered, unregistering it first\n")

        action_desc = idaapi.action_desc_t(
            self.ACTION_GET_OFFSET,  
            "Copy Offset",           
            IDACtxEntry(copy_offset), 
            PLUGIN_HOTKEY,           
            "Copy the offset from the image base of the current cursor address.",
            31                       
        )
        
        # Register the action
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_get_offset(self):
        idaapi.unregister_action(self.ACTION_GET_OFFSET)

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()

class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        super().__init__()

    def finish_populating_widget_popup(self, form, popup):
        widget_title = idaapi.get_widget_title(form)
        if "IDA View" in widget_title:
            idaapi.attach_action_to_popup(form, popup, GetOffsetPlugin.ACTION_GET_OFFSET, "Copy Address Offset", idaapi.SETMENU_APP)
        return 0

def get_screen_linear_address(): 
    return idc.get_screen_ea()

def get_imagebase_offset():
    return idaapi.get_imagebase()

def get_input_offset():
    vCurrentPos = get_screen_linear_address()
    offset = idaapi.get_fileregion_offset(vCurrentPos)
    
    if vCurrentPos != idaapi.BADADDR:
        print(f"Offset = [{offset:#x}]")
        set_clipboard_text(f"{offset:#x}")
    else:
        print("Current address is not valid.")

def copy_offset():
    print("------------------------------------------")
    get_input_offset()

class IDACtxEntry(idaapi.action_handler_t):
    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
