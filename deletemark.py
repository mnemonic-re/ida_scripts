import idaapi
import ida_idc
import ida_idaapi
import ida_kernwin
import idc

VERSION = "1.0.0"
__AUTHOR__ = "argie"

PLUGIN_NAME = "Delete Mark"
PLUGIN_HOTKEY = "Ctrl+D"

# Action name must be globally unique inside IDA
ACTION_DELETE_MARK = "my:delete_mark"


# ------------------------------------------------------------
# Mark helpers
# ------------------------------------------------------------

def get_screen_ea():
    """Current EA under cursor in the active disassembly view."""
    return idc.get_screen_ea()


def find_mark_slots_at_ea(ea, max_slots=1024):
    """
    Return a list of mark slots whose marked address equals `ea`.

    IDA "Mark position" is a slot system (0..1023).
    get_marked_pos(slot) returns BADADDR if slot is empty.
    """
    hits = []
    for slot in range(max_slots):
        pos = ida_idc.get_marked_pos(slot)
        if pos == ea:
            hits.append(slot)
    return hits


def clear_mark_slot(slot):
    """
    Clear a mark slot.

    IDAPython does not provide a dedicated "delete mark" function in the public API,
    but clearing can be achieved by re-marking the slot with ea=BADADDR.
    We verify afterwards.

    Returns True if the slot is cleared.
    """
    # Attempt #1: BADADDR + empty comment
    ida_idc.mark_position(ida_idaapi.BADADDR, 0, 0, 0, slot, "")

    if ida_idc.get_marked_pos(slot) == ida_idaapi.BADADDR:
        return True

    # Attempt #2: BADADDR + non-empty comment (some older flows expected non-empty)
    ida_idc.mark_position(ida_idaapi.BADADDR, 0, 0, 0, slot, "cleared")

    return ida_idc.get_marked_pos(slot) == ida_idaapi.BADADDR


def delete_mark_at_cursor():
    """
    Delete mark(s) at current cursor EA (exact match).
    If multiple slots point to the same EA (rare but possible), we delete them all.
    """
    ea = get_screen_ea()
    if ea == idaapi.BADADDR:
        idaapi.msg("[Delete Mark] Cursor EA is not valid.\n")
        return

    slots = find_mark_slots_at_ea(ea)
    if not slots:
        idaapi.msg(f"[Delete Mark] No Mark Position found at {ea:#x}.\n")
        return

    deleted = 0
    failed = 0

    for slot in slots:
        if clear_mark_slot(slot):
            deleted += 1
        else:
            failed += 1
            cmt = ida_idc.get_mark_comment(slot)
            pos = ida_idc.get_marked_pos(slot)
            idaapi.msg(f"[Delete Mark] WARNING: failed to clear slot={slot} pos={pos:#x} cmt={cmt!r}\n")

    idaapi.msg(f"[Delete Mark] Deleted {deleted} mark(s) at {ea:#x}")
    if failed:
        idaapi.msg(f", {failed} failed.\n")
    else:
        idaapi.msg(".\n")


# ------------------------------------------------------------
# IDA Action plumbing (matches your template)
# ------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):
    """
    Simple adapter: binds an IDA action to a Python function.
    """
    def __init__(self, action_function):
        super().__init__()
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function()
        return 1

    def update(self, ctx):
        # Always enabled (you can gate it to IDA View only, but you wanted it in the popup anyway)
        return idaapi.AST_ENABLE_ALWAYS


class Hooks(idaapi.UI_Hooks):
    """
    Adds our action to the right-click menu in IDA View.
    """
    def finish_populating_widget_popup(self, form, popup):
        widget_title = idaapi.get_widget_title(form)
        if "IDA View" in widget_title:
            # Add under a submenu header. You can rename "Delete Mark" grouping if you want.
            idaapi.attach_action_to_popup(
                form,
                popup,
                ACTION_DELETE_MARK,
                "Delete Mark",
                idaapi.SETMENU_APP
            )
        return 0


class DeleteMarkPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Delete an IDA 'Mark position' at the cursor address."
    help = "Right-click in IDA View -> Delete Mark (or press Ctrl+D)."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        self._init_action_delete_mark()
        self._init_hooks()
        idaapi.msg(f"{self.wanted_name} {VERSION} initialized...\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg(f"{self.wanted_name} cannot be run as a script.\n")

    def term(self):
        self._del_action_delete_mark()
        idaapi.msg(f"{self.wanted_name} terminated...\n")

    def _init_action_delete_mark(self):
        # If action already exists (reloading plugin), unregister first.
        if idaapi.unregister_action(ACTION_DELETE_MARK):
            idaapi.msg("[Delete Mark] Warning: action was already registered, unregistering it first\n")

        action_desc = idaapi.action_desc_t(
            ACTION_DELETE_MARK,                 # internal action name
            "Delete Mark",                      # visible label
            IDACtxEntry(delete_mark_at_cursor), # handler
            PLUGIN_HOTKEY,                      # hotkey
            "Delete Mark Position at cursor EA",
            31                                  # icon id (same as your template; replace if you have your own)
        )

        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_delete_mark(self):
        idaapi.unregister_action(ACTION_DELETE_MARK)

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()


def PLUGIN_ENTRY():
    return DeleteMarkPlugin()
