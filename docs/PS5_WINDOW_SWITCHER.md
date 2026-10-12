# Process-local Wine window switching

The input event `PW_WINE_INPUT_WINDOW_CYCLE` (numeric 4) carries `code=0`,
`x=+1` for next or `x=-1` for previous, `y=0`, `down=1`. Its layout is unchanged.
The title controller router assigns Options release in UI/mouse mode; a Create
chord cancels that action so the existing close chord is not consumed here.

The driver cycles visible, enabled, non-minimized top-level app families from
its own 64-entry window registry. A family is a root owner with its owned
windows. Its topmost eligible window is chosen using Wine USER z-order, so a
disabled modal owner is not activated ahead of its enabled dialog. Tool windows,
NOACTIVATE windows, child windows, other processes, and native bridge service
windows are excluded. USER performs foreground activation and window raising,
including its own activation/focus notifications. A failed activation leaves
the previous foreground in place. No WM_SETFOCUS messages are fabricated.

Held keyboard and mouse buttons are released against their old live HWND before
explicit cycling. External focus changes are reconciled on the next driver event
poll, including an empty input queue, and between queued events. Removed/reused
registry generations do not receive those releases. The shared input queue has
one non-blocking consumer at a time; reentrant or concurrent consumers leave it
for the active consumer. Registry changes keep stable creation order.

Software surface flushes honor Wine's z-order clipping, including an empty
visible region. A background repaint therefore cannot overwrite the selected
window's opaque pixels. The clip callback forces newly exposed bitmap-local
bounds dirty; activation and destruction also invalidate the desktop's children.
Clipping allocation failure is fail-closed. Bitmap-local dirty rectangles and
offset surface rectangles are explicitly distinguished.

## What this does not establish

This is a same-process GDI foundation, not an Explorer desktop, taskbar window
list, cross-process compositor, or arbitrary Chromium child-window transport.
Minimized windows are not restored by cycling. Layered/transparent composition
and GL/Vulkan direct scanout switching are not implemented by this change.
Input release on externally initiated activation occurs when ProcessEvents next
runs; it is not a synchronous hook for every USER focus transition.

No PS5 installation, app launch, target display inspection, or target focus test
was performed for this change. Full Wine/PRX compilation remains required.

## Checks

With the pinned Wine headers or the exact composed source:

```
python3 tests/test_ps5_window_switcher.py --wine-source /path/to/wine --out /new/output
python3 tests/test_ps5_window_switcher.py --wine-source /path/to/wine --out /new/ubsan --ubsan
```

The runner applies every repository patch touching ps5drv.c, compiles the actual
registry/cycling/input/clipping function bodies against real Wine types, and links
the real title input sink. USER calls are inert boundary models. An already
composed supplied ps5drv.c must match the repository's patch chain byte-for-byte.
The checks include old-input-up before new-focus ordering, modal owners, live
visibility and generation changes, filtering, no-input focus reconciliation,
reentrant consumer rejection, failed/destroyed activation, registry capacity,
queue validation, and offset/empty z-order clipping. These are host contract
checks, not a substitute for Wine or PS5 execution. The source-contract build and
the optional composed-source Makefile checks run both strict and UBSan variants.

Target acceptance must cover two overlapping GDI windows, a disabled owner and
modal dialog, continuous background repaint, dragging/closing windows, physical
keys/buttons held during cycling, reconnect, a destroyed selected window, and
failed activation. Inspect actual pixels and actual received activation/input
messages. Test fullscreen graphics separately rather than inferring support.
