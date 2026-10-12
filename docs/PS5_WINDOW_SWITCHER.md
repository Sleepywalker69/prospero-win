# Process-local Wine window switching

The input event `PW_WINE_INPUT_WINDOW_CYCLE` (numeric 4) carries `code=0`,
`x=+1` for next or `x=-1` for previous, `y=0`, `down=1`. Its layout is unchanged.
The title controller router assigns Options release in UI/mouse mode; a Create
chord cancels that action so the existing close chord is not consumed here.

The driver cycles visible, enabled top-level app families from
its own 64-entry window registry. A family is a root owner with its owned
windows. Its topmost eligible window is chosen using Wine USER z-order, so a
disabled modal owner is not activated ahead of its enabled dialog. Tool windows,
NOACTIVATE windows, child windows, other processes, and native bridge service
windows are excluded. USER performs foreground activation and window raising,
including its own activation/focus notifications. A failed activation leaves
the previous foreground in place unless an application callback changes it. No
WM_SETFOCUS messages are fabricated.

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

## Restoring minimized windows

A minimized root-owner window is included only while it remains visible,
enabled, process-local and owned by the GUI thread consuming the cycle event.
A root disabled by a modal dialog is never restored or activated instead of
that dialog. Minimized owned popups and minimized windows belonging to another
GUI thread are skipped; ordinary visible windows keep their existing local
family cycling behavior. If a different local GUI thread drains the shared
input queue, it will skip a minimized window it does not own.

After releasing held input, the driver makes one `NtUserShowWindow(SW_RESTORE)`
call for the selected minimized root. The pinned Wine USER implementation
preserves restore-to-maximized placement, honors `WM_QUERYOPEN` and CBT vetoes,
and delivers the activation/size notifications. ShowWindow's return value is
previous visibility, not success: the driver checks the live registry generation,
process, owner family, styles and foreground again after the call. A veto,
destruction/reuse, new modal owner state or intervening focus change ends that
cycle attempt. It does not retry or fall through and activate a different family.

The current foreground must be a live entry from the local registry. If it has
changed to an unrelated window before the action, no restore or activation is
attempted. If USER/application callbacks select another window during restore,
that choice is respected. A successful foreground call is followed by another
identity/style/foreground check before raising the window.

The registry is capped at 64 entries. Each family search visits at most 256
USER z-order links; a changing or oversized desktop can therefore skip a target
rather than stall the input pump. “Bounded” means one restore call and capped
searches, not a deadline for application callbacks: a same-thread window
procedure can still block. No cross-thread synchronous restore or queued async
restore is issued. Cross-thread restore needs a separate lifetime-safe request
and acknowledgment design before it can be enabled.

Pinned semantic reference: Wine `490f6d5dcbb2a5047345b8af88d114bbcaad69a8`,
`dlls/win32u/window.c`, `window_min_maximize`, `show_window`, `NtUserShowWindow`
and `NtUserShowWindowAsync`; `dlls/win32u/input.c`, `set_foreground_window`.
These USER APIs are used directly; the driver does not manufacture a successful
restore by clearing `WS_MINIMIZE` itself.

## What this does not establish

This is a same-process GDI foundation, not an Explorer desktop, taskbar window
list, cross-process compositor, or arbitrary Chromium child-window transport.
Only eligible same-GUI-thread minimized roots can be restored, as described below.
Layered/transparent composition
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
queue validation, and offset/empty z-order clipping. Restore checks include
old-input-up before restore, forward/back cycling, a single minimized window,
veto/false-return behavior, same-thread filtering, modal/hidden/foreign-process
changes during restore, HWND reuse, callback focus changes, reentrant polling
and capped z-order traversal. These are host contract
checks, not a substitute for Wine or PS5 execution. The source-contract build and
the optional composed-source Makefile checks run both strict and UBSan variants.

Target acceptance must cover two overlapping GDI windows, a disabled owner and
modal dialog, continuous background repaint, dragging/closing windows, physical
keys/buttons held during cycling, reconnect, a destroyed selected window, and
failed activation. Inspect actual pixels and actual received activation/input
messages. Test fullscreen graphics separately rather than inferring support.


Minimized-window target acceptance additionally requires actual USER message
traces and pixels for normal and maximized-before-minimize windows, a vetoing
`WM_QUERYOPEN` window, minimized disabled modal owners, a second GUI thread,
destroy/recreate during restore callbacks, and an unrelated foreground process.
Confirm a rejected/vetoed restore is attempted once, that no queued restore
activates later, and that held key/button releases reach the old window first.
Host boundary models cannot establish those target observations.
