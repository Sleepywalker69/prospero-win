# Persistent controller settings

Controller settings use the existing `[input]` section in a game's
`/data/prospero-win/profiles/<name>.profile`, or a shared
`/data/prospero-win/input/<name>.input` preset. Edit the text file while the
application is closed. The next launch reads it again; there is no live
reload or graphical settings editor in this change.

A profile selects a shared preset with `preset = <name>`. Its own input
lines override that preset. Settings not mentioned keep the existing
defaults. Unknown keys, invalid values and repeated keys refuse the file;
they do not partially apply it. Comments belong on their own lines.

## Pointer and startup mode

```ini
[input]
; The game's normal controller API remains XInput.
mode = xinput
; Start this application with the controller operating the pointer.
start_mode = mouse
mouse_speed = 900
mouse_deadzone = 16
touch_speed = 125
```

- `start_mode = profile` (default) starts with the game's configured input.
  `start_mode = mouse` starts in mouse/UI mode. L3+R3 still switches modes.
  Switching during play does not rewrite the file or change the next
  launch's startup choice.
- `mouse_speed` is the stick pointer's maximum pixels per second: 1–20000,
  default 1200. It applies to the left stick in mouse/UI mode and to a
  configured `mouse = left_stick` or `right_stick` in keyboard-profile mode.
- `mouse_deadzone` is the number of raw stick units ignored on either side
  of the centered value 128: 0–120, default 20. Increase it to suppress
  drift; zero may expose stick noise. The motion curve remains squared
  beyond the deadzone and reaches full speed at full tilt. This setting
  does not alter XInput stick values or the existing neutral-control gate
  after a mode/focus change.
- `touch_speed` is a percentage: 25–400, default 100. At 100, one raw
  touch-sensor unit moves half a pixel. Touch motion is relative and only
  active in mouse/UI mode. Finger changes and jumps still re-anchor rather
  than move the pointer.

`mode = keyboard` or `xinput` selects the game's profile mode; it is
separate from `start_mode`. Mouse/UI mode keeps the XInput slot disconnected
so the same physical input is not also sent to the gamepad path.

## Mouse/UI bindings

Regular button lines such as `cross = space` configure keyboard-profile
mode. Prefix a button name with `ui_` to override only mouse/UI mode:

```ini
[input]
; Swap the two clicks, and add a middle click on R2.
ui_cross = mouse_right
ui_circle = mouse_left
ui_r2 = mouse_middle
```

Values use the existing binding syntax: a letter, digit, named key such as
`enter`, `f1`–`f24`, `vk:0xNN`, `mouse_left`, `mouse_right`,
`mouse_middle`, or `none`. `none` explicitly disables that UI action.
Bindings omitted from the file retain these defaults:

| Control | Mouse/UI action |
| --- | --- |
| Cross / Circle | Left / right mouse button |
| Square / Triangle | Escape / Enter |
| L1 / R1 | Shift / Tab; together, Shift+Tab |
| D-pad | Arrow keys |
| L2 / R2 / touchpad click | No key or button action |
| Left stick / one-finger touch | Relative pointer motion |

L3 and R3, Options and Create are reserved and cannot have `ui_` overrides.
L3+R3 switches modes; releasing Options cycles the same-process GDI windows;
holding Options+Create requests application closure. Touchpad click is
independent from moving a finger on the touch surface.

Each output key or mouse button may appear only once in the effective UI
map. For example, `ui_cross = enter` also requires `ui_triangle = none`
(or another unused action) in that file. This avoids a held key being
released early when two controls send it. Write both sides of a swap in
the same file. If individually valid preset and profile bindings collide
after merging, the preset is refused as a whole and only the profile's
own lines remain, matching the existing missing/refused-preset fallback.
The launch log reports the input status, effective startup settings and
resolved UI bindings as readable names.

The launcher guide shows the default bindings. Custom mappings are shown
in the launch log and can be described by the binding-label API. This is
controller routing for existing application windows, not a complete
Windows desktop or native Sony HID emulation. Host tests cover parsing,
preset reload/overrides, motion and routing; physical-console validation
is still required.

## Launcher editor

Select an available application in the library, then press **Square** or
keyboard **F2**. The screen reads the profile and preset again and shows the
current effective startup mode, stick deadzone, stick speed and touch
sensitivity. A refused or missing preset is labeled; its fallback is the same
one that the next launch uses.

- Up/down selects a setting, **Apply**, or **Cancel**.
- Left/right adjusts the setting. L1/R1 or Page Up/Page Down uses larger steps.
- Cross/Enter chooses Apply or Cancel. Circle/Escape cancels from any row.
- Settings capture all navigation and activation. Closing the screen discards
  queued activation in that input batch, so it cannot also launch the game.
- Apply writes only changed values as profile overrides, for the next launch.
  Unchanged inherited settings remain inherited from their preset. Applying
  without edits performs no file write. Cancel does not save.

This first editor does not edit bindings, change an active game's controls or
persist its temporary L3+R3 mode changes. Existing bindings, presets,
application/display/debug/runtime fields, comments and line endings are kept.
Invalid or unsupported profiles are refused rather than regenerated.

### Save boundary

The native writer refuses symlink and non-regular profiles, compares the
open-time bytes with the current file, and writes a new exclusive
`<profile>.settings.tmp` sibling. It handles interrupted/partial writes,
preserves ordinary file permission bits, flushes and closes the new file,
then rechecks the original snapshot before atomically renaming the sibling.
A failure before rename leaves the profile and editor's original values
unchanged; the draft stays open for retry or cancellation. Only the temporary
created by that save attempt is cleaned up. A pre-existing temporary is never
overwritten or removed and blocks saving until it is resolved outside the
editor.

Do not edit a profile externally while its settings screen is open. A detected
external edit asks you to cancel and reopen. The final rename is not a
cross-process compare-and-swap, so simultaneous writers are unsupported.
Atomic visibility is provided; directory durability across sudden power loss
is not claimed. No setting reaches the game until a fresh launch reads it.

Host coverage includes navigation and dismissal, no-change Apply, invalid
values, inheritance and byte preservation, preset fallback, short/interrupted
writes, file conflicts, symlink/FIFO refusal, and write/flush/close/rename
failure rollback. Target SDK build and physical-controller validation remain
separate gates.
