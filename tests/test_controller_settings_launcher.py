#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Run the actual launcher's modal dispatch with controlled profile I/O.

Also hold the real polling-loop boundary that discards queued activation on
modal transitions, and keep settings out of the isolated native probe UI.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / "native/wine64_main.c").read_text()
    helper = source.split("static int launcher_controller_control(", 1)[1].split("\n#endif", 1)[0]
    helper = "static int launcher_controller_control(" + helper
    harness = r'''
#include "native/pw_wine_controller_settings.h"
#include <assert.h>
#include <string.h>
#define PS5LOG_LOG(...) ((void)0)
static const char *library_root = "/unused";
static PwWineLibrary library;
static struct { const char *id; } catalog[] = {{"demo"}};
static const size_t catalog_count = 1;
static int open_calls, save_calls, open_failure, save_failure, wrong_id;
int pw_wine_controller_edit_open(PwWineControllerEdit *edit, const char *root, const char *file)
{
    assert(!strcmp(root, library_root) && !strcmp(file, "demo.profile")); open_calls++;
    if (open_failure) return PW_ERR_VM;
    PwGameInput input; pw_game_input_init(&input);
    strcpy(edit->profile.app.id, wrong_id ? "other" : "demo");
    return pw_controller_settings_open(&edit->screen, &input);
}
int pw_wine_controller_edit_save(void *context, const PwControllerValues *values, uint32_t fields)
{
    assert(context && values->touch_speed == 200 && fields == PW_CONTROLLER_TOUCH);
    save_calls++; return save_failure;
}
''' + helper + r'''
int main(void)
{
    PwLauncherItem items[] = {{"demo",0,1},{"refused",0,0}};
    PwLauncherScene scene = {items,2,0,0};
    PwWineControllerEdit edit = {0}; int help = 0; const char *feedback = NULL;
    library.count = 1; library.entries[0].status = PW_OK;
    strcpy(library.entries[0].profile.app.id, "demo"); strcpy(library.entries[0].file, "demo.profile");
#define ACTION(a) launcher_controller_control(&scene, (a), 1, &help, &edit, &feedback)
    assert(!ACTION(PW_LAUNCHER_ACTION_HELP) && help);
    assert(!ACTION(PW_LAUNCHER_ACTION_SETTINGS) && !open_calls);
    assert(!ACTION(PW_LAUNCHER_ACTION_BACK) && !help);
    scene.selected = 1;
    assert(!ACTION(PW_LAUNCHER_ACTION_SETTINGS) && !open_calls && feedback);
    scene.selected = 0; items[0].available = 0;
    assert(!ACTION(PW_LAUNCHER_ACTION_SETTINGS) && !open_calls);
    items[0].available = 1;
    assert(!ACTION(pw_launcher_pad_action(0x8000 | 0x4000)) && edit.screen.active && open_calls == 1);
    assert(!ACTION(PW_LAUNCHER_ACTION_HELP) && !help && edit.screen.active);
    assert(!ACTION(PW_LAUNCHER_ACTION_RIGHT) && scene.selected == 0 && edit.screen.draft.start_mode == PW_GAME_START_MOUSE);
    assert(!ACTION(PW_LAUNCHER_ACTION_CHOOSE) && !save_calls && edit.screen.active);
    assert(!ACTION(pw_launcher_pad_action(0x2000 | 0x4000)) && !edit.screen.active && !save_calls);
    assert(!ACTION(PW_LAUNCHER_ACTION_SETTINGS) && open_calls == 2);
    assert(edit.screen.draft.start_mode == PW_GAME_START_PROFILE);
    edit.screen.draft.touch_speed = 200; edit.screen.selected = PW_CONTROLLER_APPLY; save_failure = PW_ERR_VM;
    assert(!ACTION(PW_LAUNCHER_ACTION_CHOOSE) && edit.screen.active && save_calls == 1 && edit.screen.original.touch_speed == 100);
    save_failure = PW_OK;
    assert(!ACTION(PW_LAUNCHER_ACTION_CHOOSE) && !edit.screen.active && save_calls == 2 && feedback);
    open_failure = 1;
    assert(!ACTION(PW_LAUNCHER_ACTION_SETTINGS) && !edit.screen.active && feedback);
    open_failure = 0; wrong_id = 1;
    assert(!ACTION(PW_LAUNCHER_ACTION_SETTINGS) && !edit.screen.active && feedback);
    wrong_id = 0;
    assert(ACTION(PW_LAUNCHER_ACTION_CHOOSE)); /* only a fresh library activation launches */
    return 0;
}
'''
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory(prefix="pw-controller-launcher-") as temporary:
        path = Path(temporary)
        (path / "dispatch.c").write_text(harness)
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I.",
                        str(path / "dispatch.c"), "src/pw_controller_settings.c",
                        "src/pw_game_profile.c", "src/pw_app_profile.c", "src/pw_launcher_render.c",
                        "-o", str(path / "dispatch")], cwd=ROOT, check=True)
        subprocess.run([str(path / "dispatch")], check=True)
    def preprocessed(probe):
        return subprocess.check_output([cc, "-E", "-P", f"-DPW_NATIVE_CHILD_PROBE={probe}",
            "-Iinclude", "-Isrc", "-Inative", "native/wine64_main.c"], cwd=ROOT, text=True)
    normal, probe = preprocessed(0), preprocessed(1)
    launcher = normal.split("static void run_launcher(void)", 1)[1].split("int main(", 1)[0]
    assert launcher.count("prior_settings != controller_edit.screen.active") == 2
    assert "chosen < 0 && !controls_changed" in launcher
    assert "if (controls_changed) break;" in launcher
    assert "&& !controller_edit.screen.active" in launcher
    assert "pw_launcher_render_settings(&scene" in launcher
    probe_launcher = probe.split("static void run_launcher(void)", 1)[1].split("int main(", 1)[0]
    assert "controller_edit" not in probe_launcher
    assert "launcher_controller_control" not in probe_launcher
    assert "pw_launcher_render_controls(&scene" in probe_launcher
    print("controller launcher passed: real dispatch, modal batch barriers, probe isolation")


if __name__ == "__main__":
    main()
