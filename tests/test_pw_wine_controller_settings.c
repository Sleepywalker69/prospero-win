/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../native/pw_wine_controller_settings.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define APP "[application]\nid = demo\nname = Demo\nexecutable = C:\\Game.exe\n" \
    "working_directory = C:\\\nprefix = default\nruntime = wine-wow64\narchitecture = pe32\ngraphics = gdi\n"
static const char original[] = APP "# retained\n[display]\nscaling = integer\n[input]\npreset = demo\n"
    "cross = enter\nui_circle = q\n[debug]\nwinedebug = +seh\n[runtime]\nshared_input = true\n";
static char root[] = "/tmp/pw-settings-XXXXXX", path[256], temporary[272];
static int failure, writes, temp_fd = -1;
enum { FAIL_WRITE = 1, FAIL_ZERO, FAIL_SYNC, FAIL_CLOSE, FAIL_RENAME, CHANGE_FILE, SHORT_WRITE, INTERRUPT_WRITE };
ssize_t __real_write(int fd, const void *bytes, size_t count);
int __real_fsync(int fd);
int __real_close(int fd);
int __real_rename(const char *a, const char *b);
ssize_t __wrap_write(int fd, const void *bytes, size_t count)
{
    temp_fd = fd; writes++;
    if (failure == FAIL_WRITE) { errno = ENOSPC; return -1; }
    if (failure == FAIL_ZERO) return 0;
    if (failure == INTERRUPT_WRITE && writes == 1) { errno = EINTR; return -1; }
    if (failure == SHORT_WRITE && count > 7) count = 7;
    return __real_write(fd, bytes, count);
}
static void write_file(const char *file, const char *text)
{
    FILE *f = fopen(file, "wb"); assert(f && fputs(text, f) >= 0 && !fclose(f));
}
int __wrap_fsync(int fd)
{
    if (failure == FAIL_SYNC) { errno = EIO; return -1; }
    if (failure == CHANGE_FILE) write_file(path, APP "# external edit\n");
    return __real_fsync(fd);
}
int __wrap_close(int fd)
{
    int was_temp = fd == temp_fd;
    if (was_temp) temp_fd = -1;
    int result = __real_close(fd);
    if (was_temp && failure == FAIL_CLOSE) { errno = EIO; return -1; }
    return result;
}
int __wrap_rename(const char *a, const char *b)
{
    if (failure == FAIL_RENAME) { errno = EACCES; return -1; }
    return __real_rename(a, b);
}
static void matches(const char *file, const char *expected)
{
    char content[PW_APP_PROFILE_MAX_BYTES + 1]; FILE *f = fopen(file, "rb"); assert(f);
    size_t length = fread(content, 1, sizeof(content), f); assert(!ferror(f) && !fclose(f));
    assert(length == strlen(expected) && !memcmp(content, expected, length));
}
static void basics(void)
{
    PwWineControllerEdit edit, snapshot;
    struct stat info;
    assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
    assert(edit.preset_status == PW_OK && edit.screen.active);
    assert(edit.screen.original.mouse_speed == 2100 && edit.screen.original.mouse_deadzone == 16 &&
           edit.screen.original.touch_speed == 125 && edit.screen.original.start_mode == PW_GAME_START_MOUSE);
    snapshot = edit;
    /* No changed values means no profile rewrite or new override. */
    assert(pw_wine_controller_edit_save(&edit, &edit.screen.original, 0) == PW_OK && !writes);
    matches(path, original);
    PwControllerValues wanted = edit.screen.original; wanted.touch_speed = 200;
    assert(pw_wine_controller_edit_save(&edit, &wanted, PW_CONTROLLER_TOUCH) == PW_OK);
    const char *expected = APP "# retained\n[display]\nscaling = integer\n[input]\npreset = demo\n"
        "cross = enter\nui_circle = q\ntouch_speed = 200\n[debug]\nwinedebug = +seh\n[runtime]\nshared_input = true\n";
    matches(path, expected); assert(access(temporary, F_OK) != 0);
    assert(!stat(path, &info) && (info.st_mode & 0777) == 0640);
    assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
    assert(edit.screen.original.touch_speed == 200 && edit.screen.original.mouse_speed == 2100);
    assert(edit.profile.display.scaling == PW_GAME_SCALING_INTEGER && edit.profile.runtime.shared_input == 1);
    /* Unchanged inherited values remain inherited, including future preset edits. */
    char preset[256]; snprintf(preset, sizeof(preset), "%s/input/demo.input", root);
    write_file(preset, "[input]\nstart_mode = profile\nmouse_deadzone = 18\nmouse_speed = 3100\ntouch_speed = 175\n");
    assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
    assert(edit.screen.original.mouse_speed == 3100 && edit.screen.original.mouse_deadzone == 18 &&
           edit.screen.original.start_mode == PW_GAME_START_PROFILE && edit.screen.original.touch_speed == 200);
    wanted = edit.screen.original; wanted.touch_speed = 0;
    snapshot = edit; writes = 0;
    assert(pw_wine_controller_edit_save(&edit, &wanted, PW_CONTROLLER_TOUCH) == PW_ERR_MALFORMED);
    assert(!writes && !memcmp(&edit, &snapshot, sizeof(edit))); matches(path, expected);
    /* Safe name checks, symlink refusal and regular-file check. */
    assert(pw_wine_controller_edit_open(&edit, root, "../demo.profile") == PW_ERR_MALFORMED);
    assert(!memcmp(&edit, &snapshot, sizeof(edit)));
    char link[256]; snprintf(link, sizeof(link), "%s/profiles/link.profile", root);
    assert(!symlink(path, link));
    assert(pw_wine_controller_edit_open(&edit, root, "link.profile") != PW_OK);
    assert(!unlink(link));
    assert(!mkfifo(link, 0600));
    assert(pw_wine_controller_edit_open(&edit, root, "link.profile") != PW_OK);
    assert(!unlink(link));
    /* The edit snapshot does not permit stale overwrites. */
    write_file(path, original); writes = 0;
    wanted = snapshot.screen.original; wanted.touch_speed = 300;
    assert(pw_wine_controller_edit_save(&snapshot, &wanted, PW_CONTROLLER_TOUCH) == PW_ERR_STATE && !writes);
    matches(path, original);
}
static void failures(void)
{
    PwWineControllerEdit edit, snapshot;
    for (int test = FAIL_WRITE; test <= CHANGE_FILE; test++) {
        failure = 0; writes = 0; write_file(path, original);
        assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
        snapshot = edit; PwControllerValues wanted = edit.screen.original; wanted.touch_speed = 333;
        failure = test;
        assert(pw_wine_controller_edit_save(&edit, &wanted, PW_CONTROLLER_TOUCH) ==
               (test == CHANGE_FILE ? PW_ERR_STATE : PW_ERR_VM));
        assert(!memcmp(&edit, &snapshot, sizeof(edit)));
        matches(path, test == CHANGE_FILE ? APP "# external edit\n" : original);
        assert(access(temporary, F_OK) != 0);
    }
    failure = 0; writes = 0; write_file(path, original);
    assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
    PwControllerValues wanted = edit.screen.original; wanted.touch_speed = 333;
    write_file(temporary, "PREVIOUS TEMPORARY MUST SURVIVE");
    assert(pw_wine_controller_edit_save(&edit, &wanted, PW_CONTROLLER_TOUCH) == PW_ERR_VM && !writes);
    matches(path, original); matches(temporary, "PREVIOUS TEMPORARY MUST SURVIVE");
    assert(!unlink(temporary));
    for (int test = SHORT_WRITE; test <= INTERRUPT_WRITE; test++) {
        failure = 0; writes = 0; write_file(path, original);
        assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
        failure = test;
        assert(pw_wine_controller_edit_save(&edit, &wanted, PW_CONTROLLER_TOUCH) == PW_OK && writes > 1);
        assert(access(temporary, F_OK) != 0);
        failure = 0;
        assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
        assert(edit.screen.original.touch_speed == 333);
    }
    /* Preset refusal uses the same fallback values as a launch. */
    write_file(path, APP "[input]\npreset = missing\nmouse_speed = 2345\n");
    assert(pw_wine_controller_edit_open(&edit, root, "demo.profile") == PW_OK);
    assert(edit.preset_status == PW_ERR_NOT_FOUND && edit.screen.original.mouse_speed == 2345 &&
           edit.screen.original.touch_speed == 100);
}
int main(void)
{
    assert(mkdtemp(root));
    char directory[256]; snprintf(directory, sizeof(directory), "%s/profiles", root); assert(!mkdir(directory, 0755));
    snprintf(directory, sizeof(directory), "%s/input", root); assert(!mkdir(directory, 0755));
    snprintf(path, sizeof(path), "%s/profiles/demo.profile", root);
    snprintf(temporary, sizeof(temporary), "%s.settings.tmp", path);
    write_file(path, original); assert(!chmod(path, 0640));
    char preset[256]; snprintf(preset, sizeof(preset), "%s/input/demo.input", root);
    write_file(preset, "[input]\nstart_mode = mouse\nmouse_deadzone = 16\nmouse_speed = 2100\ntouch_speed = 125\n");
    basics(); failures();
    assert(!unlink(path) && !unlink(preset));
    assert(!rmdir(directory)); snprintf(directory, sizeof(directory), "%s/profiles", root);
    assert(!rmdir(directory) && !rmdir(root));
    puts("native controller settings passed"); return 0;
}
