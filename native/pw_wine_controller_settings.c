/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_controller_settings.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_profile(const char *path, uint8_t *bytes, size_t *length, struct stat *info)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    int status = PW_ERR_VM;
    size_t used = 0;
    if (fd < 0) return PW_ERR_NOT_FOUND;
    if (fstat(fd, info) || !S_ISREG(info->st_mode)) goto done;
    while (used < PW_APP_PROFILE_MAX_BYTES) {
        ssize_t count = read(fd, bytes + used, PW_APP_PROFILE_MAX_BYTES - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (!count) { *length = used; status = PW_OK; goto done; }
        used += (size_t)count;
    }
    status = PW_ERR_LIMIT;
done:
    if (close(fd) && status == PW_OK) status = PW_ERR_VM;
    return status;
}
static int filename(const char *file)
{
    size_t length = strlen(file);
    if (length <= 8 || length >= PW_WINE_LIBRARY_NAME || strcmp(file + length - 8, ".profile")) return 0;
    for (size_t i = 0; i < length - 8; i++)
        if (!((file[i] >= 'a' && file[i] <= 'z') || (file[i] >= '0' && file[i] <= '9') ||
              file[i] == '-' || file[i] == '_')) return 0;
    return 1;
}
int pw_wine_controller_edit_open(PwWineControllerEdit *edit, const char *root, const char *file)
{
    PwWineControllerEdit opened;
    PwGameInput input;
    struct stat info;
    int status, length;
    if (!edit || !root || !*root || !file) return PW_ERR_PRECONDITION;
    if (!filename(file)) return PW_ERR_MALFORMED;
    memset(&opened, 0, sizeof(opened));
    length = snprintf(opened.path, sizeof(opened.path), "%s/profiles/%s", root, file);
    if (length < 0 || length >= (int)sizeof(opened.path)) return PW_ERR_LIMIT;
    if ((status = read_profile(opened.path, opened.before, &opened.before_length, &info)) != PW_OK ||
        (status = pw_game_profile_parse(opened.before, opened.before_length, &opened.profile)) != PW_OK)
        return status;
    opened.preset_status = pw_wine_library_input(&opened.profile, root, &input);
    /* A refused preset already falls back to the validated profile's lines. */
    if ((status = pw_controller_settings_open(&opened.screen, &input)) != PW_OK) return status;
    *edit = opened;
    return PW_OK;
}
int pw_wine_controller_edit_save(void *context, const PwControllerValues *values, uint32_t fields)
{
    PwWineControllerEdit *edit = context;
    uint8_t current[PW_APP_PROFILE_MAX_BYTES], updated[PW_APP_PROFILE_MAX_BYTES];
    size_t current_length = 0, updated_length = 0, written = 0;
    struct stat original, latest;
    PwGameProfile profile;
    char temporary[PW_WINE_LIBRARY_PATH + PW_WINE_LIBRARY_NAME + 16];
    int status, fd = -1, length;
    if (!edit || !values || !edit->path[0] || !edit->before_length) return PW_ERR_PRECONDITION;
    if ((status = pw_controller_profile_update(edit->before, edit->before_length, values, fields,
                                               updated, sizeof(updated), &updated_length)) != PW_OK) return status;
    if ((status = read_profile(edit->path, current, &current_length, &original)) != PW_OK) return status;
    if (current_length != edit->before_length || memcmp(current, edit->before, current_length)) return PW_ERR_STATE;
    if (!fields || (updated_length == current_length && !memcmp(updated, current, current_length))) return PW_OK;
    if ((status = pw_game_profile_parse(updated, updated_length, &profile)) != PW_OK) return status;
    length = snprintf(temporary, sizeof(temporary), "%s.settings.tmp", edit->path);
    if (length < 0 || length >= (int)sizeof(temporary)) return PW_ERR_LIMIT;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return PW_ERR_VM;
    status = PW_ERR_VM;
    while (written < updated_length) {
        ssize_t count = write(fd, updated + written, updated_length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto failed;
        written += (size_t)count;
    }
    if (fchmod(fd, original.st_mode & 0777) || fsync(fd)) goto failed;
    if (close(fd)) { fd = -1; goto failed; }
    fd = -1;
    if (read_profile(edit->path, current, &current_length, &latest) != PW_OK) goto failed;
    if (latest.st_dev != original.st_dev || latest.st_ino != original.st_ino ||
        current_length != edit->before_length || memcmp(current, edit->before, current_length)) {
        status = PW_ERR_STATE; goto failed;
    }
    if (rename(temporary, edit->path)) goto failed;
    memcpy(edit->before, updated, updated_length); edit->before_length = updated_length;
    edit->profile = profile;
    return PW_OK;
failed:
    if (fd >= 0) (void)close(fd);
    (void)unlink(temporary); /* only the exclusive sibling created by this call */
    return status;
}
