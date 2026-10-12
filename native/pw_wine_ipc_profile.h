/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_WINE_IPC_PROFILE_H
#define PW_WINE_IPC_PROFILE_H
#include <stddef.h>
#include "../wine/ps5/pw_wine_creation.h"
#ifndef PW_WINE_IPC_PROFILE_ENABLED
#define PW_WINE_IPC_PROFILE_ENABLED 0
#endif
#if PW_WINE_IPC_PROFILE_ENABLED != 0 && PW_WINE_IPC_PROFILE_ENABLED != 1
#error PW_WINE_IPC_PROFILE_ENABLED must be zero or one
#endif
#if PW_WINE_IPC_PROFILE_ENABLED && defined(PW_WINE_CHILD_UI_ENABLED) && PW_WINE_CHILD_UI_ENABLED
#error Child preview and IPC admission require separate matched cohorts
#endif
#define PW_WINE_IPC_PREFIX "/data/prospero-win/prefixes/windows-chromium-ipc-v1"
#define PW_WINE_IPC_SLUG "windows-chromium-ipc-v1"
enum { PW_WC_PROFILE_IPC_FIRST=PW_WINE_CREATION_IPC_FIRST,
       PW_WC_PROFILE_IPC_LAST=PW_WINE_CREATION_IPC_LAST };
typedef struct PwWineIpcProfile {
    const char *id,*image,*cwd,*native_image,*native_alias,*native_cwd;
    unsigned direct_children;
} PwWineIpcProfile;
/* Fixed identities, never a prefix/glob admission rule. Byte-identical images
 * from other cases are deliberately not interchangeable selected paths. */
static inline const PwWineIpcProfile *pw_wine_ipc_profile(unsigned mode)
{
    static const PwWineIpcProfile profiles[]={
        {"windows-chromium-ipc-self-memory-v1","C:\\windows-chromium-ipc\\pw-ipc-self-memory.exe",
         "C:\\windows-chromium-ipc\\self-memory",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-self-memory.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-self-memory.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/self-memory",0},
        {"windows-chromium-ipc-live-memory-v1","C:\\windows-chromium-ipc\\pw-ipc-live-memory.exe",
         "C:\\windows-chromium-ipc\\live-memory",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-live-memory.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-live-memory.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/live-memory",1},
        {"windows-chromium-ipc-suspended-memory-v1","C:\\windows-chromium-ipc\\pw-ipc-suspended-memory.exe",
         "C:\\windows-chromium-ipc\\suspended-memory",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-suspended-memory.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-suspended-memory.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/suspended-memory",1},
        {"windows-chromium-ipc-section-readonly-v1","C:\\windows-chromium-ipc\\pw-ipc-section-readonly.exe",
         "C:\\windows-chromium-ipc\\section-readonly",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-section-readonly.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-section-readonly.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/section-readonly",1},
        {"windows-chromium-ipc-section-duplicate-v1","C:\\windows-chromium-ipc\\pw-ipc-section-duplicate.exe",
         "C:\\windows-chromium-ipc\\section-duplicate",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-section-duplicate.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-section-duplicate.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/section-duplicate",1},
        {"windows-chromium-ipc-section-close-source-v1","C:\\windows-chromium-ipc\\pw-ipc-section-close-source.exe",
         "C:\\windows-chromium-ipc\\section-close-source",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-section-close-source.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-section-close-source.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/section-close-source",1},
        {"windows-chromium-ipc-mojo-pipe-v1","C:\\windows-chromium-ipc\\pw-ipc-mojo-pipe.exe",
         "C:\\windows-chromium-ipc\\mojo-pipe",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-mojo-pipe.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-mojo-pipe.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/mojo-pipe",1},
        {"windows-chromium-ipc-page-regression-v1","C:\\windows-chromium-ipc\\pw-ipc-page-regression.exe",
         "C:\\windows-chromium-ipc\\page-regression",PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/pw-ipc-page-regression.exe",
         PW_WINE_IPC_PREFIX "/dosdevices/c:/windows-chromium-ipc/pw-ipc-page-regression.exe",
         PW_WINE_IPC_PREFIX "/drive_c/windows-chromium-ipc/page-regression",0}
    };
    return mode>=PW_WC_PROFILE_IPC_FIRST&&mode<=PW_WC_PROFILE_IPC_LAST?
        &profiles[mode-PW_WC_PROFILE_IPC_FIRST]:NULL;
}
#endif
