/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define PW_WINE_CHILD_UI_ENABLED 1
#define PW_WINE_CHILD_UI_COHORT 1
#define main legacy_title_controls
#include "test_pw_wine_child_title.c"
#undef main
int main(void)
{
    assert(!legacy_title_controls());reset();assert(!pw_wine_child_title_prepare(2,NULL));
    assert(captured.ui_frame&&captured.ui_retired&&PW_WINE_CHILD_UI_INPUT_ENABLED==0);
    PwWineChildUiIdentity id={captured.session,81,600};uint32_t pixel=0xff123456;
    assert(!captured.ui_frame(captured.context,id,&pixel,1,1,4));
    PwWineChildUiPreview view={0};assert(pw_wine_child_title_preview(&view)&&view.valid&&view.identity.native_pid==600);
    captured.ui_retired(captured.context,id);assert(pw_wine_child_title_preview(&view)&&!view.valid);
    reset();puts("child UI title: bounded tagged preview and exact-generation retirement passed");return 0;
}
