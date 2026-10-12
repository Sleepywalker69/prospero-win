/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Real sink, with only pre-entry state seeded to exercise the fail-closed gate. */
#include "../wine/ps5/pw_wine_sink.c"
#include <assert.h>
#include <stdio.h>
static void seed(void)
{
    count=PW_WINE_INPUT_QUEUE;head=PW_WINE_INPUT_QUEUE-1;
    memset(queue,0x55,sizeof(queue));memset(&pad_state,0x55,sizeof(pad_state));
    pad_state.connected=1;rumble_left=100;rumble_right=200;rumble_changed=1;
}
static void empty(void)
{
    PwWinePad zero={0};PwWineInput nothing[PW_WINE_INPUT_QUEUE]={{0}};
    assert(!head&&!count&&!memcmp(queue,nothing,sizeof(queue)));
    assert(!memcmp(&pad_state,&zero,sizeof(zero)));
    assert(!rumble_left&&!rumble_right&&!rumble_changed);
}
int main(void)
{
    PwWineInput event={PW_WINE_INPUT_KEY,65,0,0,1},out;
    PwWinePad pad={.connected=1,.buttons=0xffff},seen;
    uint32_t left=1,right=1;
    for(unsigned api=0;api<7;api++) {
        seed();
        switch(api) {
        case 0: assert(pw_wine_post_input(&event)==-1);break;
        case 1: memset(&out,0xaa,sizeof(out));assert(!pw_wine_next_input(&out));break;
        case 2: pw_wine_set_pad(&pad);break;
        case 3: assert(!pw_wine_pad(&seen)&&!seen.connected&&!seen.buttons);break;
        case 4: pw_wine_set_rumble(10,20);break;
        case 5: assert(!pw_wine_rumble(&left,&right)&&!left&&!right);break;
        case 6: assert(pw_wine_input_fd()==-1);break;
        }
        empty();assert(wake[0]==-1&&wake[1]==-1);
    }
    for(unsigned type=PW_WINE_INPUT_KEY;type<=PW_WINE_INPUT_WINDOW_CYCLE;type++)
        for(unsigned edge=0;edge<2;edge++) {
            event.type=type;event.down=edge;assert(pw_wine_post_input(&event)==-1);
            assert(!pw_wine_next_input(&out));
        }
    assert(!stats.inputs_delivered&&!stats.inputs_posted);
    puts("neutral sink: seeded backlog, XInput, rumble, wake and all legacy event kinds refused");
    return 0;
}
