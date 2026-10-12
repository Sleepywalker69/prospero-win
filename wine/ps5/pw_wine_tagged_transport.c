/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_tagged_transport.h"
#include <string.h>

int pw_tagged_init(PwTaggedTransport *t,const PwTaggedSourceConfig *config,unsigned sources)
{
    if(!t)return PW_TAGGED_INVALID;
    memset(t,0,sizeof(*t));
    if(!config || !sources || sources>PW_TAGGED_SOURCES)return PW_TAGGED_INVALID;
    for(unsigned i=0;i<sources;i++)
        if(!config[i].session || !config[i].epoch)return PW_TAGGED_INVALID;
    if(pthread_mutex_init(&t->lock,NULL))return PW_TAGGED_INVALID;
    for(unsigned i=0;i<sources;i++) {
        t->source[i].session=config[i].session;
        t->source[i].epoch=config[i].epoch;
    }
    t->sources=sources;t->initialized=1;
    return PW_TAGGED_OK;
}
int pw_tagged_destroy(PwTaggedTransport *t)
{
    if(!t || !t->initialized)return PW_TAGGED_INVALID;
    if(pthread_mutex_destroy(&t->lock))return PW_TAGGED_INVALID;
    t->initialized=0;
    return PW_TAGGED_OK;
}
static int valid_event(const PwWineInput *e)
{
    switch(e->type) {
    case PW_WINE_INPUT_KEY:return e->code>0 && e->code<256 && e->down<=1;
    case PW_WINE_INPUT_MOUSE_MOVE:return 1;
    case PW_WINE_INPUT_MOUSE_BUTTON:return e->code<=2 && e->down<=1;
    case PW_WINE_INPUT_WINDOW_CYCLE:
        return !e->code && (e->x==1 || e->x==-1) && !e->y && e->down==1;
    default:return 0;
    }
}
int pw_tagged_post(PwTaggedTransport *t,const PwTaggedInput *input)
{
    int result=PW_TAGGED_INVALID;
    if(!t || !t->initialized || !input)return result;
    pthread_mutex_lock(&t->lock);
    if(input->abi==PW_TAGGED_ABI && input->size==sizeof(*input) &&
       !input->reserved && !input->reserved_tail &&
       input->source<t->sources && input->source<PW_TAGGED_SOURCES &&
       input->sequence && valid_event(&input->event)) {
        PwTaggedSource *s=&t->source[input->source];
        if(input->session!=s->session || input->epoch!=s->epoch)
            result=PW_TAGGED_STALE;
        else if(s->closed)result=PW_TAGGED_CLOSED;
        else if(input->sequence<=s->last_sequence)result=PW_TAGGED_STALE;
        else if(t->count==PW_TAGGED_CAPACITY)result=PW_TAGGED_FULL;
        else {
            t->queue[(t->head+t->count)%PW_TAGGED_CAPACITY]=*input;
            t->count++;s->last_sequence=input->sequence;result=PW_TAGGED_OK;
        }
    }
    pthread_mutex_unlock(&t->lock);
    return result;
}
int pw_tagged_next(PwTaggedTransport *t,PwTaggedInput *output)
{
    int result=PW_TAGGED_EMPTY;
    if(!t || !t->initialized || !output)return PW_TAGGED_INVALID;
    pthread_mutex_lock(&t->lock);
    if(t->count) {
        *output=t->queue[t->head];
        result=t->source[output->source].closed?PW_TAGGED_CANCELLED:PW_TAGGED_DATA;
        t->head=(t->head+1)%PW_TAGGED_CAPACITY;t->count--;
    }
    pthread_mutex_unlock(&t->lock);
    return result;
}
int pw_tagged_close_source(PwTaggedTransport *t,uint32_t source,
                           uint64_t session,uint64_t original_epoch,PwTaggedReset *output)
{
    int result=PW_TAGGED_STALE;
    if(!t || !t->initialized || !output ||
       source>=t->sources || source>=PW_TAGGED_SOURCES)return PW_TAGGED_INVALID;
    pthread_mutex_lock(&t->lock);
    PwTaggedSource *s=&t->source[source];
    if(session==s->session &&
       original_epoch==(s->closed?s->reset.old_epoch:s->epoch)) {
        if(!s->closed) {
            s->reset=(PwTaggedReset){source,s->epoch==UINT64_MAX,s->session,
                                    s->epoch,s->epoch,s->last_sequence};
            if(s->epoch!=UINT64_MAX)s->epoch++;
            s->reset.new_epoch=s->epoch;s->closed=1;s->pending=1;
        }
        *output=s->reset;result=PW_TAGGED_OK;
    }
    pthread_mutex_unlock(&t->lock);
    return result;
}
int pw_tagged_next_reset(PwTaggedTransport *t,PwTaggedReset *output)
{
    int result=PW_TAGGED_EMPTY;
    if(!t || !t->initialized || !output)return PW_TAGGED_INVALID;
    pthread_mutex_lock(&t->lock);
    for(unsigned i=0;i<t->sources;i++)if(t->source[i].pending) {
        *output=t->source[i].reset;t->source[i].pending=0;result=1;break;
    }
    pthread_mutex_unlock(&t->lock);
    return result;
}
