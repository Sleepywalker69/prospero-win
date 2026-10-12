/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_child_ui_channel.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int terminal(PwWineChildUiChannel *q,int error)
{
    if(!q->error)q->error=error?error:EIO;
    atomic_store_explicit(&q->cancelled,1,memory_order_release);
    pw_wine_child_ui_tx_end(&q->tx);return -1;
}
/* Caller holds lock except during single-threaded initialization. */
static int now(PwWineChildUiChannel *q,uint64_t *out)
{
    uint64_t value;
    if(atomic_load_explicit(&q->cancelled,memory_order_acquire)||
       (q->stop&&q->stop(q->context)))return terminal(q,ECANCELED);
    if(q->clock_ms(q->context,&value)||value<q->last_clock)return terminal(q,EIO);
    q->last_clock=value;
    if(value>=q->lifetime_end||(q->queued&&value>=q->record_end))return terminal(q,ETIMEDOUT);
    *out=value;return 0;
}
static int enqueue(void *context,const void *bytes,size_t count)
{
    PwWineChildUiChannel *q=context;
    if(!q->building||count>q->capacity-q->used)return -1;
    memcpy(q->storage+q->used,bytes,count);q->used+=count;return 0;
}
int pw_wine_child_ui_channel_init(PwWineChildUiChannel *q,int *owned_fd,
                                 PwWineChildUiIdentity identity,unsigned kind,
                                 void *storage,size_t capacity,uint64_t lifetime_end,
                                 unsigned write_ms,int (*clock_ms)(void *,uint64_t *),
                                 int (*stop)(void *),void *context)
{
    if(!q||q->initialized||!owned_fd||*owned_fd<0||!storage||capacity<PW_WCU_HEADER+20||
       capacity>PW_WCU_HEADER+PW_WCU_MAX_BYTES||!lifetime_end||!write_ms||write_ms>1000||!clock_ms)return -1;
    PwWineChildUiTx tx;
    if(pw_wine_child_ui_tx_init(&tx,identity,kind,enqueue,q))return -1;
    uint64_t start;if(clock_ms(context,&start)||start>=lifetime_end||(stop&&stop(context)))return -1;
    int type=0;socklen_t bytes=sizeof(type);
    if(getsockopt(*owned_fd,SOL_SOCKET,SO_TYPE,&type,&bytes)||bytes!=sizeof(type)||type!=SOCK_STREAM)return -1;
    int flags=fcntl(*owned_fd,F_GETFD);if(flags<0||fcntl(*owned_fd,F_SETFD,flags|FD_CLOEXEC))return -1;
    int error=pthread_mutex_init(&q->lock,NULL);if(error)return -1;
    atomic_init(&q->cancelled,0);q->tx=tx;q->storage=storage;q->capacity=capacity;
    q->lifetime_end=lifetime_end;q->write_ms=write_ms;q->last_clock=start;
    q->clock_ms=clock_ms;q->stop=stop;q->context=context;q->fd=*owned_fd;
    q->initialized=1;*owned_fd=-1;return 0;
}
static int begin(PwWineChildUiChannel *q,int dropping_frame)
{
    uint64_t tick;
    if(q->queued||q->building)return dropping_frame?1:terminal(q,ENOBUFS);
    if(q->retired||now(q,&tick))return -1;
    uint64_t remaining=q->lifetime_end-tick;
    q->record_end=remaining<q->write_ms?q->lifetime_end:tick+q->write_ms;
    q->used=q->sent=0;q->building=1;return 0;
}
static int finish(PwWineChildUiChannel *q,int rc)
{
    q->building=0;
    if(rc){q->used=0;return terminal(q,ENOBUFS);}
    q->queued=1;uint64_t tick;
    if(now(q,&tick))return -1;
    return 0;
}
static int claim(PwWineChildUiChannel *q,int dropping_frame)
{
    if(!q||!q->initialized||atomic_load_explicit(&q->cancelled,memory_order_acquire))return -1;
    int error=pthread_mutex_trylock(&q->lock);
    if(error){if(error!=EBUSY||!dropping_frame)atomic_store_explicit(&q->cancelled,1,memory_order_release);return -1;}
    return 0;
}
int pw_wine_child_ui_channel_present(void *context,const void *pixels,uint32_t width,uint32_t height,uint32_t stride)
{
    PwWineChildUiChannel *q=context;if(claim(q,1))return -1;
    int rc=begin(q,1);
    if(!rc)rc=finish(q,pw_wine_child_ui_present(&q->tx,pixels,width,height,stride));
    pthread_mutex_unlock(&q->lock);return rc?-1:0;
}
int pw_wine_child_ui_channel_input(PwWineChildUiChannel *q,const PwWineInput *event)
{
    if(claim(q,0))return -1;
    int rc=begin(q,0);
    if(!rc)rc=finish(q,pw_wine_child_ui_send_input(&q->tx,event));
    pthread_mutex_unlock(&q->lock);return rc;
}
int pw_wine_child_ui_channel_pump(PwWineChildUiChannel *q)
{
    if(!q||!q->initialized)return -1;
    int error=pthread_mutex_trylock(&q->lock);if(error)return error==EBUSY?0:-1;
    uint64_t tick;int rc=now(q,&tick);
    if(!rc&&q->queued){
        size_t count=q->used-q->sent;if(count>65536)count=65536;
        ssize_t sent=send(q->fd,q->storage+q->sent,count,MSG_DONTWAIT|MSG_NOSIGNAL);
        int native_error=sent<0?errno:0;
        if(sent<0&&(native_error==EAGAIN||native_error==EWOULDBLOCK))rc=0;
        else if(sent<=0||(size_t)sent>count)rc=terminal(q,native_error);
        else {q->sent+=(size_t)sent;rc=1;}
        /* Retain the record deadline until the post-write check, including
         * the final write; a late full send is not reported as success. */
        if(now(q,&tick))rc=-1;
        if(rc>=0&&q->sent==q->used){q->queued=0;q->used=q->sent=0;}
    }
    pthread_mutex_unlock(&q->lock);return rc;
}
void pw_wine_child_ui_channel_cancel(PwWineChildUiChannel *q)
{
    if(q&&q->initialized)atomic_store_explicit(&q->cancelled,1,memory_order_release);
}
int pw_wine_child_ui_channel_retire(PwWineChildUiChannel *q,int (*detach)(void *),void *context)
{
    if(!q||!q->initialized)return -1;
    /* Owner-thread only; lifetime is process-long, including after retire. */
    if(q->retired)return q->close_uncertain?-1:0;
    pw_wine_child_ui_channel_cancel(q);
    if(!detach||detach(context)){q->detach_failed=1;return -1;}
    if(pthread_mutex_lock(&q->lock)){q->detach_failed=1;return -1;}
    q->detach_failed=0;pw_wine_child_ui_tx_end(&q->tx);
    int fd=q->fd;q->fd=-1;q->retired=1;q->queued=0;q->used=q->sent=0;
    int rc=close(fd),error=rc<0?errno:0;
    if(rc){q->close_uncertain=1;if(!q->error)q->error=error?error:EIO;}
    pthread_mutex_unlock(&q->lock);return rc?-1:0;
}
