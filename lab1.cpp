/*
 * 滑动窗口协议实验
 *
 * 作者：高乐耘 <seeson@pku.edu.cn>
 * 创建日期：2023年3月12日
 */

/*
 * 实验参数配置
 */
#define WINDOW_SIZE_STOP_WAIT     1
#define WINDOW_SIZE_BACK_N_FRAME  4

/*
 * 系统函数：发送帧
 *
 * pData: 指向要发送的帧的内容的指针
 * len:   要发送的帧的长度
 */
extern void SendFRAMEPacket(unsigned char *pData, unsigned int len);

#undef NDEBUG  /* activate assert */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#ifdef __unix__  /* 我的笔记本环境 */

#include <stdint.h>

/*
 * 固定大小的整形
 */
#define UINT8  uint8_t
#define UINT16 uint16_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define INT8   int8_t
#define INT16  int16_t
#define INT32  int32_t
#define INT64  int64_t

/*
 * 消息类型
 */
#define MSG_TYPE_TIMEOUT  1
#define MSG_TYPE_SEND     2
#define MSG_TYPE_RECEIVE  3

#else  /* __unix__ */

#include "sysinclude.h"

#endif  /* __unix__ */

/*
 * 帧类型
 */
#define FRAME_KIND_DATA  0
#define FRAME_KIND_ACK   1
#define FRAME_KIND_NAK   2

/*
 * 帧头
 */
typedef struct frame_head {
  UINT32 kind;              /* 大端帧类型 */
  UINT32 seq;               /* 大端序列号 */
  UINT32 ack;               /* 大端确认号 */
  unsigned char data[100];  /* 二进制数据 */
} frame_head;

/*
 * 全帧
 */
typedef struct frame {
  frame_head head;  /* 帧头 */
  UINT32 size;      /* 大端数据大小 */
} frame;

/*
 * 帮助函数：获取本机字节序
 *
 * 退回值
 *     0: 大端序，与网络一致
 *     1: 小端序，与网络不一致
 */
static UINT8 endian(void)
{
  UINT16 prob = 1;
  return *(UINT8 *)&prob;
}

/*
 * 帮助函数：改变字节序
 */
static UINT32 bswap32(UINT32 u32)
{
  UINT32 u0 = (u32 >> 24) & 0xff;
  UINT32 u1 = (u32 >> 16) & 0xff;
  UINT32 u2 = (u32 >>  8) & 0xff;
  UINT32 u3 = (u32 >>  0) & 0xff;
  return (u0 << 0) | (u1 << 8) | (u2 << 16) | (u3 << 24);
}

/*
 * 帮助函数：网络字节序 -> 主机字节序
 */
static UINT32 ntoh32(UINT32 u32)
{
  if(endian()) {  /* 应从大到小 */
    return bswap32(u32);
  }
  return u32;
}

/*
 * 帮助函数：主机字节序 -> 网络字节序
 */
static UINT32 hton32(UINT32 u32)
{
  return ntoh32(u32);
}

/*
 * 帮助函数：拷贝帧
 */
static frame *frame_dup(const frame *pframe)
{
  frame *p = (frame *)malloc(sizeof *p);  /* 需要 free() */
  assert(p != NULL);
  memcpy(p, pframe, sizeof *p);  /* frame 结构体可以直接二进制拷贝 */
  return p;
}

/*
 * 帧队列链表节点
 */
typedef struct flist_node {
  frame *pframe;            /* 帧内容的拷贝 */
  int flen;                 /* 帧长度 */
  struct flist_node *prev;  /* 上一节点 */
  struct flist_node *next;  /* 下一节点 */
} flist_node;

/*
 * 帧队列链表
 */
typedef struct flist {
  flist_node *head;  /* 头节点 */
  flist_node *tail;  /* 尾节点 */
  int size;          /* 节点数 */
} flist;

/*
 * 空帧队列链表，用于初始化新链表
 */
static const flist flist_empty = {
  NULL, NULL, 0
};

/*
 * 帮助函数：向帧队列链表尾部添加帧
 */
static void flist_push(flist *pflist, frame *pframe, int flen)
{
  /* 分配新节点 */
  flist_node *node = (flist_node *)malloc(sizeof *node);
  assert(node != NULL);

  /* 填充新节点 */
  node->pframe = frame_dup(pframe);
  node->flen = flen;
  node->prev = pflist->tail;
  node->next = NULL;

  /* 插入新节点 */
  if(pflist->tail == NULL) {
    pflist->head = pflist->tail = node;
  } else {
    pflist->tail = pflist->tail->next = node;
  }

  /* 更新节点数 */
  ++pflist->size;
}

/*
 * 帮助函数：从帧队列链表头部移除帧
 */
static void flist_pop(flist *pflist)
{
  /* 获取头节点 */
  flist_node *node = pflist->head;
  assert(node != NULL);

  /* 删除头节点 */
  pflist->head = node->next;
  if(pflist->head == NULL) {
    pflist->tail = NULL;
  } else {
    pflist->head->prev = NULL;
  }

  /* 释放节点所占有的内存资源 */
  free(node->pframe);
  free(node);

  /* 更新节点数 */
  --pflist->size;
}

/*
 * 帮助函数：打印帧队列链表
 */
static void flist_print(const flist *pflist)
{
  const flist_node *p;
  printf("*** %s:", __func__);
  if(pflist->head == NULL) {
    printf(" (empty)");
  } else {
    for(p = pflist->head; p; p = p->next) {
      printf(" %d", ntoh32(p->pframe->head.seq));
    }
  }
  printf("\n");
}

/*
 * 包装函数：发送帧
 */
void send_frame(frame *pframe, int flen)
{
  printf("*** %s: seq=%d flen=%d\n", __func__, ntoh32(pframe->head.seq), flen);
  SendFRAMEPacket((unsigned char *)pframe, (unsigned int)flen);
}

/*
 * 停等协议测试函数
 *
 * pBuffer:     指向系统要发送或接收到的帧内容的指针，或者指向超时消息中超时帧的序列号内容的指针
 * bufferSize:  pBuffer 表示内容的长度
 * messageType: 传入的消息类型，可以为以下几种情况
 *     MSG_TYPE_TIMEOUT  某个帧超时
 *     MSG_TYPE_SEND     系统要发送一个帧
 *     MSG_TYPE_RECEIVE  系统接收到一个帧的 ACK
 */
int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, UINT8 messageType)
{
  /* 发送队列链表 */
  static flist sndlst = flist_empty;

  /* 帧内容和长度 */
  frame *pframe;
  int flen;

  /* 超时帧的序列号 */
  UINT32 seq;

  switch(messageType) {

  case MSG_TYPE_TIMEOUT:  /* 某个帧超时 */

    /* 获取超时帧的序列号 */
    seq = *(UINT32 *)pBuffer;

    printf("*** %s: MSG_TYPE_TIMEOUT: seq=%d\n", __func__, seq);

    /* 该序列号必定与发送队头相等 */
    assert(sndlst.head != NULL && ntoh32(sndlst.head->pframe->head.seq) == seq);

    /* 获取帧内容和长度 */
    pframe = sndlst.head->pframe;
    flen = sndlst.head->flen;

    /* 重发该帧 */
    send_frame(pframe, flen);

    break;

  case MSG_TYPE_SEND:  /* 系统要发送一个帧 */

    /* 获取帧内容和长度 */
    pframe = (frame *)pBuffer;
    flen = bufferSize;

    printf("*** %s: MSG_TYPE_SEND: seq=%d\n", __func__, ntoh32(pframe->head.seq));

    /* 将当前帧压入队列链表 */
    flist_push(&sndlst, pframe, flen);

    /* 如果队列链表中没有等待 ACK 的帧，发送当前帧 */
    if(sndlst.size == 1) {
      send_frame(pframe, flen);
    }

    break;

  case MSG_TYPE_RECEIVE:  /* 系统接收到一个帧的 ACK */

    /* 获取帧内容和长度 */
    pframe = (frame *)pBuffer;
    flen = bufferSize;

    printf("*** %s: MSG_TYPE_RECEIVE: ack=%d\n", __func__, ntoh32(pframe->head.ack));

    /* 检查 ACK 是否与 SEQ 对应 */
    if(sndlst.size == 0) break;
    if(pframe->head.ack != sndlst.head->pframe->head.seq) {
      break;
    }

    /* 如果对应，则移除发送队列链表头 */
    flist_pop(&sndlst);

    /* 没有其它排队任务时才退回 */
    if(sndlst.size == 0) break;

    /* 获取帧内容和长度 */
    pframe = sndlst.head->pframe;
    flen = sndlst.head->flen;

    /* 发送该帧 */
    send_frame(pframe, flen);

    break;

  }

  flist_print(&sndlst);
  return 0;  /* XXX */
}

/*
 * 回退 N 帧协议测试函数
 *
 * pBuffer:     指向系统要发送或接收到的帧内容的指针，或者指向超时消息中超时帧的序列号内容的指针
 * bufferSize:  pBuffer 表示内容的长度
 * messageType: 传入的消息类型，可以为以下几种情况
 *     MSG_TYPE_TIMEOUT  某个帧超时
 *     MSG_TYPE_SEND     系统要发送一个帧
 *     MSG_TYPE_RECEIVE  系统接收到一个帧的 ACK
 */
int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, UINT8 messageType)
{
  /* 发送队列链表 */
  static flist sndlst = flist_empty;

  /* 当前已发送且等待 ACK 的帧数 */
  static int nwaiting = 0;

  /* 对应第一个被挂起等待发送的帧 */
  static flist_node *first_pending = NULL;

  /* 发送链表节点指针 */
  flist_node *p;

  /* 帧内容和长度 */
  frame *pframe;
  int flen;

  /* 超时帧的序列号 */
  UINT32 seq;

  switch(messageType) {

  case MSG_TYPE_TIMEOUT:  /* 某个帧超时 */

    /* 获取超时帧的序列号 */
    seq = *(UINT32 *)pBuffer;

    printf("*** %s: MSG_TYPE_TIMEOUT: seq=%d\n", __func__, seq);

    /* 从发送链表中找到超时帧 */
    for(p = sndlst.head; p != first_pending; p = p->next) {
      if(p->pframe->head.seq == hton32(seq)) break;
    }
    assert(p != first_pending);

#if 0
    /* 重发其后的所有帧并重新计算等待帧数 */
    nwaiting = 0;
    for(; p; p = p->next) {
      send_frame(p->pframe, p->flen);
      ++nwaiting;

      /* 如果发送窗口占满，则挂起之后的发送请求 */
      if(nwaiting == WINDOW_SIZE_BACK_N_FRAME) {
        first_pending = p->next;
        break;
      }
    }
#endif  /* 0 */

    /* 重发发送窗口中的所有帧 */
    for(p = sndlst.head; p != first_pending; p = p->next) {
      send_frame(p->pframe, p->flen);
    }

    break;

  case MSG_TYPE_SEND:  /* 系统要发送一个帧 */

    /* 获取帧内容和长度 */
    pframe = (frame *)pBuffer;
    flen = bufferSize;

    printf("*** %s: MSG_TYPE_SEND: seq=%d\n", __func__, ntoh32(pframe->head.seq));

    /* 将当前帧压入队列链表 */
    flist_push(&sndlst, pframe, flen);

    /* 如果当前帧落在发送窗口内，发送当前帧，并更新等待计数 */
    if(nwaiting < WINDOW_SIZE_BACK_N_FRAME) {
      send_frame(pframe, flen);
      ++nwaiting;
    } else if(first_pending == NULL) {  /* 当前帧为首个被挂起帧 */
      first_pending = sndlst.tail;
    }

    break;

  case MSG_TYPE_RECEIVE:  /* 系统接收到一个帧的 ACK */

    /* 获取帧内容和长度 */
    pframe = (frame *)pBuffer;
    flen = bufferSize;

    printf("*** %s: MSG_TYPE_RECEIVE: ack=%d\n", __func__, ntoh32(pframe->head.ack));

    /* 按照累计确认原则在发送队列中寻找匹配 */
    if(sndlst.size != 0) {
      for(p = sndlst.head; p != first_pending; p = p->next) {
        if(p->pframe->head.seq == pframe->head.ack) {
          break;
        }
      }

      /* 没有找到匹配，则什么也不做 */
      if(p == first_pending) break;

      /* 弹出 p 前所有的节点 */
      while(sndlst.head != p) {
        flist_pop(&sndlst);
        --nwaiting;
      }

      /* 弹出 p */
      flist_pop(&sndlst);
      --nwaiting;
    }

    /* 当发送窗口未充满时，唤醒挂起的发送任务 */
    while(first_pending && nwaiting < WINDOW_SIZE_BACK_N_FRAME) {

      /* 获取帧内容和长度 */
      pframe = first_pending->pframe;
      flen = first_pending->flen;

      /* 更新首个等待位置，即发送窗口右沿右移 1 单位 */
      first_pending = first_pending->next;

      /* 发送该帧 */
      send_frame(pframe, flen);
      ++nwaiting;
    }

    break;

  }

  flist_print(&sndlst);
  return 0;  /* XXX */
}

/*
 * 选择性重传协议测试函数
 *
 * pBuffer:     指向系统要发送或接收到的帧内容的指针，或者指向超时消息中超时帧的序列号内容的指针
 * bufferSize:  pBuffer 表示内容的长度
 * messageType: 传入的消息类型，可以为以下几种情况
 *     MSG_TYPE_SEND     系统要发送一个帧
 *     MSG_TYPE_RECEIVE  系统接收到一个帧的 ACK 或 NAK
 */
int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, UINT8 messageType)
{
  /* 发送队列链表 */
  static flist sndlst = flist_empty;

  /* 当前已发送且等待 ACK 的帧数 */
  static int nwaiting = 0;

  /* 对应第一个被挂起等待发送的帧 */
  static flist_node *first_pending = NULL;

  /* 发送链表节点指针 */
  flist_node *p;

  /* 帧内容和长度 */
  frame *pframe;
  int flen;

  switch(messageType) {

  case MSG_TYPE_SEND:  /* 系统要发送一个帧 */

    /* 获取帧内容和长度 */
    pframe = (frame *)pBuffer;
    flen = bufferSize;

    printf("*** %s: MSG_TYPE_SEND: seq=%d\n", __func__, ntoh32(pframe->head.seq));

    /* 将当前帧压入队列链表 */
    flist_push(&sndlst, pframe, flen);

    /* 如果当前帧落在发送窗口内，发送当前帧，并更新等待计数 */
    if(nwaiting < WINDOW_SIZE_BACK_N_FRAME) {
      send_frame(pframe, flen);
      ++nwaiting;
    } else if(first_pending == NULL) {  /* 当前帧为首个被挂起帧 */
      first_pending = sndlst.tail;
    }

    break;

  case MSG_TYPE_RECEIVE:  /* 系统接收到一个帧的 ACK 或 NAK */

    /* 获取帧内容和长度 */
    pframe = (frame *)pBuffer;
    flen = bufferSize;

    if(ntoh32(pframe->head.kind) == FRAME_KIND_ACK) {  /* 系统接收到一个帧的 ACK */

      printf("*** %s: MSG_TYPE_RECEIVE: ack=%d (FRAME_KIND_ACK)\n", __func__, ntoh32(pframe->head.ack));

      /* 按照累计确认原则在发送队列中寻找匹配 */
      if(sndlst.size != 0) {
        for(p = sndlst.head; p != first_pending; p = p->next) {
          if(p->pframe->head.seq == pframe->head.ack) {
            break;
          }
        }

        /* 没有找到匹配，则什么也不做 */
        if(p == first_pending) break;

        /* 弹出 p 前所有的节点 */
        while(sndlst.head != p) {
          flist_pop(&sndlst);
          --nwaiting;
        }

        /* 弹出 p */
        flist_pop(&sndlst);
        --nwaiting;
      }

      /* 当发送窗口未充满时，唤醒挂起的发送任务 */
      while(first_pending && nwaiting < WINDOW_SIZE_BACK_N_FRAME) {

        /* 获取帧内容和长度 */
        pframe = first_pending->pframe;
        flen = first_pending->flen;

        /* 更新首个等待位置，即发送窗口右沿右移 1 单位 */
        first_pending = first_pending->next;

        /* 发送该帧 */
        send_frame(pframe, flen);
        ++nwaiting;
      }

    } else {  /* 系统接收到一个帧的 NAK */

      printf("*** %s: MSG_TYPE_RECEIVE: ack=%d (FRAME_KIND_NAK)\n", __func__, ntoh32(pframe->head.ack));

      /* 在发送队列中寻找匹配 */
      for(p = sndlst.head; p != first_pending; p = p->next) {
        if(p->pframe->head.seq == pframe->head.ack) {
          break;
        }
      }
      assert(p != first_pending);

      /* 重发该帧 */
      send_frame(p->pframe, p->flen);

    }

    break;

  }

  flist_print(&sndlst);
  return 0;  /* XXX */
}

#if __cplusplus >= 201703  /* 我的笔记本/机房台式机编译环境 */

/*
 * 本地测试
 */
int main(void)
{
  printf("Hello from %s()!\n", __func__);
  assert(endian() == 1);
  assert(ntoh32(0x01000000) == 1);
  assert(hton32(0x01000000) == 1);
  return 0;
}

/*
 * 构造空壳函数以通过编译
 */
void SendFRAMEPacket(unsigned char *pData, unsigned int len)
{
  assert(pData != NULL);
  assert(len != 0);
}

#endif  /* __cplusplus >= 201703 */
