/*
 * TCP 协议实验
 *
 * 客户端 TCP I/O 的停等实现
 *
 * 作者：高乐耘 <seeson@pku.edu.cn>
 * 创建日期：2023年4月22日
 */

#undef NDEBUG  /* activate assert */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
# include <winsock.h>  // compile and link with: -lws2_32
#else  /* WIN32 */
# include <arpa/inet.h>
#endif  /* WIN32 */

#ifdef __unix__  /* 我的笔记本环境 */

#include <stdint.h>

/*
 * 固定大小的整形
 */
#define UINT8   uint8_t
#define UINT16  uint16_t
#define UINT32  uint32_t

#define INT8    int8_t
#define INT16   int16_t
#define INT32   int32_t

/*
 * 丢弃报文的原因
 */
#define STUD_TCP_TEST_SEQNO_ERROR    1
#define STUD_TCP_TEST_SRCPORT_ERROR  2
#define STUD_TCP_TEST_DSTPORT_ERROR  3

#else  /* __unix__ */

#include "sysinclude.h"

#endif  /* __unix__ */

/* 修正系统中错误的定义 */
#undef  UINT64
#undef  INT64
#define UINT64  uint64_t
#define INT64   int64_t

/*
 * 参数配置
 */
#define SOCKFD_MAX  256

/*
 * 全局变量
 */
int gSrcPort = 2007;
int gDstPort = 2006;
int gSeqNum = 0;
int gAckNum = 0;

/*
 * 系统函数
 */
extern void tcp_DiscardPkt(char *buf, int type);
extern void tcp_sendReport(int type);
extern void tcp_sendIpPkt(unsigned char *data, UINT16 len,
    UINT32 srcaddr, UINT32 dstaddr, UINT8 ttl);
extern int waitIpPacket(char *buf, int timeout);
extern unsigned int getIpv4Address(void);
extern unsigned int getServerIpv4Address(void);

/*
 * TCP 报头
 */
typedef struct tcphdr {
  UINT16 srcport;
  UINT16 dstport;
  UINT32 seq;
  UINT32 ack;
  UINT16 flags;
  UINT16 win;
  UINT16 cs;
  UINT16 up;
  char op[0];
} tcphdr;

/*
 * TCP 标志掩码
 */
#define TCP_FIN  (1 << 0)
#define TCP_SYN  (1 << 1)
#define TCP_RST  (1 << 2)
#define TCP_PSH  (1 << 3)
#define TCP_ACK  (1 << 4)
#define TCP_URG  (1 << 5)
#define TCP_FLG  (0x3f)

/*
 * 主机字节序下的 TCP 头长度访问
 */
#define TCP_ENC_THL(thl)  ((UINT16)(((((UINT16)(thl) + 3) >> 2) & 15) << 12))
#define TCP_DEC_THL(flags)  ((UINT16)((UINT16)(flags) >> 12 << 2))

/*
 * 获取 TCP 校验和
 */
UINT16 tcp_cs(const tcphdr *hdr, UINT16 siz, UINT32 src, UINT32 dst)
{
  UINT64 cs = htonl(src) + htonl(dst) + htons(17) + htons(siz);
  size_t n = siz >> 2;
  UINT32 *p = (UINT32 *)hdr, rem = 0;
  asm("":::"memory");  // 在 strict aliasing 下充当内存屏障
  for(size_t i = 0; i < n; ++i) cs += p[i];
  for(size_t i = siz; i & 3; --i) {
    ((char *)&rem)[(i - 1) & 3] = ((char *)hdr)[i - 1];
  }
  cs += rem;
  cs = (cs & 0xffffffff) + (cs >> 32);
  cs = (cs & 0xffffffff) + (cs >> 32);
  cs = (cs & 0xffff) + (cs >> 16);
  cs = (cs & 0xffff) + (cs >> 16);
  return ~cs;
}

/*
 * TCP 状态
 */
typedef enum tcpstat {
  TCP_CLOSED,
  TCP_LISTEN,       /* S */
  TCP_SYN_SENT,     /* C */
  TCP_SYN_RCVD,     /* S */
  TCP_ESTABLISHED,
  TCP_FIN_WAIT_1,   /* C */
  TCP_CLOSE_WAIT,   /* S */
  TCP_FIN_WAIT_2,   /* C */
  TCP_LAST_ACK,     /* S */
  TCP_TIME_WAIT,    /* C */
} tcpstat;

/*
 * TCP 模式
 */
typedef enum tcpmode {
  TCP_ACTIVE,
  TCP_PASSIVE,
} tcpmode;

/*
 * TCP 缓冲区
 */
typedef struct tcpbuf {
  char *data;
  UINT16 size;
} tcpbuf;

/*
 * TCP 缓冲区链表
 */
typedef struct tcplst {
  tcpbuf buf;
  struct tcplst *prev, *next;
} tcplst;

/*
 * TCB 控制块
 */
typedef struct tcb {
  tcpstat stat;
  tcpmode mode;
  UINT16 srcport, dstport;
  UINT32 srcaddr, dstaddr;
  UINT32 sndlow, rcvlow;  // 窗口下沿序号
  UINT32 sndbeg, rcvbeg;  // 窗口序号开始
  tcphdr *sndbuf;         // 窗口缓冲区
  UINT32 sndsiz;          // 窗口当前大小
  tcplst sndlst;          // 窗口外缓冲区链表
} tcb;

/*
 * 初始化 TCB 控制块
 */
void tcb_init(tcb *cb)
{
  cb->stat = TCP_CLOSED;
  cb->mode = TCP_ACTIVE;
  cb->srcport = cb->dstport = 0;
  cb->srcaddr = cb->dstaddr = 0;

  /* 窗口缓冲区 */
  cb->sndlow = cb->rcvlow = 0;
  cb->sndbeg = cb->rcvbeg = 1;
  cb->sndbuf = NULL;
  cb->sndsiz = 0;

  /* 窗口外缓冲区链表 */
  cb->sndlst.buf.data = NULL;
  cb->sndlst.buf.size = 0;
  cb->sndlst.prev = cb->sndlst.next = &cb->sndlst;
}

/*
 * 发送 TCP 报文
 */
int tcp_send(tcphdr *hdr, UINT16 siz, UINT32 srcaddr, UINT32 dstaddr)
{
  printf("*** %s: siz=%hu srcaddr=%#x dstaddr=%#x\n", __func__, siz, srcaddr, dstaddr);

  hdr->cs = 0;
  hdr->cs = tcp_cs(hdr, siz, srcaddr, dstaddr);
  tcp_sendIpPkt((unsigned char *)hdr, siz, srcaddr, dstaddr, 64);
  return 0;
}

/*
 * 接收 TCP 报文
 */
int tcp_recv(tcphdr *hdr, UINT16 siz, UINT32 srcaddr, UINT32 dstaddr)
{
  if(tcp_cs(hdr, siz, srcaddr, dstaddr)) {
    return 1;
  }
  return 0;
}

/*
 * 初始化 TCP 报文
 */
void tcp_init(tcphdr *hdr, const tcb *cb, UINT16 thl,
    const void *data, UINT16 size, UINT16 flags)
{
  hdr->srcport = htons(cb->srcport);
  hdr->dstport = htons(cb->dstport);
  hdr->seq = htonl(cb->sndlow);
  hdr->ack = htonl(cb->rcvlow);
  hdr->flags = htons((flags & TCP_FLG) | TCP_ENC_THL(thl));
  hdr->win = htons(1);
  hdr->cs = 0;
  hdr->up = htons(0);
  memset(hdr->op, 0, thl - sizeof *hdr);
  memcpy((char *)hdr + thl, data, size);
}

/*
 * TCP 主动连接
 */
int tcp_connect(tcb *cb)
{
  int r = 0;
  if(cb->mode != TCP_ACTIVE) return 1;
  if(cb->stat != TCP_CLOSED) return 1;

  /* 使用发送窗口发送 SYN 并进入 SYN_SENT 状态 */
  tcphdr *hdr = (tcphdr *)malloc(sizeof *hdr);
  if(hdr == NULL) return -1;
  tcp_init(hdr, cb, sizeof *hdr, NULL, 0, TCP_SYN);
  cb->sndbuf = hdr;
  cb->sndsiz = sizeof *hdr;
  r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
  cb->stat = TCP_SYN_SENT;
  return r;
}

/*
 * TCP 主动关闭
 */
int tcp_close(tcb *cb)
{
  int r = 0;
  if(cb->mode != TCP_ACTIVE) return 1;

  /* 关闭尚未建立的连接，丢弃所有队列任务 */
  if(cb->stat == TCP_SYN_SENT) {
    free(cb->sndbuf);
    cb->sndbuf = NULL;
    cb->sndsiz = 0;
    for(tcplst *p = cb->sndlst.next, *q; p != &cb->sndlst; p = q) {
      q = p->next;
      free(p->buf.data);
      free(p);
    }
    cb->sndlst.prev = cb->sndlst.next = &cb->sndlst;
    cb->stat = TCP_CLOSED;
    return 0;
  }

  /* 不能显式关闭部分关闭的连接 */
  if(cb->stat != TCP_ESTABLISHED) return 1;

  /* 还有尚未确认或排队发送的任务，则关闭失败 */
  if(cb->sndbuf || cb->sndlst.next != &cb->sndlst) return 1;

  /* 使用发送窗口发送 FIN 并进入 FIN_WAIT_1 状态 */
  tcphdr *hdr = (tcphdr *)malloc(sizeof *hdr);
  if(hdr == NULL) return -1;
  tcp_init(hdr, cb, sizeof *hdr, NULL, 0, TCP_FIN);
  cb->sndbuf = hdr;
  cb->sndsiz = sizeof *hdr;
  r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
  cb->stat = TCP_FIN_WAIT_1;
  return r;
}

/*
 * TCP 解析收取的报文
 */
int tcp_parse(tcb *cb, tcphdr *hdr, UINT16 siz)
{
  UINT16 flags = ntohs(hdr->flags);
  UINT16 thl = TCP_DEC_THL(flags);
  UINT32 seq = ntohl(hdr->seq);
  UINT32 ack = ntohl(hdr->ack);
  int r = 0;

  if(cb->stat == TCP_CLOSED) return 1;

  if((flags & TCP_SYN) && (flags & TCP_ACK)) {
    if((flags & TCP_FIN)) return 1;  /* 无效标志组合 */
    switch(cb->stat) {

    case TCP_SYN_SENT:  /* 等待建立连接 */

      if(ack != cb->sndlow + 1) return 1;  /* ack 号错 */

      /* 更新 TCB 中的序列号信息 */
      cb->sndlow = ack;
      cb->sndbeg = ack;
      cb->rcvlow = seq + 1;
      cb->rcvbeg = seq + 1;

      /* 发送 ACK 并进入 ESTABLISHED 状态 */
      cb->sndbuf->seq = htonl(cb->sndlow);
      cb->sndbuf->ack = htonl(cb->rcvlow);
      cb->sndbuf->flags = htons((ntohs(cb->sndbuf->flags) & ~TCP_FLG) | TCP_ACK);
      r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
      cb->stat = TCP_ESTABLISHED;
      if(r) {
        free(cb->sndbuf);
        cb->sndbuf = NULL;
        cb->sndsiz = 0;
        return r;
      }

      /* 如有排队任务，取出发送 */
      if(cb->sndlst.next != &cb->sndlst) {
        tcplst *p = cb->sndlst.next;
        char *data = p->buf.data;
        UINT16 size = p->buf.size;
        p->prev->next = p->next;
        p->next->prev = p->prev;
        free(p);
        cb->sndsiz = sizeof *hdr + size;
        cb->sndbuf = (tcphdr *)realloc(cb->sndbuf, cb->sndsiz);
        tcp_init(cb->sndbuf, cb, sizeof *hdr, data, size, 0);
        free(data);
        r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
      } else {
        free(cb->sndbuf);
        cb->sndbuf = NULL;
        cb->sndsiz = 0;
      }

      return r;

    case TCP_ESTABLISHED:

      if(seq + 1 != cb->rcvbeg) return 1;  /* seq 号错 */
      if(ack != cb->sndbeg) return 1;  /* ack 号错 */

      /* 重发 ACK */
      tcp_init(hdr, cb, sizeof *hdr, NULL, 0, TCP_ACK);
      r = tcp_send(hdr, sizeof *hdr, cb->srcaddr, cb->dstaddr);
      if(r) return r;

      /* 如有已发送任务，重发 */
      if(cb->sndbuf) {
        r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
      }

      return r;

    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
    case TCP_TIME_WAIT:
    default:
      return 1;
    }
  }

  if((flags & TCP_SYN)) return 1;  /* 缺少 ACK */

  if((flags & TCP_FIN)) {
    if(!(flags & TCP_ACK)) return 1;  /* 缺少 ACK */
    switch(cb->stat) {

    case TCP_FIN_WAIT_1:

      if(seq != cb->rcvlow) return 1;  /* seq 号错 */
      if(ack != cb->sndlow + 1) return 1;  /* ack 号错 */

      /* 更新 TCB 中的序列号信息 */
      cb->sndlow = ack;
      cb->rcvlow = seq + 1;

      /* 发送 ACK 并进入 TIME_WAIT 状态 */
      cb->sndbuf->seq = htonl(cb->sndlow);
      cb->sndbuf->ack = htonl(cb->rcvlow);
      cb->sndbuf->flags = htons((ntohs(cb->sndbuf->flags) & ~TCP_FLG) | TCP_ACK);
      r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
      cb->stat = TCP_TIME_WAIT;
      free(cb->sndbuf);
      cb->sndbuf = NULL;
      cb->sndsiz = 0;
      return r;

    case TCP_FIN_WAIT_2:
      if(seq != cb->rcvlow) return 1;  /* seq 号错 */
      if(ack != cb->sndlow) return 1;  /* ack 号错 */

      /* 更新 TCB 中的序列号信息 */
      cb->rcvlow = seq + 1;

      /* 发送 ACK 并进入 TIME_WAIT 状态 */
      tcp_init(hdr, cb, sizeof *hdr, NULL, 0, TCP_ACK);
      r = tcp_send(hdr, sizeof *hdr, cb->srcaddr, cb->dstaddr);
      cb->stat = TCP_TIME_WAIT;
      return r;

    case TCP_TIME_WAIT:

      if(seq + 1 != cb->rcvlow) return 1;  /* seq 号错 */
      if(ack != cb->sndlow) return 1;  /* ack 号错 */

      /* 重发 ACK */
      tcp_init(hdr, cb, sizeof *hdr, NULL, 0, TCP_ACK);
      r = tcp_send(hdr, sizeof *hdr, cb->srcaddr, cb->dstaddr);
      return r;

    case TCP_SYN_SENT:
    case TCP_ESTABLISHED:
    default:
      return 1;

    }
  }

  if((flags & TCP_ACK)) {

    flags = 0;
    switch(cb->stat) {

    case TCP_ESTABLISHED:

      if(cb->sndbuf == NULL) return 1;  /* 无等待确认的发送 */

      if(seq != cb->rcvlow && seq + 1 != cb->rcvlow) return 1;  /* seq 号错 */
      if(ack != cb->sndlow + (
            cb->sndsiz - TCP_DEC_THL(ntohs(cb->sndbuf->flags))
        )) return 1;  /* ack 号错 */

      /* 更新发送序列号 */
      cb->sndlow = ack;

      /* 对端捎带确认：如果 seq 号对应接收序列号，接收数据 */
      if(seq == cb->rcvlow && siz > thl) {
        // tcp_handup((char *)hdr + thl, siz - thl, seq - cb->rcvbeg);
        cb->rcvlow += siz - thl;
        flags |= TCP_ACK;
      }

      /* 如有排队任务，取出发送，否则在需要时单独发送确认消息 */
      if(cb->sndlst.next != &cb->sndlst) {
        tcplst *p = cb->sndlst.next;
        char *data = p->buf.data;
        UINT16 size = p->buf.size;
        p->prev->next = p->next;
        p->next->prev = p->prev;
        free(p);
        cb->sndsiz = sizeof *hdr + size;
        cb->sndbuf = (tcphdr *)realloc(cb->sndbuf, cb->sndsiz);
        tcp_init(cb->sndbuf, cb, sizeof *hdr, data, size, flags);
        free(data);
        r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
      } else {
        free(cb->sndbuf);
        cb->sndbuf = NULL;
        cb->sndsiz = 0;
        if(flags) {
          tcp_init(hdr, cb, sizeof *hdr, NULL, 0, flags);
          r = tcp_send(hdr, sizeof *hdr, cb->srcaddr, cb->dstaddr);
        }
      }

      return r;

    case TCP_FIN_WAIT_1:

      if(seq != cb->rcvlow && seq + 1 != cb->rcvlow) return 1;  /* seq 号错 */
      if(ack != cb->sndlow + 1) return 1;  /* ack 号错 */

      /* 更新发送序列号 */
      cb->sndlow = ack;

      /* 对端捎带确认：如果 seq 号对应接收序列号，接收数据 */
      if(seq == cb->rcvlow && siz > thl) {
        // tcp_handup((char *)hdr + thl, siz - thl, seq - cb->rcvbeg);
        cb->rcvlow += siz - thl;
        flags |= TCP_ACK;
      }

      /* 一定无排队任务，故在需要时应当单独发送确认消息 */
      free(cb->sndbuf);
      cb->sndbuf = NULL;
      cb->sndsiz = 0;
      if(flags) {
        tcp_init(hdr, cb, sizeof *hdr, NULL, 0, flags);
        r = tcp_send(hdr, sizeof *hdr, cb->srcaddr, cb->dstaddr);
      }
      cb->stat = TCP_FIN_WAIT_2;

      return r;

    case TCP_SYN_SENT:
    case TCP_FIN_WAIT_2:
    case TCP_TIME_WAIT:
    default:
      return 1;

    }

  }

  switch(cb->stat) {

  case TCP_ESTABLISHED:
  case TCP_FIN_WAIT_1:
  case TCP_FIN_WAIT_2:

    if(seq != cb->rcvlow) return 1;  /* seq 号错 */

    if(siz > thl) {
      // tcp_handup((char *)hdr + thl, siz - thl, seq - cb->rcvbeg);
      cb->rcvlow += siz - thl;
      flags |= TCP_ACK;
    }

    /* 一定不发新任务，故在需要时应当单独发送确认消息 */
    if(flags) {
      tcp_init(hdr, cb, sizeof *hdr, NULL, 0, flags);
      r = tcp_send(hdr, sizeof *hdr, cb->srcaddr, cb->dstaddr);
    }

    return r;

  case TCP_SYN_SENT:
  case TCP_TIME_WAIT:
  default:
    return 1;

  }
}

/*
 * TCP 超时
 */
int tcp_timeout(tcb *cb)
{
  int r = 0;
  if(cb->stat == TCP_CLOSED) return 1;

  switch(cb->stat) {

  case TCP_ESTABLISHED:
  case TCP_SYN_SENT:
  case TCP_FIN_WAIT_1:
    if(cb->sndbuf) {
      r = tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
    }
    return r;

  case TCP_FIN_WAIT_2:
  case TCP_TIME_WAIT:
    cb->stat = TCP_CLOSED;
    return 0;

  default:
    return 1;
  }
}

/*
 * TCP 发送报文
 */
int tcp_trans(tcb *cb, const void *data, UINT16 size)
{
  tcphdr *hdr;
  if(cb->stat == TCP_CLOSED) return 1;

  switch(cb->stat) {

  case TCP_SYN_SENT:
  case TCP_ESTABLISHED:

    if(cb->sndbuf) {
      tcplst *p = (tcplst *)malloc(sizeof *p);
      if(p == NULL) return -1;
      p->buf.data = (char *)malloc(size);
      if(p->buf.data == NULL) {
        free(p);
        return -1;
      }
      memcpy(p->buf.data, data, size);
      p->buf.size = size;
      p->prev = cb->sndlst.prev;
      p->next = &cb->sndlst;
      p->prev->next = p;
      p->next->prev = p;
      return 0;
    }

    hdr = (tcphdr *)malloc(sizeof *hdr + size);
    if(hdr == NULL) return -1;
    tcp_init(hdr, cb, sizeof *hdr, data, size, 0);
    cb->sndbuf = hdr;
    cb->sndsiz = sizeof *hdr + size;
    return tcp_send(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);

  case TCP_FIN_WAIT_1:
  case TCP_FIN_WAIT_2:
  case TCP_TIME_WAIT:
  default:
    return 1;
  }
}

tcb gtcb;

__attribute__((constructor))
static void gtcb_init(void)
{
  tcb_init(&gtcb);
  gtcb.srcaddr = getIpv4Address();
  gtcb.dstaddr = getServerIpv4Address();
  gtcb.srcport = gSrcPort;
  gtcb.dstport = gDstPort;
  gtcb.sndbeg = gSeqNum;
  gtcb.sndlow = gSeqNum;
  gtcb.rcvbeg = gAckNum;
  gtcb.rcvlow = gAckNum;
}

int stud_tcp_input(char *buf, UINT16 siz, UINT32 src, UINT32 dst)
{
  printf("*** %s: siz=%hu src=%#x dst=%#x\n", __func__, siz, src, dst);

  tcphdr *hdr = (tcphdr *)buf;

  if(siz < sizeof *hdr) return 1;
  if(src != gtcb.dstaddr) return 1;
  if(dst != gtcb.srcaddr) return 1;
  if(tcp_cs(hdr, siz, src, dst)) return 1;

  UINT16 srcport = ntohs(hdr->srcport);
  UINT16 dstport = ntohs(hdr->dstport);
  UINT32 seq = ntohl(hdr->seq);

  if(srcport != gtcb.dstport) {
    tcp_sendReport(STUD_TCP_TEST_SRCPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SRCPORT_ERROR);
    return 1;
  }
  if(dstport != gtcb.srcport) {
    tcp_sendReport(STUD_TCP_TEST_DSTPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_DSTPORT_ERROR);
    return 1;
  }
  if(seq != gtcb.rcvlow) {
    tcp_sendReport(STUD_TCP_TEST_SEQNO_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SEQNO_ERROR);
    return 1;
  }

  return tcp_parse(&gtcb, hdr, siz);
}

void stud_tcp_output(char *data, UINT16 size, unsigned char flags,
    UINT16 srcport, UINT16 dstport, UINT32 srcaddr, UINT32 dstaddr)
{
  printf("*** %s: size=%hu flags=%hhu srcport=%hu dstport=%hu srcaddr=%#x dstaddr=%#x\n",
      __func__, size, flags, srcport, dstport, srcaddr, dstaddr);

  printf("*** %s: srcport=%hu gtcb.srcport=%hu\n", __func__, srcport, gtcb.srcport);
  if(srcport != gtcb.srcport) return;
  printf("*** %s: dstport=%hu gtcb.dstport=%hu\n", __func__, dstport, gtcb.dstport);
  if(dstport != gtcb.dstport) return;
  gtcb.srcaddr = dstaddr;
  printf("*** %s: srcaddr=%#x gtcb.srcaddr=%#x\n", __func__, srcaddr, gtcb.srcaddr);
  gtcb.dstaddr = dstaddr;
  printf("*** %s: dstaddr=%#x gtcb.dstaddr=%#x\n", __func__, dstaddr, gtcb.dstaddr);

  if((flags & TCP_SYN)) {
    if((flags & (TCP_ACK | TCP_FIN))) return;
    printf("*** %s: SYN size=%hu\n", __func__, size);
    if(size) return;
    int r = tcp_connect(&gtcb);
    printf("*** %s: SYN ret=%d\n", __func__, r);
    return;
  }

  if((flags & TCP_FIN)) {
    if((flags & TCP_ACK)) return;
    if(size) return;
    tcp_close(&gtcb);
    return;
  }

  if((flags & TCP_ACK)) {
    if(size) return;
    return;
  }

  tcp_trans(&gtcb, data, size);
}

static tcb *socktab[SOCKFD_MAX];

int stud_tcp_socket(int domain, int type, int protocol)
{
  if(domain != AF_INET) return -1;
  if(type != SOCK_STREAM) return -1;
  if(protocol != 0 && protocol != IPPROTO_TCP) return -1;
  for(int i = 0; i < SOCKFD_MAX; ++i) {
    if(socktab[i] == NULL) {
      socktab[i] = (tcb *)malloc(sizeof *socktab[i]);
      if(socktab[i] == NULL) return -1;
      tcb_init(socktab[i]);
      return i;
    }
  }
  return -1;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int)
{
  int r = 0;
  tcb *cb = socktab[sockfd];
  if(cb == NULL) return 1;

  cb->srcaddr = getIpv4Address();
  cb->srcport = gSrcPort;
  cb->dstaddr = ntohl(addr->sin_addr.s_addr);
  cb->dstport = ntohs(addr->sin_port);
  if((r = tcp_connect(cb))) return r;

  char *buf = (char *)malloc(65535);
  if(buf == NULL) return -1;
  int siz_i;
  if((siz_i = waitIpPacket(buf, 10)) == -1) {
    free(buf);
    return 1;
  }
  UINT16 siz = siz_i;
  tcphdr *hdr = (tcphdr *)buf;
  if(siz < sizeof *hdr) {
    free(buf);
    return 1;
  }

  UINT16 srcport = ntohs(hdr->srcport);
  UINT16 dstport = ntohs(hdr->dstport);
  UINT32 seq = ntohl(hdr->seq);

  if(srcport != gtcb.dstport) {
    tcp_sendReport(STUD_TCP_TEST_SRCPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SRCPORT_ERROR);
    free(buf);
    return 1;
  }
  if(dstport != gtcb.srcport) {
    tcp_sendReport(STUD_TCP_TEST_DSTPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_DSTPORT_ERROR);
    free(buf);
    return 1;
  }
  if(seq != gtcb.rcvlow) {
    tcp_sendReport(STUD_TCP_TEST_SEQNO_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SEQNO_ERROR);
    free(buf);
    return 1;
  }

  r = tcp_parse(cb, hdr, siz);
  free(buf);
  return r;
}

int stud_tcp_send(int sockfd,
    const unsigned char *data, UINT16 size, int flags)
{
  int r;
  tcb *cb = socktab[sockfd];
  if(cb == NULL) return 1;

  if(flags) return 1;
  if((r = tcp_trans(cb, data, size))) return r;

  char *buf = (char *)malloc(65535);
  if(buf == NULL) return -1;
  int siz_i;
  if((siz_i = waitIpPacket(buf, 10)) == -1) {
    free(buf);
    return 1;
  }
  UINT16 siz = siz_i;
  tcphdr *hdr = (tcphdr *)buf;
  if(siz < sizeof *hdr) {
    free(buf);
    return 1;
  }

  UINT16 srcport = ntohs(hdr->srcport);
  UINT16 dstport = ntohs(hdr->dstport);
  UINT32 seq = ntohl(hdr->seq);

  if(srcport != gtcb.dstport) {
    tcp_sendReport(STUD_TCP_TEST_SRCPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SRCPORT_ERROR);
    free(buf);
    return 1;
  }
  if(dstport != gtcb.srcport) {
    tcp_sendReport(STUD_TCP_TEST_DSTPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_DSTPORT_ERROR);
    free(buf);
    return 1;
  }
  if(seq != gtcb.rcvlow) {
    tcp_sendReport(STUD_TCP_TEST_SEQNO_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SEQNO_ERROR);
    free(buf);
    return 1;
  }

  r = tcp_parse(cb, hdr, siz);
  free(buf);
  return r;
}

int stud_tcp_recv(int sockfd,
    unsigned char *data, UINT16 datalen, int flags)
{
  int r;
  tcb *cb = socktab[sockfd];
  if(cb == NULL) return 1;

  if(flags) return 1;

  char *buf = (char *)malloc(65535);
  if(buf == NULL) return -1;
  int siz_i;
  if((siz_i = waitIpPacket(buf, 10)) == -1) {
    free(buf);
    return 1;
  }
  UINT16 siz = siz_i;
  tcphdr *hdr = (tcphdr *)buf;
  if(siz < sizeof *hdr) {
    free(buf);
    return 1;
  }

  UINT16 srcport = ntohs(hdr->srcport);
  UINT16 dstport = ntohs(hdr->dstport);
  UINT32 seq = ntohl(hdr->seq);

  if(srcport != gtcb.dstport) {
    tcp_sendReport(STUD_TCP_TEST_SRCPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SRCPORT_ERROR);
    free(buf);
    return 1;
  }
  if(dstport != gtcb.srcport) {
    tcp_sendReport(STUD_TCP_TEST_DSTPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_DSTPORT_ERROR);
    free(buf);
    return 1;
  }
  if(seq != gtcb.rcvlow) {
    tcp_sendReport(STUD_TCP_TEST_SEQNO_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SEQNO_ERROR);
    free(buf);
    return 1;
  }

  r = tcp_parse(cb, hdr, siz);
  if(r) return r;

  UINT16 thl = TCP_DEC_THL(ntohs(hdr->flags));
  UINT16 size = siz - thl;
  if(size > datalen) {
    r = 1;
  } else {
    memcpy(data, (char *)hdr + thl, size);
  }
  free(buf);
  return r;
}

int stud_tcp_close(int sockfd)
{
  int r;
  tcb *cb = socktab[sockfd];
  if(cb == NULL) return 1;

  r = tcp_close(cb);
  if(r) return r;

  while(cb->stat != TCP_CLOSED) {

    char *buf = (char *)malloc(65535);
    if(buf == NULL) return -1;
    int siz_i;
    if((siz_i = waitIpPacket(buf, 10)) == -1) {
      free(buf);
      return 1;
    }
    UINT16 siz = siz_i;
    tcphdr *hdr = (tcphdr *)buf;
    if(siz < sizeof *hdr) {
      free(buf);
      return 1;
    }

    UINT16 srcport = ntohs(hdr->srcport);
    UINT16 dstport = ntohs(hdr->dstport);
    UINT32 seq = ntohl(hdr->seq);

  if(srcport != gtcb.dstport) {
    tcp_sendReport(STUD_TCP_TEST_SRCPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SRCPORT_ERROR);
    free(buf);
    return 1;
  }
  if(dstport != gtcb.srcport) {
    tcp_sendReport(STUD_TCP_TEST_DSTPORT_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_DSTPORT_ERROR);
    free(buf);
    return 1;
  }
  if(seq != gtcb.rcvlow) {
    tcp_sendReport(STUD_TCP_TEST_SEQNO_ERROR);
    tcp_DiscardPkt(buf, STUD_TCP_TEST_SEQNO_ERROR);
    free(buf);
    return 1;
  }

    r = tcp_parse(cb, hdr, siz);
    free(buf);
    if(r) return r;

  }
  free(cb);
  socktab[sockfd] = NULL;
  return 0;
}

#if __cplusplus >= 201703  /* 我的笔记本/机房台式机编译环境 */

/*
 * 本地测试
 */
int main(void)
{
  assert(TCP_DEC_THL(TCP_ENC_THL(0)) == 0);
  assert(TCP_DEC_THL(TCP_ENC_THL(1)) == 4);
  assert(TCP_DEC_THL(TCP_ENC_THL(2)) == 4);
  assert(TCP_DEC_THL(TCP_ENC_THL(3)) == 4);
  assert(TCP_DEC_THL(TCP_ENC_THL(4)) == 4);
  assert(TCP_DEC_THL(TCP_ENC_THL(5)) == 8);

  tcphdr *hdr = (tcphdr *)malloc(sizeof *hdr + 4096);
  assert(hdr != NULL);
  hdr->srcport = htons(15280);
  hdr->dstport = htons(12580);
  hdr->seq = 0;
  hdr->ack = 0;
  hdr->flags = htons(TCP_ENC_THL(sizeof *hdr));
  hdr->win = htons(1);
  hdr->cs = 0;
  hdr->up = 0;

  tcb cb;
  tcb_init(&cb);
  cb.srcport = 12580;
  cb.dstport = 15280;
  cb.srcaddr = 0x7f000001;
  cb.dstaddr = 0x7f000001;

  /* SYN -> SYN_SENT */
  assert(tcp_connect(&cb) == 0);
  assert(cb.stat == TCP_SYN_SENT);

  /* close -> CLOSED */
  assert(tcp_close(&cb) == 0);
  assert(cb.stat == TCP_CLOSED);

  /* SYN -> SYN_SENT */
  assert(tcp_connect(&cb) == 0);
  assert(cb.stat == TCP_SYN_SENT);

  /* SYNACK -> ESTABLISHED */
  hdr->seq = htonl(256);
  hdr->ack = htonl(1);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_SYN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_ESTABLISHED);

  /* ESTABLISHED -> FIN_WAIT_1 */
  assert(tcp_close(&cb) == 0);
  assert(cb.stat == TCP_FIN_WAIT_1);

  /* FINACK -> TIME_WAIT */
  hdr->seq = htonl(257);
  hdr->ack = htonl(2);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_FIN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_TIME_WAIT);

  /* timeout -> CLOSED */
  tcp_timeout(&cb);
  assert(cb.stat == TCP_CLOSED);

  tcb_init(&cb);
  cb.srcport = 12580;
  cb.dstport = 15280;
  cb.srcaddr = 0x7f000001;
  cb.dstaddr = 0x7f000001;

  /* SYN -> SYN_SENT */
  assert(tcp_connect(&cb) == 0);
  assert(cb.stat == TCP_SYN_SENT);

  /* SYNACK -> ESTABLISHED */
  hdr->seq = htonl(256);
  hdr->ack = htonl(1);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_SYN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_ESTABLISHED);

  /* ESTABLISHED -> FIN_WAIT_1 */
  assert(tcp_close(&cb) == 0);
  assert(cb.stat == TCP_FIN_WAIT_1);

  /* ACK -> FIN_WAIT_2 */
  hdr->seq = htonl(257);
  hdr->ack = htonl(2);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_FIN_WAIT_2);

  /* FINACK -> TIME_WAIT */
  hdr->seq = htonl(257);
  hdr->ack = htonl(2);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_FIN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_TIME_WAIT);

  /* FINACK -> TIME_WAIT */
  hdr->seq = htonl(257);
  hdr->ack = htonl(2);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_FIN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_TIME_WAIT);

  /* timeout -> CLOSED */
  tcp_timeout(&cb);
  assert(cb.stat == TCP_CLOSED);

  tcb_init(&cb);
  cb.srcport = 12580;
  cb.dstport = 15280;
  cb.srcaddr = 0x7f000001;
  cb.dstaddr = 0x7f000001;

  /* SYN -> SYN_SENT */
  assert(tcp_connect(&cb) == 0);
  assert(cb.stat == TCP_SYN_SENT);

  /* SYNACK -> ESTABLISHED */
  hdr->seq = htonl(256);
  hdr->ack = htonl(1);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_SYN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_ESTABLISHED);

  memset(hdr->op, -1, 4096);
  assert(tcp_trans(&cb, hdr->op, 4096) == 0);
  assert(cb.sndbuf);
  assert(cb.sndbuf->op[1111] == -1);
  assert(cb.sndsiz == 4096 + sizeof *hdr);
  assert(cb.stat == TCP_ESTABLISHED);

  memset(hdr->op, 1, 4096);
  assert(tcp_trans(&cb, hdr->op, 4096) == 0);
  assert(cb.sndlst.next != &cb.sndlst);
  assert(cb.sndlst.next->buf.data[2222] == 1);
  assert(cb.sndlst.next->buf.size == 4096);
  assert(cb.stat == TCP_ESTABLISHED);

  hdr->seq = htonl(257);
  hdr->ack = htonl(4097);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_ESTABLISHED);

  hdr->seq = htonl(257);
  hdr->ack = htonl(8193);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_ACK);
  memset(hdr->op, 2, 4096);
  assert(tcp_parse(&cb, hdr, sizeof *hdr + 4096) == 0);
  assert(cb.stat == TCP_ESTABLISHED);

  /* ESTABLISHED -> FIN_WAIT_1 */
  assert(tcp_close(&cb) == 0);
  assert(cb.stat == TCP_FIN_WAIT_1);

  /* FINACK -> TIME_WAIT */
  hdr->seq = htonl(4353);
  hdr->ack = htonl(8194);
  hdr->flags = htons((ntohs(hdr->flags) & ~TCP_FLG) | TCP_FIN | TCP_ACK);
  assert(tcp_parse(&cb, hdr, sizeof *hdr) == 0);
  assert(cb.stat == TCP_TIME_WAIT);

  /* timeout -> CLOSED */
  tcp_timeout(&cb);
  assert(cb.stat == TCP_CLOSED);

  free(hdr);
  return 0;
}

/*
 * 本地空壳函数
 */
__attribute__((noinline))
void tcp_DiscardPkt(char *buf, int type)
{
  assert(buf);
  assert(type >= STUD_TCP_TEST_SEQNO_ERROR);
  assert(type <= STUD_TCP_TEST_DSTPORT_ERROR);
}
__attribute__((noinline))
void tcp_sendReport(int type)
{
  printf("*** %s: %d\n", __func__, type);
}
__attribute__((noinline))
void tcp_sendIpPkt(unsigned char *data, UINT16 len, UINT32, UINT32, UINT8)
{
  assert(data);
  assert(len >= sizeof(tcphdr));
}
__attribute__((noinline))
int waitIpPacket(char *buf, int timeout)
{
  assert(buf);
  assert(timeout);
  memset(buf, -1, 65535);
  return -1;
}
__attribute__((noinline))
UINT32 getIpv4Address()
{
  return 0x7f000001;  // 127.0.0.1
}
__attribute__((noinline))
UINT32 getServerIpv4Address()
{
  return 0x7f000002;  // 127.0.0.1
}

#endif  /* __cplusplus >= 201703 */
