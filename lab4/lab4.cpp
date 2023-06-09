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
# include <winsock.h>  /* compile and link with: -lws2_32 */
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
#define UINT64  uint64_t

#define INT8    int8_t
#define INT16   int16_t
#define INT32   int32_t
#define INT64   int64_t

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
#define SOCKFD_MAX    256
#define SOCKPORT_MIN  40000
#define SOCKPORT_MAX  (SOCKPORT_MIN + SOCKFD_MAX)

/*
 * 全局变量
 */
int gSrcPort = 2007;
int gDstPort = 2006;
int gSeqNum = 0x10000;
int gAckNum = 0x10000;

/*
 * 系统函数
 */
extern void tcp_DiscardPkt(char *buf, int type);
extern void tcp_sendReport(int type);
extern void tcp_sendIpPkt(unsigned char *data, UINT16 len,
    UINT32 srcaddr, UINT32 dstaddr, UINT8 ttl);
extern int waitIpPacket(char *buf, int timeout);
extern UINT32 getIpv4Address(void);
extern UINT32 getServerIpv4Address(void);

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
typedef struct tcphdr_pck {
  UINT16 srcport;
  UINT16 dstport;
  UINT32 seq;
  UINT32 ack;
  UINT16 flags;
  UINT16 win;
  UINT16 cs;
  UINT16 up;
  char op[0];
} __attribute__((packed)) tcphdr_pck;

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
  UINT64 cs = htonl(src) + htonl(dst) + htons(6) + htons(siz);
  size_t n = siz >> 2;
  UINT32 *p = (UINT32 *)hdr, rem = 0;
  asm("" ::: "memory");  /* 在 strict aliasing 下充当内存屏障 */
  for(size_t i = 0; i < n; ++i) cs += p[i];
  for(size_t i = siz; i & 3; --i) {
    ((char *)&rem)[(i - 1) & 3] = ((char *)hdr)[i - 1];
  }
  cs += rem;
  cs = (cs & 0xffff) + (cs >> 16);
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
 * TCP 缓冲区链表
 */
typedef struct tcplst {
  tcphdr *buf;
  UINT16 siz;
  struct tcplst *prev;
  struct tcplst *next;
} tcplst;

/*
 * TCB 控制块
 */
typedef struct tcb {
  tcpstat stat;
  tcpmode mode;
  UINT16 srcport, dstport;
  UINT32 srcaddr, dstaddr;
  UINT32 sndlow, rcvlow;  /* 窗口下沿序号 */
  UINT32 sndbeg, rcvbeg;  /* 窗口序号开始 */
  tcphdr *sndbuf;         /* 窗口缓冲区 */
  UINT32 sndsiz;          /* 窗口当前大小 */
  UINT32 sndseq;          /* 下一发送序列号 */
  tcplst sndlst;          /* 窗口外缓冲区链表 */
  char *rcvbuf;           /* 接收数据缓冲区 */
  UINT32 rcvlen;          /* 接收数据大小 */
} tcb;

/*
 * 初始化 TCB 控制块
 */
int tcb_init(tcb *cb)
{
  cb->stat = TCP_CLOSED;
  cb->mode = TCP_ACTIVE;
  cb->srcport = cb->dstport = 0;
  cb->srcaddr = cb->dstaddr = 0;

  /* 停等窗口 */
  cb->sndlow = 100;
  cb->sndbeg = 101;
  cb->rcvlow = 0;
  cb->rcvbeg = 1;
  cb->sndbuf = NULL;
  cb->sndsiz = 0;
  cb->sndseq = 100;

  /* 窗口外缓冲区链表 */
  cb->sndlst.buf = NULL;
  cb->sndlst.siz = 0;
  cb->sndlst.prev = cb->sndlst.next = &cb->sndlst;

  /* 接收缓冲区 */
  cb->rcvbuf = (char *)malloc(65535);
  cb->rcvlen = 0;

  if(cb->rcvbuf == NULL) return 1;
  return 0;
}

void tcb_destroy(tcb *cb)
{
  free(cb->sndbuf);
  free(cb->rcvbuf);
  for(tcplst *p = cb->sndlst.next, *q; p != &cb->sndlst; p = q) {
    q = p->next;
    free(p->buf);
    free(p);
  }
}

/*
 * 将 TCP 报文交给下层
 */
void tcp_senddown(tcphdr *hdr, UINT16 siz, UINT32 src, UINT32 dst)
{
  printf("*** %s: siz=%hu src=%#x dst=%#x\n", __func__, siz, src, dst);

  hdr->cs = 0;
  hdr->cs = tcp_cs(hdr, siz, src, dst);
  tcp_sendIpPkt((unsigned char *)hdr, siz, src, dst, 64);
}

/*
 * 从下层接收 TCP 报文
 */
int tcp_recvdown(tcphdr **hdrp, const void *buf, UINT16 siz, UINT32 src, UINT32 dst)
{
  printf("*** %s: siz=%hu src=%#x dst=%#x\n", __func__, siz, src, dst);

  if(siz < sizeof(tcphdr)) return 1;
  UINT16 thl = TCP_DEC_THL(ntohs(((const tcphdr_pck *)buf)->flags));
  if(thl < sizeof(tcphdr)) return 1;
  if(thl > siz) return 1;
  tcphdr *hdr = (tcphdr *)malloc(siz);  /* 确保满足对齐要求，需要释放 */
  if(hdr == NULL) return -1;
  memcpy(hdr, buf, siz);
  if(tcp_cs(hdr, siz, src, dst)) {
    free(hdr);
    return 1;
  }
  *hdrp = hdr;
  return 0;
}

/*
 * 初始化 TCP 报文
 */
void tcp_init(tcphdr *hdr, tcb *cb, UINT16 thl,
    const void *data, UINT16 size, UINT16 flags)
{
  hdr->srcport = htons(cb->srcport);
  hdr->dstport = htons(cb->dstport);
  hdr->seq = htonl(cb->sndseq);
  hdr->ack = htonl(cb->rcvlow);
  hdr->flags = htons((flags & TCP_FLG) | TCP_ENC_THL(thl));
  printf("*** %s: srcport=%hu dstport=%hu seq=%u ack=%u flags=%#x\n", __func__,
      cb->srcport, cb->dstport, cb->sndlow, cb->rcvlow, flags & TCP_FLG);
  hdr->win = htons(1024);
  hdr->cs = 0;
  hdr->up = htons(0);
  memset(hdr->op, 0, thl - sizeof *hdr);
  memcpy((char *)hdr + thl, data, size);
  cb->sndseq += size;
}

/*
 * 将待发送的报文入队
 */
int tcp_pend(tcb *cb, const void *data, UINT16 size, UINT16 flags)
{
  flags &= TCP_FLG;
  if((flags & (TCP_SYN | TCP_FIN))) return 1;
  tcphdr *hdr = (tcphdr *)malloc(sizeof *hdr + size);
  if(hdr == NULL) return -1;
  tcplst *lst = (tcplst *)malloc(sizeof *lst);
  if(lst == NULL) {
    free(hdr);
    return -1;
  }
  tcp_init(hdr, cb, sizeof *hdr, data, size, flags);
  lst->buf = hdr;
  lst->siz = sizeof *hdr + size;
  lst->prev = cb->sndlst.prev;
  lst->next = &cb->sndlst;
  lst->prev->next = lst->next->prev = lst;
  return 0;
}

/*
 * 从队列中取出报文并发送
 */
int tcp_submit(tcb *cb, UINT16 flags)
{
  tcplst *lst = cb->sndlst.next;
  if(lst == &cb->sndlst) return -1;
  if(cb->sndbuf) return 1;
  flags &= TCP_FLG;
  if((flags & (TCP_SYN | TCP_FIN))) return 1;
  cb->sndbuf = lst->buf;
  cb->sndsiz = lst->siz;
  lst->prev->next = lst->next;
  lst->next->prev = lst->prev;
  free(lst);
  cb->sndbuf->ack = htonl(cb->rcvlow);
  cb->sndbuf->flags |= htons(flags);
  tcp_senddown(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
  return 0;
}

/*
 * 排队发送 TCP 报文
 */
int tcp_seqsend(tcb *cb, const void *data, UINT16 size, UINT16 flags)
{
  if(cb->sndbuf) return tcp_pend(cb, data, size, flags);
  tcphdr *hdr = (tcphdr *)malloc(sizeof *hdr + size);
  if(hdr == NULL) return -1;
  tcp_init(hdr, cb, sizeof *hdr, data, size, flags);
  cb->sndbuf = hdr;
  cb->sndsiz = sizeof *hdr + size;
  tcp_senddown(cb->sndbuf, cb->sndsiz, cb->srcaddr, cb->dstaddr);
  return 0;
}

/*
 * 不排队发送 TCP 报文
 */
int tcp_dirsend(tcb *cb, const void *data, UINT16 size, UINT16 flags)
{
  if(size) return 1;
  if(!(flags & TCP_ACK)) return 1;
  if((flags & (TCP_SYN | TCP_FIN))) return 1;
  tcphdr *hdr = (tcphdr *)malloc(sizeof *hdr + size);
  if(hdr == NULL) return -1;
  tcp_init(hdr, cb, sizeof *hdr, data, size, flags);
  if(cb->sndlst.next != &cb->sndlst) {
    hdr->seq = cb->sndlst.next->buf->seq;
  }
  tcp_senddown(hdr, sizeof *hdr + size, cb->srcaddr, cb->dstaddr);
  free(hdr);
  return 0;
}

/*
 * 从上层接收 TCP 数据或控制标志
 */
int tcp_recvup(tcb *cb, const void *data, UINT16 size, UINT16 flags,
    UINT16 srcport, UINT16 dstport, UINT32 srcaddr, UINT32 dstaddr)
{
  flags &= TCP_FLG;
  printf("*** %s: stat=%d size=%hu flags=%#hx"
      " srcport=%hu dstport=%hu srcaddr=%#x dstaddr=%#x\n",
      __func__, cb->stat, size, flags,
      srcport, dstport, srcaddr, dstaddr);

  if(flags == TCP_SYN) {  /* 建立连接的第一次握手 */
    if(cb->stat != TCP_CLOSED) return 1;
    cb->srcport = srcport;
    cb->dstport = dstport;
    cb->srcaddr = srcaddr;
    cb->dstaddr = dstaddr;
    cb->stat = TCP_SYN_SENT;
    int r = tcp_seqsend(cb, data, size, flags);
    cb->sndseq = cb->sndlow + 1;
    return r;
  }

  if((flags & TCP_SYN)) return 1;
  if(cb->stat == TCP_CLOSED) return 1;
  if(cb->srcport != srcport) return 1;
  if(cb->dstport != dstport) return 1;
  if(cb->srcaddr != srcaddr) return 1;
  if(cb->dstaddr != dstaddr) return 1;

  if((flags & TCP_FIN)) {  /* 连接断开的第一次挥手 */
    if(cb->stat == TCP_ESTABLISHED || cb->stat == TCP_FIN_WAIT_1) {
      cb->stat = TCP_FIN_WAIT_1;
      cb->sndseq = cb->sndlow;
      int r = tcp_seqsend(cb, data, size, flags);
      cb->sndseq = cb->sndlow + 1;
      return r;
    }
    return 1;
  }

  if(cb->stat != TCP_ESTABLISHED) return 1;
  return tcp_seqsend(cb, data, size, flags);  /* 停等发送数据 */
}

/*
 * 向上层发送 TCP 数据或接收控制消息
 */
int tcp_sendup(tcb *cb, tcphdr *hdr, UINT16 siz, UINT32 src, UINT32 dst)
{
  int r = 0;
  printf("*** %s: stat=%d siz=%hu src=%#x dst=%#x\n",
      __func__, cb->stat, siz, src, dst);
  UINT32 seq = ntohl(hdr->seq);
  UINT32 ack = ntohl(hdr->ack);
  UINT16 flags = ntohs(hdr->flags);
  UINT16 thl = TCP_DEC_THL(flags);
  UINT16 size = siz - thl;
  flags &= TCP_FLG;

  if(flags == (TCP_SYN | TCP_ACK)) {  /* 建立连接的第二次握手 */
    if(cb->stat != TCP_SYN_SENT) return 1;
    if(ack != cb->sndlow + 1) return 1;
    cb->sndlow = ack;
    cb->sndbeg = ack;
    cb->rcvlow = seq + 1;
    cb->rcvbeg = seq + 1;
    free(cb->sndbuf);
    cb->sndbuf = NULL;
    cb->sndsiz = 0;
    cb->stat = TCP_ESTABLISHED;
    return tcp_dirsend(cb, NULL, 0, TCP_ACK);  /* 建立连接的第三次握手 */
  }

  if((flags & TCP_SYN)) return 1;

  if((flags & TCP_FIN)) {  /* 断开连接的第三次挥手 */
    if(!(flags & TCP_ACK)) return 1;
    if(cb->stat == TCP_FIN_WAIT_1) {
      if(cb->rcvlow != seq) return 1;
      if(cb->sndlow + 1 != ack) return 1;
      cb->rcvlow = seq + 1;
      cb->sndlow = ack;
      free(cb->sndbuf);
      cb->sndbuf = NULL;
      cb->sndsiz = 0;
      cb->stat = TCP_TIME_WAIT;
      return tcp_dirsend(cb, NULL, 0, TCP_ACK);  /* 断开连接的第四次挥手 */
    }
    if(cb->stat == TCP_FIN_WAIT_2) {
      if(cb->rcvlow != seq) return 1;
      if(cb->sndlow + 1 != ack) return 1;
      cb->rcvlow = seq + 1;
      cb->sndlow = ack;
      cb->stat = TCP_TIME_WAIT;
      return tcp_dirsend(cb, NULL, 0, TCP_ACK);  /* 断开连接的第四次挥手 */
    }
    if(cb->stat == TCP_TIME_WAIT) {
      if(cb->rcvlow != seq + 1) return 1;
      if(cb->sndlow != ack) return 1;
      return tcp_dirsend(cb, NULL, 0, TCP_ACK);  /* 断开连接的第四次挥手 */
    }
    return 1;
  }

  if(cb->stat != TCP_ESTABLISHED
      && cb->stat != TCP_FIN_WAIT_1
      && cb->stat != TCP_FIN_WAIT_2)
  {
    return 1;
  }

  if(cb->rcvlow != seq) return 1;

  /* 接收数据 */
  memcpy(cb->rcvbuf, (char *)hdr + thl, size);
  cb->rcvlen = size;
  cb->rcvlow += size;

  /* 处理确认 */
  while((flags & TCP_ACK)) {
    if(cb->sndbuf == NULL) break;

    if(cb->stat == TCP_ESTABLISHED) {
      UINT16 sndlen = cb->sndsiz - TCP_DEC_THL(ntohs(cb->sndbuf->flags));
      /* 确认号不对应时，理解为单纯发送数据 */
      if(cb->sndlow + sndlen != ack) break;
      cb->sndlow = ack;
      free(cb->sndbuf);
      cb->sndbuf = NULL;
      cb->sndsiz = 0;
      break;
    }

    /* 停等实现下，不可能确认数据，只能确认 FIN */
    if(cb->sndlow + 1 != ack) break;
    /* 断开连接的第二次挥手 */
    free(cb->sndbuf);
    cb->sndbuf = NULL;
    cb->sndsiz = 0;
    cb->stat = TCP_FIN_WAIT_2;
    break;
  }

  /* 如果可以发送新数据报文，则在需要时捎带确认 */
  if(cb->sndbuf == NULL) {
    r = tcp_submit(cb, size ? TCP_ACK : 0);
    if(r >= 0) return r;
    r = 0;
  }

  /* 不能发送新数据报文或没有新数据报文，则在需要时单发确认 */
  if(size) r = tcp_dirsend(cb, NULL, 0, TCP_ACK);
  return r;
}

/* 全局 TCB 控制块 */
static tcb *gtcb;

__attribute__((constructor))
static void gtcb_init(void)
{
  gtcb = (tcb *)malloc(sizeof *gtcb);
  if(gtcb == NULL) abort();
  if(tcb_init(gtcb)) {
    free(gtcb);
    gtcb = NULL;
    abort();
  }
  gtcb->srcport = gSrcPort;
  gtcb->dstport = gDstPort;
  gtcb->srcaddr = getIpv4Address();
  gtcb->dstaddr = getServerIpv4Address();
  gtcb->sndlow = gSeqNum;
  gtcb->sndbeg = gSeqNum + 1;
  gtcb->rcvlow = gAckNum;
  gtcb->rcvbeg = gAckNum + 1;
  gtcb->sndseq = gSeqNum;
}

__attribute__((destructor))
static void gtcb_fini(void)
{
  tcb_destroy(gtcb);
  free(gtcb);
  gtcb = NULL;
}

int stud_tcp_input(char *buf, UINT16 siz, UINT32 src, UINT32 dst)
{
  src = ntohl(src);
  dst = ntohl(dst);
  printf("*** %s: siz=%hu src=%#x dst=%#x\n", __func__, siz, src, dst);
  tcphdr *hdr;
  int r = tcp_recvdown(&hdr, buf, siz, src, dst);
  if(r) return r;
  r = tcp_sendup(gtcb, hdr, siz, src, dst);
  free(hdr);
  return r;
}

void stud_tcp_output(char *data, UINT16 size, unsigned char flags,
    UINT16 srcport, UINT16 dstport, UINT32 srcaddr, UINT32 dstaddr)
{
  printf("*** %s: size=%hu flags=%#hhx"
      " srcport=%hu dstport=%hu srcaddr=%#x dstaddr=%#x\n",
      __func__, size, flags, srcport, dstport, srcaddr, dstaddr);
  int r = tcp_recvup(gtcb, data, size, flags,
      srcport, dstport, srcaddr, dstaddr);
  printf("*** %s: ret=%d\n", __func__, r);
}

/* TCP 套接字表 */
static tcb *tcpsock[SOCKFD_MAX];

int stud_tcp_socket(int domain, int type, int protocol)
{
  printf("*** %s: domain=%d type=%d protocol=%d\n", __func__, domain, type, protocol);

  if(domain != AF_INET) return -1;
  if(type != SOCK_STREAM) return -1;
  if(protocol != IPPROTO_TCP) return -1;

  for(int i = 2; i < SOCKFD_MAX; ++i) {
    if(tcpsock[i] == NULL) {
      tcpsock[i] = (tcb *)malloc(sizeof(tcb));
      if(tcpsock[i] == NULL) return -1;
      if(tcb_init(tcpsock[i])) {
        free(tcpsock[i]);
        tcpsock[i] = NULL;
        return -1;
      }
      tcpsock[i]->srcaddr = getIpv4Address();
      tcpsock[i]->srcport = SOCKPORT_MIN + i;
      printf("*** %s: ret=%d srcaddr=%#x srcport=%d\n",
          __func__, i, tcpsock[i]->srcaddr, tcpsock[i]->srcport);
      return i;
    }
  }

  return -1;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{
  printf("*** %s: sockfd=%d addrlen=%d\n", __func__, sockfd, addrlen);
  if(sockfd < 0 || sockfd >= SOCKFD_MAX || tcpsock[sockfd] == NULL) {
    return -1;
  }
  if(addrlen < (int)sizeof(sockaddr_in)) return -1;

  tcb *cb = tcpsock[sockfd];
  UINT16 srcport = cb->srcport;
  UINT16 dstport = ntohs(addr->sin_port);
  UINT32 srcaddr = cb->srcaddr;
  UINT32 dstaddr = ntohl(addr->sin_addr.s_addr);
  UINT16 siz;
  int r = 0;
  char buf[65535];

  printf("*** %s: sin_family=%hu dstaddr=%#x dstport=%hu\n",
      __func__, addr->sin_family, dstaddr, dstport);
  if(addr->sin_family != AF_INET) return -1;

  /* 设置套接字地址并发送 SYN */
  r = tcp_recvup(cb, NULL, 0, TCP_SYN, srcport, dstport, srcaddr, dstaddr);
  if(r) return r;

  /* 等待 SYNACK */
  r = waitIpPacket(buf, 10);
  if(r < 0) return r;
  siz = r;
  r = 0;

  /* 处理 SYNACK 并返回 ACK */
  tcphdr *hdr;
  r = tcp_recvdown(&hdr, buf, siz, dstaddr, srcaddr);
  if(r) return r;
  r = tcp_sendup(cb, hdr, siz, dstaddr, srcaddr);
  free(hdr);
  if(r == 0) printf("*** %s: success\n", __func__);
  return r;
}

int stud_tcp_send(int sockfd, const unsigned char *buf, UINT16 size, int flags)
{
  printf("*** %s: sockfd=%d size=%hu flags=%#x\n", __func__, sockfd, size, flags);
  if(sockfd < 0 || sockfd >= SOCKFD_MAX || tcpsock[sockfd] == NULL) {
    return -1;
  }
  tcb *cb = tcpsock[sockfd];
  UINT16 siz;
  int r = 0;
  char rcvbuf[65535];

  /* 发送 TCP 报文 */
  r = tcp_recvup(cb, buf, size, flags,
      cb->srcport, cb->dstport, cb->srcaddr, cb->dstaddr);
  if(r) return r;

  /* 等待 ACK */
  r = waitIpPacket(rcvbuf, 10);
  if(r < 0) return r;
  siz = r;
  r = 0;

  /* 处理 ACK */
  tcphdr *hdr;
  r = tcp_recvdown(&hdr, rcvbuf, siz, cb->dstaddr, cb->srcaddr);
  if(r) return r;
  r = tcp_sendup(cb, hdr, siz, cb->dstaddr, cb->srcaddr);
  free(hdr);
  return r;
}

int stud_tcp_recv(int sockfd, unsigned char *buf, UINT16 size, int flags)
{
  printf("*** %s: sockfd=%d size=%hu flags=%#x\n", __func__, sockfd, size, flags);
  if(sockfd < 0 || sockfd >= SOCKFD_MAX || tcpsock[sockfd] == NULL) {
    return -1;
  }
  tcb *cb = tcpsock[sockfd];
  UINT16 siz;
  int r = 0;
  char rcvbuf[65535];

  /* 等待对方发送数据分组 */
  r = waitIpPacket(rcvbuf, 10);
  if(r < 0) return r;
  siz = r;
  r = 0;

  /* 处理对方发送的数据分组并发送 ACK */
  tcphdr *hdr;
  r = tcp_recvdown(&hdr, rcvbuf, siz, cb->dstaddr, cb->srcaddr);
  if(r) return r;
  cb->rcvlen = 0;
  r = tcp_sendup(cb, hdr, siz, cb->dstaddr, cb->srcaddr);
  if(r) {
    free(hdr);
    return r;
  }

  /* 拷贝接收到的数据 */
  if(size > cb->rcvlen) size = cb->rcvlen;
  memcpy(buf, cb->rcvbuf, size);
  free(hdr);
  return 0;
}

int stud_tcp_close(int sockfd)
{
  printf("*** %s: sockfd=%d\n", __func__, sockfd);
  if(sockfd < 0 || sockfd >= SOCKFD_MAX || tcpsock[sockfd] == NULL) {
    return -1;
  }
  tcb *cb = tcpsock[sockfd];
  UINT16 siz;
  int r = 0;
  char rcvbuf[65535];

  if(cb->stat == TCP_SYN_SENT) {
    tcb_destroy(cb);
    free(cb);
    tcpsock[sockfd] = NULL;
    return 0;
  }

  if(cb->stat == TCP_ESTABLISHED) {

    /* 发送 FINACK */
    r = tcp_recvup(cb, NULL, 0, TCP_FIN | TCP_ACK,
        cb->srcport, cb->dstport, cb->srcaddr, cb->dstaddr);
    if(r) return r;

    while(cb->stat != TCP_TIME_WAIT) {
      /* 等待对方分组 */
      r = waitIpPacket(rcvbuf, 10);
      if(r < 0) return r;
      siz = r;
      r = 0;

      /* 处理对方分组并改变状态 */
      tcphdr *hdr;
      r = tcp_recvdown(&hdr, rcvbuf, siz, cb->dstaddr, cb->srcaddr);
      if(r) return r;
      r = tcp_sendup(cb, hdr, siz, cb->dstaddr, cb->srcaddr);
      if(r) {
        free(hdr);
        return r;
      }
    }

    /* 等待一段时间后释放连接 */
    for(int t = 0; t < 10000000; ++t) {
      asm volatile("movl\t%1, %0" : "+r"(t));  /* 防止循环被优化 */
    }
    tcb_destroy(cb);
    free(cb);
    tcpsock[sockfd] = NULL;
    return 0;

  }

  return 1;
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
  assert(type >= STUD_TCP_TEST_SEQNO_ERROR);
  assert(type <= STUD_TCP_TEST_DSTPORT_ERROR);
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
  memset(buf, -1, 16);
  return 16;
}
__attribute__((noinline))
UINT32 getIpv4Address()
{
  return 0x7f000001;  /* 127.0.0.1 */
}
__attribute__((noinline))
UINT32 getServerIpv4Address()
{
  return 0x7f000002;  /* 127.0.0.2 */
}

#else  /* __cplusplus >= 201703 */

/* 所有所需函数均已实现 */

#endif  /* __cplusplus >= 201703 */
