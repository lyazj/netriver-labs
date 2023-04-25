#include <stdint.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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
  UINT64 cs = htonl(src) + htonl(dst) + htons(6) + htons(siz);
  size_t n = siz >> 2;
  UINT32 *p = (UINT32 *)hdr, rem = 0;
  asm("":::"memory");  // 在 strict aliasing 下充当内存屏障
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

int main(void)
{
  tcphdr *hdr = (tcphdr *)malloc(65535);
  UINT16 *p;
  int n;
  UINT32 cs;

  hdr->srcport = htons(56364);
  hdr->dstport = htons(10001);
  hdr->seq = htonl(0x53dc167f);
  hdr->ack = htonl(0x0077cef9);
  hdr->flags = htons(TCP_ENC_THL(20) | TCP_PSH | TCP_ACK);
  hdr->win = htons(4096);
  hdr->cs = 0;
  hdr->up = 0;
  memcpy(hdr->op,
      "\x54\x68\x69\x73"
      "\x20\x69\x73\x20"
      "\x61\x20\x54\x43"
      "\x50\x20\x6d\x65"
      "\x73\x73\x61\x67"
      "\x65\x00        ",
      22
  );
  hdr->cs = tcp_cs(hdr, 42, 0xa9fe5205, 0xa9fe5263);

  for(int i = 0; i < 42; i += 16) {
    for(int j = i; j < i + 16 && j < 42; ++j) {
      printf(" %02hhx", ((char *)hdr)[j]);
    }
    printf("\n");
  }

  p = (UINT16 *)hdr;
  n = 21;
  cs = 0;
  cs += 0xa9fe;
  cs += 0x5205;
  cs += 0xa9fe;
  cs += 0x5263;
  cs += 0x002a;
  cs += 0x0006;
  for(int i = 0; i < n; ++i) {
    cs += ntohs(p[i]);
  }
  cs = (cs & 0xffff) + (cs >> 16);
  cs = (cs & 0xffff) + (cs >> 16);
  cs = (cs & 0xffff) + (cs >> 16);
  cs = ~htons(cs);

  printf("checksum=%#hx\n", hdr->cs);
  printf("checksum=%#hx\n", (UINT16)cs);
  printf("expected=%#hx\n", (UINT16)0x1d6c);

  free(hdr);
  return 0;
}
