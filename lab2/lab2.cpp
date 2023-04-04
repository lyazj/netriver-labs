/*
 * IPv4 协议收发实验
 *
 * 作者：高乐耘 <seeson@pku.edu.cn>
 * 创建日期：2023年4月4日
 */

/*
 * 系统函数：丢弃分组
 *
 * pBuffer: 指向被丢弃分组的指针
 * type: 分组被丢弃的原因，为 STUD_IP_TEST_*
 */
extern void ip_DiscardPkt(char *pBuffer, int type);

/*
 * 系统函数：发送分组
 *
 * pBuffer: 指向待发送分组头部的指针
 * length: 待发送分组的长度
 */
extern void ip_SendtoLower(char *pBuffer, int length);

/*
 * 系统函数：上交分组
 *
 * pBuffer: 指向要上交的上层协议报文头部的指针
 * length: 上交报文长度
 */
extern void ip_SendtoUp(char *pBuffer, int length);

/*
 * 系统函数：获取本机 IPv4 地址
 */
extern unsigned getIpv4Address(void);

#undef NDEBUG  /* activate assert */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
 * 分组被丢弃的原因
 */
#define STUD_IP_TEST_CHECKSUM_ERROR      1  /* IP 校验和出错 */
#define STUD_IP_TEST_TTL_ERROR           2  /* TTL 值出错 */
#define STUD_IP_TEST_VERSION_ERROR       4  /* IP 版本号错 */
#define STUD_IP_TEST_HEADLEN_ERROR       8  /* 头部长度错 */
#define STUD_IP_TEST_DESTINATION_ERROR  16  /* 目的地址错 */

#else  /* __unix__ */

#include "sysinclude.h"

#endif  /* __unix__ */

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
static UINT16 bswap16(UINT16 u16)
{
  UINT16 u0 = (u16 >> 8) & 0xff;
  UINT16 u1 = (u16 >> 0) & 0xff;
  return (u0 << 0) | (u1 << 8);
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
static UINT16 ntoh16(UINT16 u16)
{
  if(endian()) {  /* 应从大到小 */
    return bswap16(u16);
  }
  return u16;
}

/*
 * 帮助函数：主机字节序 -> 网络字节序
 */
static UINT32 hton32(UINT32 u32)
{
  return ntoh32(u32);
}
static UINT16 hton16(UINT16 u16)
{
  return ntoh16(u16);
}

/*
 * IPv4 协议头
 */
typedef struct ipv4_header {
  UINT8 version : 4;            /* 当前使用的 IP 协议版本 */
  UINT8 ip_header_length : 4;   /* IP 协议头长度，至少为 5（20 字节） */
  UINT8 type_of_service : 6;    /* 期望的服务质量 */
  UINT8 hole_0 : 2;             /* 填充空洞 0 */
  UINT16 total_length;          /* 包括头部的分组全长 */
  UINT16 identification;        /* 数据报分片标识 */
  UINT8 hole_1 : 1;             /* 填充空洞 1 */
  UINT8 df : 1;                 /* 是否为最后分片 */
  UINT8 mf : 1;                 /* 是否分片 */
  UINT16 fragment_offset : 13;  /* 与源数据报的起始端相关的分片数据位置 */
  UINT8 time_to_live;           /* 剩余可转发跳数 */
  UINT8 protocol;               /* 上层协议 */
  UINT16 header_checksum;       /* IP 协议头校验和 */
  UINT32 source_address;        /* 源 IPv4 地址 */
  UINT32 destination_address;   /* 目标 IPv4 地址 */
  char options[0];              /* 变长的各种选项 */
} ipv4_header;

/*
 * 包装函数：丢弃分组
 *
 * header: 指向被丢弃分组头部的指针
 * why: 分组被丢弃的原因，为 STUD_IP_TEST_*
 */
static void discard_packet(ipv4_header *header, int why)
{
  printf("*** %s: id=%d\n", __func__, ntoh16(header->identification));
  ip_DiscardPkt((char *)header, why);
}

/*
 * 包装函数：发送分组
 *
 * header: 指向待发送分组头部的指针
 */
static void send_packet(ipv4_header *header)
{
  printf("*** %s: id=%d\n", __func__, ntoh16(header->identification));
  ip_SendtoLower((char *)header, ntoh16(header->total_length));
}

/*
 * 包装函数：上交分组
 *
 * header: 指向待上交分组头部的指针
 */
static void handup_packet(ipv4_header *header)
{
  int header_length, data_length;

  /* 分别获取头部和数据报文长度 */
  header_length = header->ip_header_length << 2;
  data_length = ntoh16(header->total_length) - header_length;

  printf("*** %s: id=%d\n", __func__, ntoh16(header->identification));
  ip_SendtoUp((char *)header + header_length, data_length);
}

/*
 * 帮助函数：判断是否为广播地址
 *
 * addr: 需要判断的 IPv4 地址
 */
static int is_broadcast(UINT32 addr)
{
  return addr == (UINT32)-1;  /* FIXME */
}

/*
 * 帮助函数：校验分组目标地址
 *
 * header: 指向待校验分组头部的指针
 * 退回值
 *     0: 本机不应接收
 *     1: 本机应当接收
 */
static int validate_packet_destination(const ipv4_header *header)
{
  return header->destination_address == getIpv4Address()
    || is_broadcast(header->destination_address);
}

/*
 * 帮助函数：计算分组校验和
 *
 * header: 指向待校验分组头部的指针
 */
static UINT16 get_packet_header_checksum(const ipv4_header *header)
{
  UINT32 cs = 0, cs_high16;

  for(UINT16 *p = (UINT16 *)header; p != (UINT16 *)header->options; ++p) {
    cs += ntoh16(*p);  /* 按 16-bit 分组求和 */
  }
  for(;;) {  /* 消去求和结果的高 16 位 */
    cs_high16 = cs >> 16;
    if(cs_high16 == 0) break;
    cs = (cs & 0xffff) + cs_high16;
  }
  return ~cs;
}

/*
 * 帮助函数：写入分组校验和
 *
 * header: 指向待校验分组头部的指针
 */
static void write_packet_header_checksum(ipv4_header *header)
{
  UINT16 cs;

  header->header_checksum = 0;
  cs = get_packet_header_checksum(header);
  header->header_checksum = hton16(cs);
}

/*
 * 帮助函数：检验分组校验和
 *
 * header: 指向待校验分组头部的指针
 * 退回值
 *     0: 校验失败
 *     1: 检验成功
 */
static int validate_packet_header_checksum(const ipv4_header *header)
{
  return get_packet_header_checksum(header) == 0;
}

/*
 * 接收来自下层的 IPv4 分组
 *
 * pBuffer: 指向接收缓冲区的指针，指向 IPv4 分组头部
 * length: IPv4 分组长度
 * 退回值
 *     0: 接收成功，IP 分组被交给上层
 *     1: 接收失败，IP 分组被丢弃
 */
int stud_ip_recv(char *pBuffer, UINT16 length)
{
  ipv4_header *header;  /* 接收缓冲区中的 IPv4 头部 */

  /* 确保缓冲区长度达到 IPv4 头部的最小长度 */
  assert(length >= sizeof(ipv4_header));
  header = (ipv4_header *)pBuffer;

  /* 检验 IP 版本号 */
  if(header->version != 4) {
    discard_packet(header, STUD_IP_TEST_VERSION_ERROR);
    return 1;
  }

  /* 检验头部长度 */
  if((header->ip_header_length << 2) < (int)sizeof(ipv4_header)) {
    discard_packet(header, STUD_IP_TEST_HEADLEN_ERROR);
    return 1;
  }

  /* 检验生存时间 */
  if(header->time_to_live == 0) {
    discard_packet(header, STUD_IP_TEST_TTL_ERROR);
    return 1;
  }

  /* 检验头校验和 */
  if(validate_packet_header_checksum(header) == 0) {
    discard_packet(header, STUD_IP_TEST_CHECKSUM_ERROR);
    return 1;
  }

  /* 检验目标 IPv4 地址 */
  if(validate_packet_destination(header) == 0) {
    discard_packet(header, STUD_IP_TEST_DESTINATION_ERROR);
    return 1;
  }

  /* 通过所有校验，接收并上交上层 */
  handup_packet(header);
  return 0;
}

/*
 * 发送来自上层的数据报文
 *
 * pBuffer: 指向发送缓冲区的指针，指向 IPv4 上层协议数据头部
 * length: IPv4 上层协议数据长度
 * srcAddr: 源 IPv4 地址
 * dstAddr: 目的 IPv4 地址
 * protocol: IPv4 上层协议号
 * ttl: 生存时间（Time To Live）
 * 退回值
 *     0: 发送成功
 *     1: 发送失败
 */
int stud_ip_Upsend(char *pBuffer, UINT16 length,
    UINT32 srcAddr, UINT32 dstAddr, UINT8 protocol, UINT8 ttl)
{
  ipv4_header *header;

  /* 分配 IPv4 分组缓冲区 */
  header = (ipv4_header *)malloc(length + sizeof *header);
  if(header == NULL) return 1;  /* 无法分配内存，发送失败 */

  /* 填写分组头 */
  header->version = 4;
  header->ip_header_length = 5;
  header->type_of_service = 0;  /* FIXME */
  header->hole_0 = 0;
  header->total_length = hton16(length + sizeof *header);
  header->identification = hton16(rand());
  header->hole_1 = 0;
  header->df = 0;
  header->mf = 0;
  header->fragment_offset = 0;
  header->time_to_live = ttl;
  header->protocol = protocol;
  header->source_address = srcAddr;
  header->destination_address = dstAddr;
  write_packet_header_checksum(header);

  /* 拷贝 IPv4 分组数据 */
  memcpy(header->options, pBuffer, length);

  /* 将分组交给下层发送 */
  send_packet(header);

  /* 释放分配的资源并退回成功码 */
  free(header);
  return 0;
}

#if __cplusplus >= 201703  /* 我的笔记本/机房台式机编译环境 */

/*
 * 本地测试
 */
int main(void)
{
  ipv4_header header;
  printf("Hello from %s()!\n", __func__);
  assert(sizeof header == 20);
  assert(endian() == 1);
  assert(ntoh32(0x01000000) == 1);
  assert(hton32(0x01000000) == 1);
  assert(ntoh16(0x0100) == 1);
  assert(hton16(0x0100) == 1);
  return 0;
}

/*
 * 本地空壳函数
 */
void ip_DiscardPkt(char *pBuffer, int type)
{
  assert(pBuffer != NULL);
  assert(type >= 1 && type <= 31);
}
void ip_SendtoLower(char *pBuffer, int length)
{
  assert(pBuffer != NULL);
  assert(length >= (int)sizeof(ipv4_header));
}
void ip_SendtoUp(char *pBuffer, int length)
{
  assert(pBuffer != NULL);
  assert(length >= 0);
}
unsigned getIpv4Address(void)
{
  return 0;
}

#endif  /* __cplusplus >= 201703 */
