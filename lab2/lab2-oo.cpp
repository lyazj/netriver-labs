/*
 * IPv4 协议收发实验
 *
 * 作者：高乐耘 <seeson@pku.edu.cn>
 * 创建日期：2023年4月6日
 */

#undef NDEBUG  /* activate assert */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Endian prober.
 *
 * Author: lyazj <seeson@pku.edu.cn>
 * Last Update: Apr 6 2023
 */
#ifdef WIN32
# include <winsock.h>  // compile and link with: -lws2_32
#else  /* WIN32 */
# include <arpa/inet.h>
#endif  /* WIN32 */

#ifndef LITTLE_ENDIAN
# define LITTLE_ENDIAN  1234
#endif  /* LITTLE_ENDIAN */
#ifndef BIG_ENDIAN
# define BIG_ENDIAN  4321
#endif  /* BIG_ENDIAN */
#ifndef BYTE_ORDER
# define BYTE_ORDER  (htonl(1) == 1 ? BIG_ENDIAN : LITTLE_ENDIAN)
#endif  /* BYTE_ORDER */

/*
 * Integer types in Internet byte order.
 *
 * Author: lyazj <seeson@pku.edu.cn>
 * Last Update: Apr 6 2023
 */
#include <stdint.h>

// Converter between T and nint<T>.
template<class T>
class nint_converter {
public:
  static T convert(T t) {
    if(BYTE_ORDER == BIG_ENDIAN) {
      return t;  // already network BO
    }
    T value;  // value with BO reversed
    char *p = (char *)&t + sizeof t;
    char *q = (char *)&value;
    while(p != (char *)&t) {
      *q++ = *--p;
    }
    return value;
  }
};

template<class T>
class nint {
private:
  T value;

  // Conversion between T and nint<T>.
  static T convert(T t) {
    return nint_converter<T>::convert(t);
  }

public:
  nint(T t = T()) {  // T -> nint<T>
    value = convert(t);
  }

  operator T() const {  // nint<T> -> T
    return convert(value);
  }

  T raw() const {  // nint<T> -> T without BO conversion
    return value;
  }
};

typedef nint<uint8_t>   nint8;
typedef nint<uint16_t>  nint16;
typedef nint<uint32_t>  nint32;
typedef nint<uint64_t>  nint64;

template<>
class nint_converter<uint8_t> {
public:
  static uint8_t convert(uint8_t t) {
    return t;
  }
};

template<>
class nint_converter<uint16_t> {
public:
  static uint16_t convert(uint16_t t) {
    return htons(t);
  }
};

template<>
class nint_converter<uint32_t> {
public:
  static uint32_t convert(uint32_t t) {
    return htonl(t);
  }
};

template<>
class nint_converter<uint64_t> {
public:
  static uint64_t convert(uint64_t t) {
    if(BYTE_ORDER == BIG_ENDIAN) return t;  // already network BO
    uint64_t low32 = nint_converter<uint32_t>::convert(t >> 32);
    uint64_t high32 = nint_converter<uint32_t>::convert(t << 32 >> 32);
    return (high32 << 32) | low32;
  }
};

/*
 * Structures relevant to IPv4 packet.
 *
 * Author: lyazj <seeson@pku.edu.cn>
 * Last Update: Apr 6 2023
 */
class ipv4_header {
private:
  char _header_begin[0];
  nint8 _version_and_ihl;
  nint8 _tos;  // type of service
  nint16 _total_length;
  nint16 _identification;
  nint16 _fragment_flags_and_offset;
  nint8 _ttl;  // time to live
  nint8 _protocol;
  nint16 _hcs;  // header checksum
  nint32 _src;  // source address
  nint32 _dst;  // destination address
  char _options_and_padding[0];

  class hcs_updater_16 {  // CAUTION: overlap avoidance
  private:
    uint16_t *hcs, *addr, value;

  public:
    hcs_updater_16(nint16 &h, nint8 &t) {  // for nint8
      hcs = (uint16_t *)&h;
      addr = (uint16_t *)((uintptr_t)&t & -2);
      value = *addr;
    }

    hcs_updater_16(nint16 &h, nint16 &t) {  // for nint16
      hcs = (uint16_t *)&h;
      addr = (uint16_t *)&t;
      value = *addr;
    }

    ~hcs_updater_16() {
      uint32_t s = (uint16_t)~*hcs;
      s += *addr - value;
      s = (s & 0xffff) + (s >> 16);
      *hcs = ~s;
    }
  };

  class hcs_updater_32 {  // CAUTION: overlap avoidance
  private:
    hcs_updater_16 updater[2];

  public:
    hcs_updater_32(nint16 &h, nint32 &t) :
      updater { {h, ((nint16 *)&t)[0]}, {h, ((nint16 *)&t)[1]} }
    {  }
  };

  // These attributes cannot be directly changed by user.
  void version(uint8_t u) {
    hcs_updater_16 updater(_hcs, _version_and_ihl);
    _version_and_ihl = (u << 4) | ihl();
  }
  void ihl(uint8_t u) {
    hcs_updater_16 updater(_hcs, _version_and_ihl);
    _version_and_ihl = (version() << 4) | u;
  }
  void total_length(uint16_t u) {
    hcs_updater_16 updater(_hcs, _total_length);
    _total_length = u;
  }

  nint16 get_hcs() const {  // 16-bit sum of the one's complement
    // NOTE: The 16-bit one's complement sum is BO-insensitive.
    uint16_t *p = (uint16_t *)_header_begin;
    uint16_t *q = p + (header_length() >> 1);
    uint32_t s = 0;
    while(p != q) s += *p++;
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    s = ~s;
    return *(nint16 *)&s;
  }

public:
  // Initialize each field.
  ipv4_header() {
    _version_and_ihl = 0x45;  // IPv4, 20 Bytes
    _tos = 0;  // default service type
    _total_length = 20;  // no data yet
    _identification = 0;  // not used
    _fragment_flags_and_offset = 0x4000;  // disabled
    _ttl = 64;  // recommended
    _protocol = 0;
    _hcs = 0;
    _src = 0;
    _dst = 0;
    _hcs = get_hcs();
  }

  // These attributes cannot be directly changed.
  uint8_t version() const { return _version_and_ihl >> 4; }
  uint8_t ihl() const { return _version_and_ihl & 0xf; }
  uint16_t total_length() const { return _total_length; }

  // RW attributes below.
  uint8_t header_length() const { return ihl() << 2; }
  void header_length(uint8_t u) { ihl((u + 3) >> 2); }

  uint16_t data_length() const { return total_length() - header_length(); }
  void data_length(uint16_t u) { total_length(u + header_length()); }

  uint8_t ttl() const { return _ttl; }
  void ttl(uint8_t u) { hcs_updater_16 updater(_hcs, _ttl); _ttl = u; }

  uint8_t protocol() const { return _protocol; }
  void protocol(uint8_t u) { hcs_updater_16 updater(_hcs, _protocol); _protocol = u; }

  uint32_t src() const { return _src; }
  void src(uint32_t u) { hcs_updater_32 updater(_hcs, _src); _src = u; }

  uint32_t dst() const { return _dst; }
  void dst(uint32_t u) { hcs_updater_32 updater(_hcs, _dst); _dst = u; }

  // Must be called after change ihl/options.
  void update_hcs() {
    _hcs = 0;
    _hcs = get_hcs();
  }

  // Field validations.
  bool validate_hcs() const { return get_hcs() == 0; }
  bool validate_version() const { return version() == 4; }
  bool validate_ihl() const { return ihl() >= 5; }
  bool validate_total_length() const { return total_length() >= header_length(); }
  bool validate_ttl() const { return ttl(); }

  // Addresses for binary I/O.
  char *header() { return _header_begin; }
  char *options() { return _options_and_padding; }
  char *data() { return _header_begin + header_length(); }
};

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
 * 系统函数：丢弃分组
 *
 * pBuffer: 指向被丢弃分组头部的指针
 * type:    分组被丢弃的原因，为 STUD_IP_TEST_*
 */
extern void ip_DiscardPkt(char *pBuffer, int type);

/*
 * 系统函数：发送分组
 *
 * pBuffer: 指向待发送分组头部的指针
 * length:  待发送分组的长度
 */
extern void ip_SendtoLower(char *pBuffer, int length);

/*
 * 系统函数：上交分组
 *
 * pBuffer: 指向要上交的上层协议报文头部的指针
 * length:  上交报文长度
 */
extern void ip_SendtoUp(char *pBuffer, int length);

/*
 * 系统函数：获取本机 IPv4 地址
 */
extern unsigned getIpv4Address(void);

/*
 * 包装函数：丢弃分组
 *
 * header: 指向被丢弃分组头部的指针
 * why:    分组被丢弃的原因，为 STUD_IP_TEST_*
 */
static void discard_packet(ipv4_header *header, int why)
{
  printf("*** %s: vsn=%hhu ihl=%hhu ttl=%hhu dst=%#x why=%d\n", __func__,
      header->version(), header->ihl(), header->ttl(), header->dst(), why);
  ip_DiscardPkt(header->header(), why);
}

/*
 * 包装函数：发送分组
 *
 * header: 指向待发送分组头部的指针
 */
static void send_packet(ipv4_header *header)
{
  printf("*** %s: vsn=%hhu ihl=%hhu ttl=%hhu dst=%#x\n", __func__,
      header->version(), header->ihl(), header->ttl(), header->dst());
  ip_SendtoLower(header->header(), header->total_length());
}

/*
 * 包装函数：上交分组
 *
 * header: 指向待上交分组头部的指针
 */
static void handup_packet(ipv4_header *header)
{
  printf("*** %s: vsn=%hhu ihl=%hhu ttl=%hhu dst=%#x\n", __func__,
      header->version(), header->ihl(), header->ttl(), header->dst());
  ip_SendtoUp(header->data(), header->data_length());
}

/*
 * 帮助函数：判断是否为广播地址
 *
 * addr: 需要判断的 IPv4 地址
 */
static int is_broadcast(UINT32 addr)
{
  return addr == (UINT32)-1;  /* XXX */
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
  UINT32 destination = header->dst();
  return destination == getIpv4Address() || is_broadcast(destination);
}

/*
 * 接收来自下层的 IPv4 分组
 *
 * pBuffer: 指向接收缓冲区的指针，指向 IPv4 分组头部
 * length:  IPv4 分组长度
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

  printf("*** %s: vsn=%hhu ihl=%hhu ttl=%hhu dst=%#x\n", __func__,
      header->version(), header->ihl(), header->ttl(), header->dst());

  /* 检验 IP 版本号 */
  if(!header->validate_version()) {
    discard_packet(header, STUD_IP_TEST_VERSION_ERROR);
    return 1;
  }

  /* 检验头部长度 */
  if(!header->validate_ihl()) {
    discard_packet(header, STUD_IP_TEST_HEADLEN_ERROR);
    return 1;
  }

  /* 检验生存时间 */
  if(!header->validate_ttl()) {
    discard_packet(header, STUD_IP_TEST_TTL_ERROR);
    return 1;
  }

  /* 检验头校验和 */
  if(!header->validate_hcs()) {
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
 * pBuffer:  指向发送缓冲区的指针，指向 IPv4 上层协议数据头部
 * length:   IPv4 上层协议数据长度
 * srcAddr:  源 IPv4 地址
 * dstAddr:  目的 IPv4 地址
 * protocol: IPv4 上层协议号
 * ttl:      生存时间（Time To Live）
 * 退回值
 *     0: 发送成功
 *     1: 发送失败
 */
int stud_ip_Upsend(char *pBuffer, UINT16 length,
    UINT32 srcAddr, UINT32 dstAddr, UINT8 protocol, UINT8 ttl)
{
  ipv4_header *header;

  /* 分配 IPv4 分组缓冲区 */
  header = new ipv4_header;

  /* 填写分组头 */
  header->data_length(length);
  header->ttl(ttl);
  header->protocol(protocol);
  header->src(srcAddr);
  header->dst(dstAddr);

  printf("*** %s: vsn=%hhu ihl=%hhu ttl=%hhu dst=%#x\n", __func__,
      header->version(), header->ihl(), header->ttl(), header->dst());

  /* 拷贝 IPv4 分组数据 */
  memcpy(header->data(), pBuffer, length);

  /* 将分组交给下层发送 */
  send_packet(header);

  /* 释放分配的资源并退回成功码 */
  delete header;
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
