/*
 * IPv4 协议转发实验
 *
 * 从下层接收 IPv4 分组：
 * - 如果目的地址为本机地址，上交
 * - 否则如果有匹配路由规则，转发
 * - 否则丢弃
 *
 * 作者：高乐耘 <seeson@pku.edu.cn>
 * 创建日期：2023年4月13日
 */

#undef NDEBUG  /* activate assert */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <new>

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
    hcs_updater_16 high, low;

  public:
    hcs_updater_32(nint16 &h, nint32 &t) :
      high(h, ((nint16 *)&t)[0]), low(h, ((nint16 *)&t)[1])
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

// Routing table implemented by Trie.
class routing_table {
private:
  routing_table *child[2];  // child table address, NULL if not exists
  uint32_t nhop;  // next-hop address, 0 being an invalid address

public:
  // Create a node mapped to address 0.0.0.0.
  routing_table() {
    memset(child, 0, sizeof child);
    nhop = 0;
  }

  // Set a routing rule.
  //     addr: destination address
  //     mlen: mask length
  //     value: next-hop address
  void set(uint32_t addr, uint32_t mlen, uint32_t value) {
    if(mlen == 0) {  // no more indexing bits
      nhop = value;
      return;
    }
    uint32_t hbit = addr >> 31;
    // If the child node doesn't exist, create it.
    if(child[hbit] == NULL) child[hbit] = new routing_table;
    child[hbit]->set(addr << 1, mlen - 1, value);
  }

  // Get the routing rule matching the longest prefix.
  //     addr: destination address
  //     mlen: mask length
  //     @ret: next-hop address
  uint32_t get(uint32_t addr, uint32_t mlen = 32) const {
    if(mlen == 0) {  // no more indexing bits
      return nhop;
    }
    uint32_t hbit = addr >> 31;
    // If the child node doesn't exist, here is the longest match.
    if(child[hbit] == NULL) return nhop;
    return child[hbit]->get(addr << 1, mlen - 1);
  }
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
 * 丢弃分组的原因
 */
#define STUD_FORWARD_TEST_TTLERROR  1
#define STUD_FORWARD_TEST_NOROUTE   1

#else  /* __unix__ */

#include "sysinclude.h"

#endif  /* __unix__ */

/*
 * 路由信息
 */
typedef struct stud_route_msg {
  unsigned int dest;
  unsigned int masklen;
  unsigned int nexthop;
} stud_route_msg;

/*
 * 系统函数：下放分组
 *
 * buf:  指向分组的指针
 * len:  分组长度
 * nhop: 下一跳 IPv4 地址
 */
extern void fwd_SendtoLower(char *buf, int len, unsigned int nhop);

/*
 * 系统函数：上交分组
 *
 * buf: 指向分组的指针
 * len: 分组长度
 */
extern void fwd_LocalRcv(char *buf, int len);

/*
 * 系统函数：丢弃分组
 *
 * buf: 指向分组的指针
 * why: 丢弃原因，为 STUD_FORWARD_TEST_*
 */
extern void fwd_DiscardPkt(char *buf, int type);

/*
 * 系统函数：获取本机 IPv4 地址
 */
extern UINT32 getIpv4Address();

/*
 * 全局路由表
 */
static routing_table routing;
static bool routing_default;

/*
 * 接口函数：初始化路由表
 */
void stud_Route_Init()
{
  // nop
}

/*
 * 接口函数：添加路由规则
 *
 * proute: 具体规则
 */
void stud_route_add(const stud_route_msg *msg)
{
  printf("*** %s: %#x/%u -> %#x",
      __func__, msg->dest, msg->masklen, msg->nexthop);
  if(msg->masklen == 0) routing_default = true;
  routing.set(msg->dest, msg->masklen, msg->nexthop);
}

/*
 * 接口函数：处理分组
 *
 * buf:  指向分组的指针
 * len:  分组长度
 * @ret: 成功为 0，失败为 1
 */
int stud_fwd_deal(char *buf, int len)
{
  ipv4_header *header = (ipv4_header *)buf;
  uint32_t addr = header->dst(), nhop;
  uint8_t ttl;

  /* 判断是否需要本机接收 */
  if(addr == getIpv4Address()) {
    printf("*** %s", "fwd_LocalRcv");
    fwd_LocalRcv(buf, len);
    return 0;
  }

  /* 如无路由规则则丢弃 */
  nhop = routing.get(addr);
  if(nhop == 0 && !routing_default) {
    printf("*** %s: %d", "fwd_DiscardPkt", STUD_FORWARD_TEST_NOROUTE);
    fwd_DiscardPkt(buf, STUD_FORWARD_TEST_NOROUTE);
    return 1;
  }

  /* 修改 TTL，归零则丢弃 */
  ttl = header->ttl() - 1;
  if(ttl == 0) {
    printf("*** %s: %d", "fwd_DiscardPkt", STUD_FORWARD_TEST_TTLERROR);
    fwd_DiscardPkt(buf, STUD_FORWARD_TEST_TTLERROR);
    return 1;
  }
  header->ttl(ttl);

  /* 发送分组 */
  printf("*** %s: %#x", "fwd_SendtoLower", nhop);
  fwd_SendtoLower(buf, len, nhop);
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
  routing_table table;
  assert(table.get(0xc0a80001) == 0);
  assert(table.get(0x7f000001) == 0);
  table.set(0x7f000000, 8, 0x7f000001);
  assert(table.get(0xc0a80001) == 0);
  assert(table.get(0x7f000001) == 0x7f000001);
  table.set(0xc0a80000, 24, 0xc0a80101);
  assert(table.get(0xc0a80001) == 0xc0a80101);
  assert(table.get(0x7f000001) == 0x7f000001);
  table.set(0xc0a80001, 32, 0xffffffff);
  assert(table.get(0xc0a80001) == 0xffffffff);
  assert(table.get(0x7f000001) == 0x7f000001);
  table.set(0xc0a80001, 32, 0);
  assert(table.get(0xc0a80001) == 0);
  assert(table.get(0x7f000001) == 0x7f000001);
  return 0;
}

/*
 * 本地空壳函数
 */
void fwd_SendtoLower(char *buf, int len, unsigned int nhop)
{
  assert(buf);
  assert(len);
  assert(nhop);
}
void fwd_LocalRcv(char *buf, int len)
{
  assert(buf);
  assert(len);
}
void fwd_DiscardPkt(char *buf, int type)
{
  assert(buf);
  assert(type == STUD_FORWARD_TEST_NOROUTE
      || type == STUD_FORWARD_TEST_TTLERROR);
}
UINT32 getIpv4Address()
{
  return 0x7f000001;  // 127.0.0.1
}

#endif  /* __cplusplus >= 201703 */
