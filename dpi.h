#pragma once
#include <stdint.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

#define DPI_ERR_BUFF_SIZE 256

#define DPI_LOG_DEBUG(...)  do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_INFO(...)  do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_ERROR(...)  do{fprintf(stderr,__VA_ARGS__);}while(0)


//定义dpi接口的头文件
typedef struct dpi_result
{
    void *pcap_handle;     //pcap句柄的指针
    uint32_t ether_count;  //以太网报文数量
    uint32_t ip_count;     //ip报文的数量
    uint32_t tcp_count;    //tcp报文的数量
    uint32_t udp_count;    //udp报文的数量
    uint32_t ssh_count;
    //...
}dpi_result;

//定义结构体来标识一个报文每个协议的起始位置和长度
typedef struct dpi_pkt
{
    const struct ether_header *ether_pkt;           //以太网报文地址
    uint32_t ether_len;                             //以太网报文长度
    const struct iphdr *ip_pkt;              //ip报文地址
    uint32_t ip_pkt_len;                //ip报文长度
    union
    {
        //共同体，如果是TCP报文，就不可能是UDP报文
        struct
        {
            const struct tcphdr *tcp_pkt;             //tcp报文地址
            uint32_t tcp_pkt_len;               //tcp报文长度
        };
        struct
        {
            const struct udphdr *udp_pkt;             //udp报文地址
            uint32_t udp_pkt_len;               //udp报文长度
        };
    };
    const unsigned char *payload;             //应用层报文地址
    uint32_t payload_len;               //应用层报文长度
}dpi_pkt;

//初始化dpi模块
//pcap_file :pcap文件地址
//errbuf : 如果出错了，这里就会有错误信息
//返回值：成功返回一个非NULL的句柄，失败返回NULL，errbuf有错误信息
dpi_result *dpi_init(const char *pcap_file,char *errbuf);


//业务处理接口，分析每个报文
//handle ：就是dpi_init 拿到的句柄
//返回值，成功返回0，失败返回非0
int dpi_pcap_analyze(dpi_result *handle);


//释放的接口
//handle ：就是dpi_init 拿到的句柄
void dpi_free(dpi_result *handle);


//定义协议识别函数类型,检测某个报文是否某个协议的报文是，返回1，否返回0，出错返回-1
typedef int (*dpi_protocol_detect_func)(dpi_pkt *pkt);

//定义支持的协议
enum dpi_protocol
{
    ProtocolBegin=-1,
#ifndef DPI_NO_SSH_SUPPORT
    SSH,
#endif
    //Telnet,
    //Http,
    //FTP,
    ProtocolEnd
};

//是dpi项目的协议识别函数指针数组
extern dpi_protocol_detect_func dpi_detect_func_arr[ProtocolEnd];


