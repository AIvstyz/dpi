#pragma once
#include <stdint.h>

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

//
//    //3 业务处理（循环去读取每一个报文的packet header）
//    //回调函数地址
//    pcap_handler callback = pcap_callback_func;
//    //用户自定义参数
//    unsigned char user = 123;
//    int res = pcap_loop(pcap,-1,callback,&user);
//    if(res<0)
//    {
//        fprintf(stderr,"Error in pcap loop \n");
//    }
//
//    //4 清理垃圾
//    pcap_close(pcap);
