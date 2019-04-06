#include "dpi.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <pcap/pcap.h>

//定义一个回调函数供pcap库来进行回调 
void dpi_pcap_callback(u_char *user,const struct pcap_pkthdr *header,
        const u_char *data);

//初始化dpi模块
//pcap_file :pcap文件地址
//errbuf : 如果出错了，这里就会有错误信息
//返回值：成功返回一个非NULL的句柄，失败返回NULL，errbuf有错误信息
dpi_result *dpi_init(const char *pcap_file,char *errbuf)
{
    //打开pcap文件，有错报错
    pcap_t *pcap = pcap_open_offline(pcap_file,errbuf);
    if(pcap==NULL)
    {
        return NULL;
    }

    //创建一个句柄，也是结果集结构体
    dpi_result *res = (dpi_result*)malloc(sizeof(dpi_result));
    assert(res);
    //断言assert =  if(!res)exit(-1); 断言在release下是无效
    memset(res,0,sizeof(dpi_result));

    //将pcap句柄也存到 res里边
    res->pcap_handle = pcap;
    return res;
}


//业务处理接口，分析每个报文
//handle ：就是dpi_init 拿到的句柄
//返回值，成功返回0，失败返回非0
int dpi_pcap_analyze(dpi_result *handle)
{
    //遍历pcap文件去识别和统计报文
    int res = pcap_loop(handle->pcap_handle,-1,dpi_pcap_callback,NULL);
    return 0;
}

//释放的接口
//handle ：就是dpi_init 拿到的句柄
void dpi_free(dpi_result *res)
{
    if(res==NULL)
        return;
    //释放pcap的句柄
    pcap_close(res->pcap_handle);
    //释放整个 result 结构
    free(res);
}


//pcap回调函数的实现
void dpi_pcap_callback(u_char *user,const struct pcap_pkthdr *header,
        const u_char *data)
{
    DPI_LOG_DEBUG("dpi_pcap_callback\n");
}
