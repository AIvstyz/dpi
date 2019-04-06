#include "dpi.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <pcap/pcap.h>


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
