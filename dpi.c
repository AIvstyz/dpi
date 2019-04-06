#include "dpi.h"
#include <stdlib.h>



//初始化dpi模块
//pcap_file :pcap文件地址
//errbuf : 如果出错了，这里就会有错误信息
//返回值：成功返回一个非NULL的句柄，失败返回NULL，errbuf有错误信息
dpi_result *dpi_init(const char *pcap_file,char *errbuf)
{
    dpi_result *res = (dpi_result*)malloc(sizeof(dpi_result));
    //TODO:res要判空

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
void dpi_free(dpi_result *handle)
{
    if(handle==NULL)
        return;
    free(handle);
}
