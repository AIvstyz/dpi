#include <stdio.h>
#include "dpi.h"
#include <string.h>

//回调函数，遍历每个报文 packet header和 packet data 就调用该函数进行处理
//user: 用户自定义参数
//pkthdr:每个报文的packet header
//pktdata:每个报文的packet data
//void pcap_callback_func(unsigned char *user,const struct pcap_pkthdr *pkthdr,const unsigned char *pktdata);

void usage(const char* argv0)
{
    fprintf(stderr,"usage : %s <pcap file>\n",argv0);
}

int main(int argc , char **argv)
{
    if(argc!=2) 
    {
        usage(argv[0]);
        return -1;
    }

    //1 初始化的接口
    char errbuf[DPI_ERR_BUFF_SIZE];
    memset(errbuf,0,sizeof(errbuf));
    dpi_result *handle = dpi_init(argv[1],errbuf);
    if(!handle)
    {
        //错误处理
        fprintf(stderr,"Error in dpi_init : %s\n",errbuf);
        return -1;
    }
    //2 业务处理的接口
    int ret = dpi_pcap_analyze(handle);
    if(ret!=0)
    {
        fprintf(stderr,"Error in dpi_pcap_analyze\n");
        return -1;
    }

    //3 释放的接口
    dpi_free(handle);
    return 0;
}
