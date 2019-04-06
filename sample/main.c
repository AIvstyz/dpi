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


void displayResult(dpi_result *res)
{
    printf("============================================\n");
    printf("ether packet count:\t%d\n",res->ether_count);
    printf("ip packet count:\t%d\n",res->ip_count);
    printf("tcp packet count:\t%d\n",res->tcp_count);
    printf("udp packet count:\t%d\n",res->udp_count);
    printf("ssh packet count:\t%d\n",res->ssh_count);
    printf("============================================\n");
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
    //handle既是句柄也是最终的结果集
    dpi_result *res = dpi_init(argv[1],errbuf);
    if(!res)
    {
        //错误处理
        fprintf(stderr,"Error in dpi_init : %s\n",errbuf);
        return -1;
    }
    //2 业务处理的接口
    int ret = dpi_pcap_analyze(res);
    if(ret!=0)
    {
        fprintf(stderr,"Error in dpi_pcap_analyze\n");
        return -1;
    }
    else
    {
        //输出处理结果，打印报文的数量
        displayResult(res);
    }

    //3 释放的接口
    dpi_free(res);
    return 0;
}
