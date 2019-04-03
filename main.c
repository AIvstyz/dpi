#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pcap/pcap.h>
#include <stdint.h>

//回调函数，遍历每个报文 packet header和 packet data 就调用该函数进行处理
//user: 用户自定义参数
//pkthdr:每个报文的packet header
//pktdata:每个报文的packet data
void pcap_callback_func(unsigned char *user,const struct pcap_pkthdr *pkthdr,const unsigned char *pktdata);

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

    //1 打开pcap文件
    char errbuf[PCAP_ERRBUF_SIZE]={0}; 
    pcap_t *pcap = pcap_open_offline(argv[1],errbuf);
    if(pcap==NULL)
    {
        fprintf(stderr,"Error in pcap open : %s\n",errbuf);
        return -1;
    }

    //3 业务处理（循环去读取每一个报文的packet header）
    //回调函数地址
    pcap_handler callback = pcap_callback_func;
    //用户自定义参数
    unsigned char user = 123;
    int res = pcap_loop(pcap,-1,callback,&user);
    if(res<0)
    {
        fprintf(stderr,"Error in pcap loop \n");
    }

    //4 清理垃圾
    pcap_close(pcap);
    return 0;
}

void pcap_callback_func(unsigned char *user,const struct pcap_pkthdr *pkthdr,const unsigned char *pktdata)
{
    printf("user: %d ,caplen : %d ,  len : %d\n",*user,pkthdr->caplen,pkthdr->len);
}
