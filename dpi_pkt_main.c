#include <dpi.h>

//解析ip报文的函数
void dpi_pkt_ip_analyze(dpi_result *res,dpi_pkt *pkt)
{
    //在这里解析ip报文
    //先判断版本号
    if(pkt->ip_pkt->version != 4)
    {
        DPI_LOG_ERROR("Error:IP version not 4\n");
        return;
    }
    //4为首部长度要记住
    size_t ihl = pkt->ip_pkt->ihl<<2;

    //16位的ip报文长度也要记住
    size_t ip_total_len = ntohs(pkt->ip_pkt->tot_len);
    
    //只解析第一个分片，将frag_off跟0x1fff做按位与可以确定后13位是否为0
    //为0表示第一个分片，否则不是
    if((htons(0x1fff) & pkt->ip_pkt->frag_off) !=0)
    {
        DPI_LOG_ERROR("Error:IP not 1st segmemt \n");
        return;
    }

    //根据是TCP报文还是UDP报文来进行解析
    switch(pkt->ip_pkt->protocol)
    {
        case IPPROTO_TCP://6
            //TCP报文解析
            //TCP报文++
            res->tcp_count++;
            //计算TCP报文的起始位置以及长度
            pkt->tcp_pkt = (struct tcphdr*)((char*)pkt->ip_pkt + ihl);
            //TCP报文的长度 = ip报文总长度 - ip报头长度
            pkt->tcp_pkt_len = ip_total_len - ihl;
            break;
        case IPPROTO_UDP://17
            //UDP报文解析
            res->udp_count++;
            pkt->udp_pkt = (struct udphdr*)((char*)pkt->ip_pkt + ihl);
            pkt->udp_pkt_len = ip_total_len - ihl;
            break;
        default:
            break;
    }


}
