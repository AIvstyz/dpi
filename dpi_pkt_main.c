#include <dpi.h>

//解析TCP报文的函数
void dpi_pkt_tcp_analyze(dpi_result *res,dpi_pkt *pkt);
//解析UDP报文的函数
void dpi_pkt_udp_analyze(dpi_result *res,dpi_pkt *pkt);

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
            if(pkt->tcp_pkt_len>0)
            {
                dpi_pkt_tcp_analyze(res,pkt);
            }
            break;
        case IPPROTO_UDP://17
            //UDP报文解析
            res->udp_count++;
            pkt->udp_pkt = (struct udphdr*)((char*)pkt->ip_pkt + ihl);
            pkt->udp_pkt_len = ip_total_len - ihl;
            if(pkt->udp_pkt_len>0)
            {
                dpi_pkt_udp_analyze(res,pkt);
            }
            break;
        default:
            break;
    }
}

//解析TCP报文的函数
void dpi_pkt_tcp_analyze(dpi_result *res,dpi_pkt *pkt)
{
    //TCP报文的长度至少是20
    if(pkt->tcp_pkt_len<sizeof(struct tcphdr))
    {
        return;
    }

    //记住TCP报文的首部长度
    size_t tcp_hl = pkt->tcp_pkt->doff << 2;

    //计算数据区域的起始位置
    pkt->payload = (unsigned char*)pkt->tcp_pkt + tcp_hl;
    //计算数据区域的长度
    pkt->payload_len = pkt->tcp_pkt_len - tcp_hl;
        
    //做保护，判断数据区域有没有数据
    if(pkt->payload_len<=0)
    {
        //没有携带数据的tcp报文，比如握手包
        return;
    }

    //解析应用层协议，使用循环遍历数组的方式，调用每一个识别函数
    int i;
    for(i = 0 ; i< ProtocolEnd ; ++i )
    {
        if(dpi_detect_func_arr[i](pkt)==1)
        {
            //识别出了某个协议
            //识别出来的协议的枚举值是 i
            if(i==SSH)
            {
                DPI_LOG_DEBUG("Protocol is SSH\n");
                res->ssh_count++;
            }
        }
    }


}

//解析UDP报文的函数
void dpi_pkt_udp_analyze(dpi_result *res,dpi_pkt *pkt)
{

}
