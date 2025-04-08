#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// 定义常量
#define MAX_FLOWS 1024
#define MAX_STREAM_SIZE 65535
#define MAX_PACKET_SIZE 65535
#define HTTP_PORT 80
#define HTTPS_PORT 443

// TCP 流的状态枚举
typedef enum {
    FLOW_NEW = 0,
    FLOW_ESTABLISHED,
    FLOW_DATA,
    FLOW_FIN,
    FLOW_CLOSED
} flow_state;

// TCP 流结构
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t next_seq;
    uint32_t init_seq;
    time_t last_seen;
    unsigned char *stream;
    int stream_size;
    flow_state state;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
} tcp_flow_t;

// 全局变量
tcp_flow_t flows[MAX_FLOWS];
int flow_count = 0;

// 函数声明
void cleanup_old_flows(time_t current_time);
void handle_tcp_packet(const struct ip *ip_header, const struct tcphdr *tcp_header,
                       const unsigned char *payload, int payload_len);
void print_flow_info(const tcp_flow_t *flow, const char *event);
void process_stream_data(tcp_flow_t *flow);

// 清理旧的流
void cleanup_old_flows(time_t current_time) {
    const int TIMEOUT = 300; // 5分钟超时
    for (int i = 0; i < flow_count; i++) {
        if (current_time - flows[i].last_seen > TIMEOUT) {
            if (flows[i].stream != NULL) {
                free(flows[i].stream);
            }
            // 移动后面的流向前
            if (i < flow_count - 1) {
                memmove(&flows[i], &flows[i + 1],
                        (flow_count - i - 1) * sizeof(tcp_flow_t));
            }
            flow_count--;
            i--; // 重新检查当前位置
        }
    }
}

// 查找或创建TCP流
tcp_flow_t* find_or_create_flow(const struct ip *ip_header, const struct tcphdr *tcp_header) {
    uint32_t src_ip = ip_header->ip_src.s_addr;
    uint32_t dst_ip = ip_header->ip_dst.s_addr;
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    // 首先查找现有流
    for (int i = 0; i < flow_count; i++) {
        if ((flows[i].src_ip == src_ip && flows[i].dst_ip == dst_ip &&
             flows[i].src_port == src_port && flows[i].dst_port == dst_port) ||
            (flows[i].src_ip == dst_ip && flows[i].dst_ip == src_ip &&
             flows[i].src_port == dst_port && flows[i].dst_port == src_port)) {
            flows[i].last_seen = time(NULL);
            return &flows[i];
        }
    }

    // 如果没找到，创建新流
    if (flow_count < MAX_FLOWS) {
        tcp_flow_t *flow = &flows[flow_count++];
        memset(flow, 0, sizeof(tcp_flow_t));
        flow->src_ip = src_ip;
        flow->dst_ip = dst_ip;
        flow->src_port = src_port;
        flow->dst_port = dst_port;
        flow->next_seq = ntohl(tcp_header->th_seq);
        flow->init_seq = flow->next_seq;
        flow->last_seen = time(NULL);
        flow->state = FLOW_NEW;
        flow->stream = (unsigned char*)malloc(MAX_STREAM_SIZE);
        flow->stream_size = 0;

        // 转换IP地址为字符串
        inet_ntop(AF_INET, &src_ip, flow->src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_ip, flow->dst_ip_str, INET_ADDRSTRLEN);

        return flow;
    }

    return NULL;
}

// 处理TCP数据流
void process_stream_data(tcp_flow_t *flow) {
    if (flow->stream_size == 0) return;

    // 检查是否是HTTP流量
    if (flow->src_port == HTTP_PORT || flow->dst_port == HTTP_PORT) {
        printf("\nHTTP Traffic Detected:\n");
        printf("From %s:%d to %s:%d\n",
               flow->src_ip_str, flow->src_port,
               flow->dst_ip_str, flow->dst_port);

        // 打印前100个字节的内容（或整个内容如果小于100字节）
        int print_size = flow->stream_size < 100 ? flow->stream_size : 100;
        printf("First %d bytes of content:\n", print_size);
        for (int i = 0; i < print_size; i++) {
            if (flow->stream[i] >= 32 && flow->stream[i] <= 126) {
                printf("%c", flow->stream[i]);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

// 处理TCP数据包
void handle_tcp_packet(const struct ip *ip_header, const struct tcphdr *tcp_header,
                       const unsigned char *payload, int payload_len) {
    tcp_flow_t *flow = find_or_create_flow(ip_header, tcp_header);
    if (!flow) return;

    // 处理TCP标志
    if (tcp_header->th_flags & TH_SYN) {
        if (flow->state == FLOW_NEW) {
            flow->state = FLOW_ESTABLISHED;
            flow->next_seq = ntohl(tcp_header->th_seq) + 1;
            print_flow_info(flow, "SYN");
        }
    }
    else if (tcp_header->th_flags & TH_FIN || tcp_header->th_flags & TH_RST) {
        flow->state = FLOW_CLOSED;
        print_flow_info(flow, tcp_header->th_flags & TH_FIN ? "FIN" : "RST");
        process_stream_data(flow);
    }
    else if (payload_len > 0) {
        uint32_t seq = ntohl(tcp_header->th_seq);
        if (seq == flow->next_seq) {
            // 确保不会超出缓冲区
            int copy_len = payload_len;
            if (flow->stream_size + copy_len > MAX_STREAM_SIZE) {
                copy_len = MAX_STREAM_SIZE - flow->stream_size;
            }

            if (copy_len > 0) {
                memcpy(flow->stream + flow->stream_size, payload, copy_len);
                flow->stream_size += copy_len;
                flow->next_seq = seq + copy_len;
                flow->state = FLOW_DATA;
                print_flow_info(flow, "DATA");
            }
        }
    }
}

// 打印流信息
void print_flow_info(const tcp_flow_t *flow, const char *event) {
    printf("\nFlow %s:%d -> %s:%d [%s] (size: %d bytes)\n",
           flow->src_ip_str, flow->src_port,
           flow->dst_ip_str, flow->dst_port,
           event, flow->stream_size);
}

// 数据包处理回调函数
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int packet_count = 0;
    packet_count++;

    // 清理旧的流
    cleanup_old_flows(time(NULL));

    // 解析以太网头部
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // 解析IP头部
    const struct ip *ip_header = (struct ip*)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;

    // 只处理TCP数据包
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    // 解析TCP头部
    const struct tcphdr *tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;

    // 计算负载数据的位置和长度
    const unsigned char *payload = (u_char *)tcp_header + tcp_header_len;
    int payload_len = ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len);

    if (payload_len >= 0) {
        handle_tcp_packet(ip_header, tcp_header, payload, payload_len);
    }

    // 每1000个包打印一次统计信息
    if (packet_count % 1000 == 0) {
        printf("\nProcessed %d packets, tracking %d flows\n", packet_count, flow_count);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net, mask;
    pcap_if_t *alldevs, *d;
    char *dev = NULL;

    // 查找可用设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // 打印可用设备列表
    printf("Available devices:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("- %s", d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }

    // 使用第一个可用设备
    if (alldevs != NULL) {
        dev = strdup(alldevs->name);
        pcap_freealldevs(alldevs);
    }

    if (dev == NULL) {
        fprintf(stderr, "No devices found\n");
        return 1;
    }

    printf("\nUsing device: %s\n", dev);

    // 获取网络信息
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Cannot get netmask for device %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    // 打开设备
    handle = pcap_open_live(dev, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Cannot open device %s: %s\n", dev, errbuf);
        free(dev);
        return 2;
    }

    // 编译过滤器
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Cannot compile filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        free(dev);
        return 3;
    }

    // 设置过滤器
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Cannot set filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        free(dev);
        return 4;
    }

    printf("\nStarting capture on %s...\n", dev);
    printf("Filtering for TCP traffic only\n");
    printf("Press Ctrl+C to stop capture\n\n");

    // 开始捕获
    pcap_loop(handle, -1, packet_handler, NULL);

    // 清理
    pcap_freecode(&fp);
    pcap_close(handle);
    free(dev);

    // 释放所有流的内存
    for (int i = 0; i < flow_count; i++) {
        if (flows[i].stream != NULL) {
            free(flows[i].stream);
        }
    }

    return 0;
}