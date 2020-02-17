 #!/usr/bin/python
 # test_lb.py
 
 from bcc import BPF
 import pyroute2
 import time
 import sys
 import os
 import ConfigParser
 import ast
 
 flags = 0
 def usage():
     print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
     print("       -S: use skb mode\n")
     print("       -H: use hardware offload mode\n")
     print("e.g.: {0} eth0\n".format(sys.argv[0]))
     exit(1)
 
 if len(sys.argv) < 2 or len(sys.argv) > 3:
     usage()
 
 offload_device = None
 if len(sys.argv) == 2:
     device = sys.argv[1]
 elif len(sys.argv) == 3:
     device = sys.argv[2]
 
 maptype = "percpu_array"
 if len(sys.argv) == 3:
     if "-S" in sys.argv:
         # XDP_FLAGS_SKB_MODE
         flags |= (1 << 1)
     if "-H" in sys.argv:
         # XDP_FLAGS_HW_MODE
         maptype = "array"
         offload_device = device
         flags |= (1 << 3)
 
 mode = BPF.XDP
 #mode = BPF.SCHED_CLS
 
 if mode == BPF.XDP:
     ret = "XDP_PASS"
     ctxtype = "xdp_md"
 else:
     ret = "TC_ACT_SHOT"
     ctxtype = "__sk_buff"
 
 code = """
 #define KBUILD_MODNAME "foo"
 #include <uapi/linux/bpf.h>
 #include <linux/in.h>
 #include <linux/if_ether.h>
 #include <linux/if_packet.h>
 #include <linux/if_vlan.h>
 #include <linux/ip.h>
 #include <linux/ipv6.h>
 #include <linux/icmp.h>
 #include <linux/if_ether.h>
 #include <linux/if_vlan.h>
 #include <linux/in.h>
 #include <linux/ip.h>
 #include <linux/tcp.h>
 #include <linux/udp.h>
 
 /* 0x3FFF mask to check for fragment offset field */
 #define IP_FRAGMENTED 65343
 #define MAX_ADDR 32
 struct pkt_meta {
         __be32 src;
         __be32 dst;
         union {
                 __u32 ports;
                 __u16 port16[2];
         };
 };
 
 struct dest_info {
         __u32 saddr;
         __u32 daddr;
         __u64 bytes;
         __u64 pkts;
         __u8 dmac[6];
 };
 
 BPF_TABLE(MAPTYPE, uint32_t, long, cnt, 256);
 BPF_TABLE(MAPTYPE, uint32_t, long, cnt2, 256);
 BPF_TABLE(MAPTYPE, uint32_t, long, cnt3, 256);
 
 static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
                                       struct pkt_meta *pkt)
 {
         struct udphdr *udp;
 
         udp = data + off;
         if (udp + 1 > data_end)
                 return false;
 
         pkt->port16[0] = udp->source;
         pkt->port16[1] = udp->dest;
 
         return true;
 }
 
 static __always_inline bool parse_tcp(void *data, __u64 off, void *data_end,
                                       struct pkt_meta *pkt)
 {
         struct tcphdr *tcp;
 
         tcp = data + off;
         if (tcp + 1 > data_end)
                 return false;
 
         pkt->port16[0] = tcp->source;
         pkt->port16[1] = tcp->dest;
 
         return true;
 }
 
 static __always_inline void set_ethhdr(struct ethhdr *new_eth,
                                        const struct ethhdr *old_eth,
                                        __be16 h_proto)
 {
         // 44:ec:ce:c1:6d:29
         __u8 dmac[6];
         dmac[0]=0x44;
         dmac[1]=0xec;
         dmac[2]=0xce;
         dmac[3]=0xc1;
         dmac[4]=0x6d;
         dmac[5]=0x29;
         memcpy(new_eth->h_source, old_eth->h_dest, sizeof(new_eth->h_source));
         memcpy(new_eth->h_dest, dmac, sizeof(new_eth->h_dest));
         new_eth->h_proto = h_proto;
 }
 
 static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
 {
         void *data_end = (void *)(long)ctx->data_end;
         void *data = (void *)(long)ctx->data;
         struct pkt_meta pkt = {};
         struct ethhdr *new_eth;
         struct ethhdr *old_eth;
         struct dest_info *tnl;
         struct iphdr iph_tnl;
         struct iphdr *iph;
         __u16 *next_iph_u16;
         __u16 pkt_size;
         __u16 payload_len;
         __u8 protocol;
         u32 csum = 0, n=2;
         __u32 saved_addr[MAX_ADDR] = {};
         iph = data + off;
 
         if (iph + 1 > data_end)
                 return XDP_PASS;
         if (iph->ihl != 5)
                 return XDP_PASS;
 
         protocol = iph->protocol;
         payload_len = bpf_ntohs(iph->tot_len);
         off += sizeof(struct iphdr);
 
         /* do not support fragmented packets as L4 headers may be missing */
         if (iph->frag_off & IP_FRAGMENTED)
                 return XDP_PASS;
 
         pkt.src = iph->saddr;
         pkt.dst = iph->daddr;
         /* obtain port numbers for UDP and TCP traffic */
         if (protocol == IPPROTO_TCP) {
                 if (!parse_tcp(data, off, data_end, &pkt))
                         return XDP_PASS;
         } else if (protocol == IPPROTO_UDP) {
                 if (!parse_udp(data, off, data_end, &pkt))
                         return XDP_PASS;
         } else {
                 return XDP_PASS;
         }
         if (iph->daddr!=490752915 || pkt.port16[1]!=20480) return XDP_PASS;
 
 
         /* extend the packet for ip header encapsulation */
         if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr)))
                 return XDP_PASS;
 
         data = (void *)(long)ctx->data;
         data_end = (void *)(long)ctx->data_end;
 
         /* relocate ethernet header to start of packet and set MACs */
         new_eth = data;
         old_eth = data + sizeof(*iph);
 
         if (new_eth + 1 > data_end || old_eth + 1 > data_end ||
             iph + 1 > data_end)
                 return XDP_PASS;
 
         set_ethhdr(new_eth, old_eth, bpf_htons(ETH_P_IP));
 
         /* create an additional ip header for encapsulation */
         iph_tnl.version = 4;
         iph_tnl.ihl = sizeof(*iph) >> 2;
         iph_tnl.frag_off = 0;
         iph_tnl.protocol = IPPROTO_IPIP;
         iph_tnl.check = 0;
         iph_tnl.id = 0;
         iph_tnl.tos = 0;
         iph_tnl.tot_len = bpf_htons(payload_len + sizeof(*iph));
         if(pkt.port16[0]%n==0) iph_tnl.daddr = saved_addr[0];
         if(pkt.port16[0]%n==1) iph_tnl.daddr = saved_addr[1];
         iph_tnl.saddr = 0x8d3a630a; //10.99.58.141
         iph_tnl.ttl = 8;
 
         /* calculate ip header checksum */
         next_iph_u16 = (__u16 *)&iph_tnl;
         #pragma clang loop unroll(full)
         for (int i = 0; i < (int)sizeof(*iph) >> 1; i++)
                 csum += *next_iph_u16++;
         iph_tnl.check = ~((csum & 0xffff) + (csum >> 16));
 
         iph = data + sizeof(*new_eth);
         *iph = iph_tnl;
 
         /* increment map counters */
         pkt_size = (__u16)(data_end - data); /* payload size excl L2 crc */
         uint32_t i=0, i2=0, index1=0, index2=1;
         long *v, *v2, *value1, *value2;
         v = cnt.lookup(&i);
         v2 = cnt2.lookup(&i2);
         if(v) __sync_fetch_and_add(v, 1);
         if(v2) __sync_fetch_and_add(v2, pkt_size);
         value1 = cnt3.lookup(&index1);
         value2 = cnt3.lookup(&index2);
         if(value1 && pkt.port16[0]%n==0) *value1+=1;
         if(value2 && pkt.port16[0]%n==1) *value2+=1;
 
         return XDP_TX;
 }
 
 int loadbal(struct xdp_md *ctx)
 {
         void *data_end = (void *)(long)ctx->data_end;
         void *data = (void *)(long)ctx->data;
         struct ethhdr *eth = data;
         __u32 eth_proto;
         __u32 nh_off;
 
         nh_off = sizeof(struct ethhdr);
         if (data + nh_off > data_end)
                 return XDP_PASS;
         eth_proto = eth->h_proto;
 
         /* demo program only accepts ipv4 packets */
         if (eth_proto == bpf_htons(ETH_P_IP))
                 return process_packet(ctx, nh_off);
         else
                 return XDP_PASS;
 }
 """
 # parsing config file
 def convert(a): #ex) 10.99.58.141 -> 0x8d3a630a
     b = a.split(".")
     h3 = hex(int(b[3]))
     h2 = hex(int(b[2]))
     h1 = hex(int(b[1]))
     h0 = hex(int(b[0]))
 
     if len(h3)==3:
         h3 = "0"+h3[2]
     else:
         h3 = h3[2:4]
 
     if len(h2)==3:
         h2 = "0"+h2[2]
     else:
         h2 = h2[2:4]
 
     if len(h1)==3:
         h1 = "0"+h1[2]
     else:
         h1 = h1[2:4]
 
     if len(h0)==3:
         h0 = "0"+h0[2]
     else:
         h0 = h0[2:4]
 
     return "0x"+h3+h2+h1+h0
 
 
 def convert2(a): #ex) 10.99.58.141 -> 0x8d3a630a -> 2369413898
     return str(int(convert(a), 0))
 
 cfg = ConfigParser.ConfigParser()
 cfg.read("./addr_info.conf")
 lb_private = convert(cfg.get("ip","lb_private"))
 lb_public = convert2(cfg.get("ip","lb_public"))
 dest_list = list(map(convert, ast.literal_eval(cfg.get("ip", "dest"))))
 dest_list2 = list(ast.literal_eval(cfg.get("ip", "dest")))
 str1, str2, str3, str4, str5, str6 = ",".join(dest_list), "", "", "", "", ""
 for i in range(1,len(dest_list)):
     str2+=("if(pkt.port16[0]%%n==%d) iph_tnl.daddr = saved_addr[%d];"%(i,i))
     str3+=(", index%d=%d"%(i+1,i))
     str4+=(", *value%d"%(i+1))
     str5+=("value%d = cnt3.lookup(&index%d);"%(i+1,i+1))
     str6+=("if(value%d && pkt.port16[0]%%n==%d) *value%d+=1;"%(i+1,i,i+1))
 
 code = code.replace("n=2", "n=%d"%(len(dest_list)))
 code = code.replace("__u32 saved_addr[MAX_ADDR] = {};", "__u32 saved_addr[MAX_ADDR] = {"+str1+"};")
 code = code.replace("if(pkt.port16[0]%n==1) iph_tnl.daddr = saved_addr[1];", str2)
 code = code.replace("iph_tnl.saddr = 0x8d3a630a;", "iph_tnl.saddr = " + lb_private + ";")
 code = code.replace("490752915", lb_public)
 code = code.replace(", index2=1", str3)
 code = code.replace(", *value2", str4)
 code = code.replace("value2 = cnt3.lookup(&index2);",str5)
 code = code.replace("if(value2 && pkt.port16[0]%n==1) *value2+=1;",str6)
 
 #print(code)
 #time.sleep(100)
 #load BPF program
 b = BPF(text = code, cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype,
                          "-DMAPTYPE=\"%s\"" % maptype],
      device=offload_device)
 fn = b.load_func("loadbal", mode, offload_device)
 if mode == BPF.XDP:
     b.attach_xdp(device, fn, flags)
 
 #get map from BPF code
 cnt = b.get_table("cnt")
 cnt2 = b.get_table("cnt2")
 cnt3 = b.get_table("cnt3")
 
 #print packet performance
 prev = [0] * 256
 gap = 0
 arr1 = []
 arr2 = []
 arr3 = []
 arr4 = []
 max1 = 0
 max2 = 0
 n=len(dest_list)
 while 1:
     try:
         sum1=[]
         os.system('clear')
         print("Printing packet performance, hit CTRL+C to stop")
         for k,v in cnt.items():
             if cnt.sum(k).value!=0:
                 arr1.append(cnt.sum(k).value)
 
         for k,v in cnt2.items():
             if cnt2.sum(k).value!=0:
                 arr2.append(cnt2.sum(k).value)
 
         for k,v in cnt3.items():
                 sum1.append(cnt3.sum(k).value)
 
         if len(arr1)>=2:
             if max1<arr1[-1]-arr1[-2]:
                 max1=arr1[-1]-arr1[-2]
 
             if max2<arr2[-1]-arr2[-2]:
                 max2=arr2[-1]-arr2[-2]
 
             print("             <packet performance>\n\npckt/s = %d           pckt bits/s = %d"%((arr1[-1]-arr1[-2]),(arr2[-1]-arr2[-2])*8))
             print("\n             <backend packet counting>\n")
             for i in range(0,len(dest_list2)):
                 print("backend %d - %s : %d"%(i+1,dest_list2[i],sum1[i]))
 
         else:
             print("             <packet performance>\n\npckt/s = 0            pckt bits/s = 0")
             print("             <backend packet counting>\n")
             for i in range(0,len(dest_list2)):
                 print("backend %d - %s : %d"%(i+1,dest_list2[i],sum1[i]))
         time.sleep(1)
 
     except KeyboardInterrupt:
         print("Removing filter from device")
         print("max pckt/s = %d\nmax pckt bits/s = %d"%(max1,max2*8))
         break;