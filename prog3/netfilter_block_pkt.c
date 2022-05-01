#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


static struct nf_hook_ops *nf_blockpkt_ops = NULL;

static unsigned int nf_blockpkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	if(!skb) 
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (ntohs(udph->dest) == 53) {
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	else if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "Drop ICMP packet\n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static int __init nf_blockpkt_init(void) 
{
	nf_blockpkt_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockpkt_ops != NULL) {
		nf_blockpkt_ops->hook = (nf_hookfn*)nf_blockpkt_handler;
		nf_blockpkt_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockpkt_ops->pf = NFPROTO_IPV4;
		nf_blockpkt_ops->priority = NF_IP_PRI_FIRST;
		
		nf_register_net_hook(&init_net, nf_blockpkt_ops);
	}
	return 0;
}


static void __exit nf_blockpkt_exit(void)
{
	if(nf_blockpkt_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_blockpkt_ops);
		kfree(nf_blockpkt_ops);
	}
	printk(KERN_INFO "Exit");
}

module_init(nf_blockpkt_init);
module_exit(nf_blockpkt_exit);

MODULE_LICENSE("GPL");


