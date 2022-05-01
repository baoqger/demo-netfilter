#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


#define NIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

static unsigned int nf_ipaddr_show(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	u32 sip, dip;
	if(skb) {
		struct sk_buff *sb = NULL;
		struct iphdr *iph;

		sb = skb;
		iph = ip_hdr(sb);
		sip = ntohl(iph->saddr);
		dip = ntohl(iph->daddr);
		printk("Source IP Address: %d.%d.%d.%d Destination IP Addresses: %d.%d.%d.%d\n ", NIPQUAD(sip), NIPQUAD(dip));
	}
	return NF_ACCEPT;

}

struct nf_hook_ops nf_ipaddr_show_ops = {
	.hook = nf_ipaddr_show,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FILTER + 2,
};

static int __init nf_ipaddr_show_init(void)
{
	if(nf_register_net_hook(&init_net, &nf_ipaddr_show_ops)) {
		printk(KERN_ERR "nf_register_hook() failed\n");
		return -1;
	}
	printk(KERN_INFO "nf_register_net_hook() success\n");
	return 0;
} 

static void __exit nf_ipaddr_show_exit(void)
{
	nf_unregister_net_hook(&init_net, &nf_ipaddr_show_ops);
	printk(KERN_INFO "Exit");
}

module_init(nf_ipaddr_show_init);

module_exit(nf_ipaddr_show_exit);


MODULE_LICENSE("GPL");
