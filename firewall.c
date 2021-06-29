#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>					/*IP头部结构*/
#include <net/tcp.h> 				/*TCP头部结构*/
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include "netfilter.h"

MODULE_LICENSE("Dual BSD/GPL");
/* NF初始化状态宏 */
#define NF_SUCCESS  0
#define NF_FAILURE  1

#define STRICT		1
#define PART		0
/* 初始化绑定状态 */
band_status b_status ;

#define OCCUPIED 1;
#define FREE     0;

nf_rule_chain in_table;
nf_rule_chain out_table; 
nf_rule_chain pre_table; 
nf_rule_chain for_table; 
nf_rule_chain post_table; 

nf_rule_chain *pf   = NULL; 
nf_rule_chain *pn   = NULL; 

nf_rule_list rule_list;

static int check_rule(band_status *sa, band_status *sb, int strict){
	if(sa == NULL || sb == NULL){
		return 0;
	}
	if(strict){
		if((sa->ip.sip == sb->ip.sip) && (sa->ip.smask == sb->ip.smask)&&
			((sa->ip.dip == sb->ip.dip) && (sa->ip.dmask == sb->ip.dmask))&&
			((sa->port.sport == sb->port.sport) && (sa->port.dport == sb->port.dport))&&
			(sa->port.protocol == sb->port.protocol) && (sa->loc == sb->loc) && (sa->policy == sb->policy)){
				return 1;
		}
		else{
			return 0;
		}
	}
	else{
		if((sa->ip.sip == (sb->ip.sip & sa->ip.smask))&&
			(sa->ip.dip == (sb->ip.dip & sa->ip.dmask))&&
			((sa->port.sport == sb->port.sport) || (sa->port.sport == 0))&&
			((sa->port.dport == sb->port.dport) || (sa->port.dport == 0))&&
			((sa->port.protocol == sb->port.protocol) || (sa->port.protocol == 0))){
				return 1;
		}
		else{
			return 0;
		}
	}
}

static int 
nf_sockopt_set(struct sock *sock, 
	int cmd, 
	void __user *user, 
	unsigned int len)
{
	int ret = 0;
	struct nf_rule_chain *prule = NULL;
	struct nf_rule_chain *ptmp = NULL;
	struct band_status status;
	/* 权限检查 */
	if(!capable(CAP_NET_ADMIN))				/*没有足够权限*/
	{
		ret = -EPERM;
		goto ERROR;
	}
	/* 从用户空间复制数据*/
	ret = copy_from_user(&status, user, len);
	if(ret != 0)								/*复制数据失败*/
	{
		ret = -EINVAL;
		goto ERROR;
	}
	if(status.act == ADD_RULE){
		prule = (struct nf_rule_chain*)kmalloc(sizeof(nf_rule_chain), GFP_KERNEL);
		if(prule == NULL){
			ret = -ENOSPC;
			goto ERROR;
		}
		prule->status = status;
		switch (status.loc){
			case SOE_PRE_ROUTING:
				prule->pnext = pre_table.pnext;
				pre_table.pnext = prule;
				break;
			case SOE_LOCAL_IN:
				prule->pnext = in_table.pnext;
				in_table.pnext = prule;
				break;
			case SOE_FORWARD:
				prule->pnext = for_table.pnext;
				for_table.pnext = prule;
				break;
			case SOE_LOCAL_OUT:
				prule->pnext = out_table.pnext;
				out_table.pnext = prule;
				break;
			case SOE_POST_ROUTING:
				prule->pnext = post_table.pnext;
				post_table.pnext = prule;
				break;
			default:
				ret = -EINVAL;
				goto ERROR;
				break;
		}
	}
	else if(status.act == DEL_RULE){
		ret = -EINVAL;
		switch (status.loc){
			case SOE_PRE_ROUTING:
				ptmp = &pre_table;
				break;
			case SOE_LOCAL_IN:
				ptmp = &in_table;
				break;
			case SOE_FORWARD:
				ptmp = &for_table;
				break;
			case SOE_LOCAL_OUT:
				ptmp = &out_table;
				break;
			case SOE_POST_ROUTING:
				ptmp = &post_table;
				break;
			default:
				ret = -EINVAL;
				goto ERROR;
					break;
		}
		pf = ptmp;
		ptmp = ptmp->pnext;
		while (ptmp != NULL){
			if(check_rule(&(ptmp->status), &status, STRICT)){
				pf->pnext = ptmp->pnext;
				kfree(ptmp);
				ptmp = pf->pnext;
				ret = 0;
			}
			else{
				pf = ptmp;
				ptmp = ptmp->pnext;
			}
		}
		
	}
ERROR:
	return ret;
}
/* nf sock 操作扩展命令操作*/
static int 
nf_sockopt_get(struct sock *sock, 
		int cmd, 
		void __user *user, 
		int *len){
	int ret = 0;
	struct nf_rule_chain *ptmp = NULL;
	/* 权限检查*/
	if(!capable(CAP_NET_ADMIN)){
		ret = -EPERM;
		goto ERROR;
	}	
	switch (cmd){
		case SOE_PRE_ROUTING:
			ptmp = &pre_table;
			break;
		case SOE_LOCAL_IN:
			ptmp = &in_table;
			break;
		case SOE_FORWARD:
			ptmp = &for_table;
			break;
		case SOE_LOCAL_OUT:
			ptmp = &out_table;
			break;
		case SOE_POST_ROUTING:
			ptmp = &post_table;
			break;
		default:
			ret = -EINVAL;
			goto ERROR;
				break;
	}

	rule_list.len = 0;
	while (ptmp->pnext != NULL){
		rule_list.rules[rule_list.len++] = ptmp->pnext->status;
		ptmp = ptmp->pnext;
	}
	
	ret = copy_to_user(user, (void*)&rule_list, *len);
	if(ret != 0) {
		ret = -EINVAL;
		goto ERROR;
	}
	
ERROR:
	return ret;
}

static unsigned int nf_hook_all(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state){
	struct sk_buff *sk = skb;
	struct iphdr *iph = ip_hdr(sk);
	struct nf_rule_chain *ptmp = NULL;
	unsigned int usmask = 0;
	unsigned int udmask = 0;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	band_status status;
	unsigned int ret = NF_DROP;

	status.ip.sip = iph->saddr;
	status.ip.dip = iph->daddr;
	status.port.protocol = iph->protocol;
	switch (iph->protocol){
		case IPPROTO_TCP:
			tcph = tcp_hdr(sk);
			status.port.sport = tcph->source;
			status.port.dport = tcph->dest;
			break;
		case IPPROTO_UDP:
			udph = udp_hdr(sk);
			status.port.sport = udph->source;
			status.port.dport = udph->dest;
			break;
		case IPPROTO_ICMP:
			break;	
		default:
			break;
	}

	switch (state->hook){
		case NF_IP_PRE_ROUTING:
			ptmp = &pre_table;
			break;
		case NF_IP_LOCAL_IN:
			ptmp = &in_table;
			break;
		case NF_IP_FORWARD:
			ptmp = &for_table;
			break;
		case NF_IP_LOCAL_OUT:
			ptmp = &out_table;
			break;
		case NF_IP_POST_ROUTING:
			ptmp = &post_table;
			break;
		default:
			goto ERROR;
				break;
	}
	ptmp = ptmp->pnext;
	while (ptmp != NULL){
		if((check_rule(&(ptmp->status), &status, PART))){
			if(ptmp->status.ip.smask >= usmask){
				ret = ptmp->status.policy;
				usmask = ptmp->status.ip.smask;
			}
			else if(ptmp->status.ip.dmask >= udmask){
				ret = ptmp->status.policy;
				udmask = ptmp->status.ip.dmask;				
			}
		}
		ptmp = ptmp->pnext;
	}
	

ERROR:
	return ret;
}

static void free_table(void *p){
	pf = in_table.pnext;
	while (pf != NULL){
		pn = pf->pnext;
		kfree(pf);
		pf = pn;
	}
	pf = out_table.pnext;
	while (pf != NULL){
		pn = pf->pnext;
		kfree(pf);
		pf = pn;
	}
	pf = pre_table.pnext;
	while (pf != NULL){
		pn = pf->pnext;
		kfree(pf);
		pf = pn;
	}
	pf = for_table.pnext;
	while (pf != NULL){
		pn = pf->pnext;
		kfree(pf);
		pf = pn;
	}
	pf = post_table.pnext;
	while (pf != NULL){
		pn = pf->pnext;
		kfree(pf);
		pf = pn;
	}
}

static struct nf_hook_ops nfin = 
{
	.hook = nf_hook_all,
	.hooknum = NF_IP_LOCAL_IN,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfout=
{
	.hook = nf_hook_all,
	.hooknum = NF_IP_LOCAL_OUT,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfpre = 
{
	.hook = nf_hook_all,
	.hooknum = NF_IP_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfforward=
{
	.hook = nf_hook_all,
	.hooknum = NF_IP_FORWARD,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfpost=
{
	.hook = nf_hook_all,
	.hooknum = NF_IP_POST_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_sockopt_ops nfsockopt = {
	.pf	= PF_INET,
	.set_optmin = SOE_SET_BEGIN,
	.set_optmax = SOE_SET_END,
	.set	= nf_sockopt_set,
	.get_optmin = SOE_GET_BEGIN,
	.get_optmax = SOE_GET_END,
	.get	= nf_sockopt_get,
	.owner = THIS_MODULE
};
/* 初始化模块 */
static int __init init_it(void)
{
	in_table.pnext = NULL;
	out_table.pnext = NULL;
	for_table.pnext = NULL;
	pre_table.pnext = NULL;
	post_table.pnext = NULL;

	nf_register_net_hook(&init_net, &nfin);
	nf_register_net_hook(&init_net, &nfout);
	nf_register_net_hook(&init_net, &nfpre);
	nf_register_net_hook(&init_net, &nfforward);
	nf_register_net_hook(&init_net, &nfpost);

	nf_register_sockopt(&nfsockopt);			/*注册扩展套接字选项*/
	
	printk(KERN_ALERT "Netfilter Start Successfully!\n");
												/*打印信息*/
	return NF_SUCCESS;
}
/* 清理模块 */
static void __exit exit_it(void)
{	
	nf_unregister_net_hook(&init_net, &nfin);
	nf_unregister_net_hook(&init_net, &nfout);
	nf_unregister_net_hook(&init_net, &nfpre);
	nf_unregister_net_hook(&init_net, &nfforward);
	nf_unregister_net_hook(&init_net, &nfpost);

	nf_unregister_sockopt(&nfsockopt);			/*注销扩展套接字选项*/
	free_table(NULL);

	printk(KERN_ALERT "Netfilter Clean Successfully!\n");
}
module_init(init_it);								/*初始化模块*/
module_exit(exit_it);								/*模块退出*/