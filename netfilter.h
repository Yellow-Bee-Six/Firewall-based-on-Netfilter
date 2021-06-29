#ifndef __NF_SOCKOPTE_H__
#define __NF_SOCKOPTE_H__

#define SOE_SET_BEGIN  		0x1000
#define SOE_SET_SELF		(SOE_SET_BEGIN + 0)
#define SOE_SET_END			(SOE_SET_BEGIN + 1)

#define SOE_GET_BEGIN		0x2000
#define SOE_PRE_ROUTING		(SOE_GET_BEGIN + 0)
#define SOE_LOCAL_IN		(SOE_GET_BEGIN + 1)
#define SOE_FORWARD			(SOE_GET_BEGIN + 2)
#define SOE_LOCAL_OUT		(SOE_GET_BEGIN + 3)
#define SOE_POST_ROUTING	(SOE_GET_BEGIN + 4)
#define SOE_GET_END			(SOE_GET_BEGIN + 5)

#define ADD_RULE 			0
#define DEL_RULE 			1

#define MAX 100

#define NF_IP_PRE_ROUTING	0
#define NF_IP_LOCAL_IN		1
#define NF_IP_FORWARD		2
#define NF_IP_LOCAL_OUT		3
#define NF_IP_POST_ROUTING	4

#define NF_IP_NUMHOOKS		5

char proto[256][16] = {'\0'};

typedef struct nf_bandip{
	unsigned int sip;
	unsigned int smask;
	unsigned int dip;
	unsigned int dmask;
} nf_bandip;

typedef struct nf_bandport{
	unsigned short protocol;
	unsigned short sport;
	unsigned short dport;
	unsigned short pmask;
} nf_bandport;

typedef struct band_status{
	int act;
	unsigned int loc;
	unsigned int policy;
	struct nf_bandip ip;
	struct nf_bandport port;
} band_status;

typedef struct nf_rule_chain{
	band_status status;
	struct nf_rule_chain *pnext;
} nf_rule_chain;

typedef struct nf_rule_list{
	int len;
	band_status rules[MAX];
} nf_rule_list;
#endif

