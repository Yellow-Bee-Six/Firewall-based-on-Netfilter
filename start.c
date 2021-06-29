#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include "netfilter.h"
#include <string.h>

int sockfd;

char short_arg[] = "IPipacl";
char long_args[][10] = {"sip", "sport", "dip", "dport", "ad", "policy",
    "loc"};

int set_rule(band_status status);
int get_rule(nf_rule_list res, int SOE_LOC);
void proto_init();
char *fgets_n(char *des, int len);
int str_split(char **des, char *res, char delim);
void split_ipmask(char *res, unsigned int *ip, unsigned int *mask);
void long2short(int argc_t, char **pargs);

int main(int argc, char *argv[]){
    band_status b;
    nf_rule_list res;
    socklen_t len = sizeof(b);

    proto_init();
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0){
        printf("socket error!\n");
        return -1;
    }

    char command[128];
    char args[16][32];
    int argc_t = 0;
    char *pargs[16];
    for(int i = 0; i < 16; i++){
        pargs[i] = args[i];
    }
    printf("Welcome! This is a simple firewall based on the netfilter!\n");
    printf("Input quit to exit and help to get more information!\n>");
    fgets_n(command, 128);
    int c = 0;
    int i = 0;
    int flag = 1;
    char carg[32];
    unsigned int location;
    while (strcmp(command, "quit")){
        i = 0;
        flag = 1;
        memset(&b, 0, sizeof(b));
        b.policy = NF_ACCEPT;
        b.loc = SOE_LOCAL_IN;
        b.act = ADD_RULE;
        argc_t = str_split(pargs, command, ' ');
        long2short(argc_t, pargs);
        if(!strcmp(pargs[0], "natset")){
            while(flag && i < argc_t){
                if(pargs[i][0] == '-'){
                    c = pargs[i][1];
                    strcpy(carg, pargs[++i]);
                    switch(c){
                        case 'I':
                            split_ipmask(carg, &b.ip.sip, &b.ip.smask);
                            break;
                        case 'P':
                            sscanf(carg, "%hu", &b.port.sport);
                            break;
                        case 'i':
                            split_ipmask(carg, &b.ip.dip, &b.ip.dmask);
                            break;
                        case 'p':
                            sscanf(carg, "%hu", &b.port.dport);
                            break;
                        case 'l':
                            if(!strcmp(carg, "input")){
                                b.loc = SOE_LOCAL_IN;
                            }
                            else if(!strcmp(carg, "output")){
                                b.loc = SOE_LOCAL_OUT;
                            }
                            else if(!strcmp(carg, "forward")){
                                b.loc = SOE_FORWARD;
                            }
                            else if(!strcmp(carg, "pre")){
                                b.loc = SOE_PRE_ROUTING;
                            }
                            else if(!strcmp(carg, "post")){
                                b.loc = SOE_POST_ROUTING;
                            }
                            else{
                                printf("Invalid arguments!\n");
                                flag = 0;
                            }                        
                            break;
                        case 'c':
                            if(!strcmp(carg, "accept")){
                                b.policy = NF_ACCEPT;
                            }
                            else if(!strcmp(carg, "drop")){
                                b.policy = NF_DROP;
                            }
                            else if(!strcmp(carg, "stolen")){
                                b.policy = NF_STOLEN;
                            }
                            else if(!strcmp(carg, "repeat")){
                                b.policy = NF_REPEAT;
                            }
                            else if(!strcmp(carg, "stop")){
                                b.policy = NF_STOP;
                            }
                            else{
                                printf("Invalid arguments!\n");
                                flag = 0;
                            }
                            break;
                        case 'a':
                            if(!strcmp(carg, "add")){
                                b.act = ADD_RULE;
                            }
                            else if(!strcmp(carg, "del")){
                                b.act = DEL_RULE;
                            }
                            else{
                                printf("Invalid arguments!\n");
                                flag = 0;
                            }                        
                            break;
                        case 'o':
                            if(!strcmp(carg, "ip")){
                                b.port.protocol = IPPROTO_IP;
                            }
                            else if(!strcmp(carg, "tcp")){
                                b.port.protocol = IPPROTO_TCP;
                            }
                            else if(!strcmp(carg, "udp")){
                            b.port.protocol = IPPROTO_UDP;
                            }
                            else if(!strcmp(carg, "icmp")){
                                b.port.protocol = IPPROTO_ICMP;
                            }
                            else{
                                printf("Invalid arguments!\n");
                                flag = 0;
                            }
                            break;
                    }
                }
                i++;
            }
            if(flag){
                if(set_rule(b) == -1){
                    printf("set_rule() error!\n");
                    return -1;
                }
            }
        }
        else if(!strcmp(pargs[0], "natget")){
            if(argc_t < 3 || (pargs[1][0] != '-' || pargs[1][1] != 'l')){
                printf("Invalid arguments!\n");
            }
            strcpy(carg, pargs[2]);
            if(!strcmp(carg, "input")){
                location = SOE_LOCAL_IN;
            }
            else if(!strcmp(carg, "output")){
                location = SOE_LOCAL_OUT;
            }
            else if(!strcmp(carg, "pre")){
                location = SOE_PRE_ROUTING;
            }
            else if(!strcmp(carg, "forward")){
                location = SOE_FORWARD;
            }
            else if(!strcmp(carg, "post")){
                location = SOE_POST_ROUTING;
            }
            else{
                printf("Invalid arguments!\n");
                flag = 0;
            }
            if(flag){
                if(get_rule(res, location) == -1){
                    printf("get_rule() error!\n");
                }
            }
        }
        else if(!strcmp(pargs[0], "help")){
            printf("-I, --sip: the source ip address, support mask, eg\n\t-I 192.168.10.0/24\n");
            printf("-P, --sport: the source port, eg\n\t-P 80\n");
            printf("-i, --dip: the dest ip address, support mask,eg\n\t-i 192.168.10.0/24\n");
            printf("-p, --dport: the dest port, eg\n\t-p 80\n");
            printf("-a, --ad: add or delete a rule, it equels to one of the followed values:\n\tadd\n\tdel\n\teg:-a add\n");                       
            printf("-c, --policy: the policy you want to apply, it equels to one of the followed values:\n\taccept: accept the data\n\tdrop: drop the data\n\tstolen\n\tstop\n\trepeat\n\teg: -c accept\n");                                 
            printf("-l, --loc: the location you want to hook or get,it equels to one of the followed values:\n\tinput\n\toutput\n\tpre\n\tforward\n\tpost\n\teg: -l input\n");
            printf("\nUsage:\n\tnetset -i 192.168.10.134 -i 80 -l output -c drop\n\tnetget -l output\n");
        }
        else if(strlen(command) == 0) {
        
        }
        else if(!strcmp(pargs[0], "allow-all")){
            for(int k = SOE_GET_BEGIN; k < SOE_GET_END; k++){
                b.loc = k;
                if(set_rule(b) == -1){
                    printf("set_rule() error!\n");
                    return -1;
                }
            }
        }
        else{
            printf("Invalid command!\n");
        }
        printf(">");
        fgets_n(command, 128);
    }
    


}

int set_rule(band_status status){
    socklen_t len = sizeof(status);
    if(setsockopt(sockfd, IPPROTO_IP, SOE_SET_SELF, &status, len) == -1){
        printf("set_rules() error!\n");
        return -1;
    }
}

int get_rule(nf_rule_list res, int SOE_LOC){
    socklen_t len = sizeof(res);
    if(getsockopt(sockfd, IPPROTO_IP, SOE_LOC, &res, &len) == -1){
        printf("get_rules() error!\n");
        return -1;
    }
    char chain[20];
    char policy[20];
    switch (SOE_LOC){
        case SOE_PRE_ROUTING:
            strcpy(chain, "PRE_ROUTING");
            break;
        case SOE_LOCAL_IN:
            strcpy(chain, "LOCAL_IN");
            break;
        case SOE_FORWARD:
            strcpy(chain, "FORWARD");
            break;
        case SOE_LOCAL_OUT:
            strcpy(chain, "LOCAL_OUT");
            break;
        case SOE_POST_ROUTING:
            strcpy(chain, "POST_ROUTING");
            break;
        default:
            return -1;
            break;
    }

    struct in_addr tmp;
    printf("%s\tSource IP\tDest IP\t\tSource Port\tDest Port\tProtocol\tPolicy\n", chain);
    for(int i = 0; i < res.len; i++){
        switch (res.rules[i].policy){
            case NF_DROP:
                strcpy(policy, "DROP");
                break;
            case NF_ACCEPT:
                strcpy(policy, "ACCEPT");
                break;
            case NF_STOLEN:
                strcpy(policy, "STOLEN");
                break;
            case NF_QUEUE:
                strcpy(policy, "QUEUE");
                break;
            case NF_REPEAT:
                strcpy(policy, "REPEAT");
                break;
            case NF_STOP:
                strcpy(policy, "STOP");
                break;
            default:
                return -1;
                break;
        }
        tmp.s_addr = res.rules[i].ip.sip; 
        printf("\t\t%-16s", inet_ntoa(tmp));
        tmp.s_addr = res.rules[i].ip.dip;
        printf("%-15s", inet_ntoa(tmp));
        printf("\t%u\t", res.rules[i].port.sport);
        printf("\t%u\t", res.rules[i].port.dport);
        printf("\t%s\t", proto[res.rules[i].port.protocol]);
        printf("\t%s\n", policy);
    }
    return 0;
}

void proto_init(){
    strcpy(proto[IPPROTO_IP], "IP");
    strcpy(proto[IPPROTO_TCP], "TCP");
    strcpy(proto[IPPROTO_UDP], "UDP");
    strcpy(proto[IPPROTO_ICMP], "ICMP");
}

char *fgets_n(char *des, int len){
    char *res = fgets(des, len, stdin);
    int len_n = strlen(des);
    if(len > 0){
        des[len_n-1] = '\0';
    }
    return res;
}

int str_split(char **des, char* res, char delim) {
    int len = strlen(res);
    int i = 0, j = 0, k = 0;
    while (i < len) {
        if (res[i] == delim) {
            if (k != 0) {
                des[j++][k] = '\0';
                k = 0;
            }
            i++;
        }
        else {
            des[j][k++] = res[i++];
        }
    }
    des[j][k] = '\0';
    return j + 1;
}

void split_ipmask(char *res, unsigned int *ip, unsigned int* mask){
    int i = 0, j = 0;
    char cip[16], cmask[4] = "32";
    int len = strlen(res);
    while(i< len && res[i] != '/'){
        cip[i] = res[i];
        i++;
    }
    cip[i++] = '\0';
    while(i < len){
        cmask[j++] = res[i++];
    }
    if(j != 0){
        cmask[j] = '\0';
    }
    *ip = inet_addr(cip);
    sscanf(cmask, "%u", mask);
}

void long2short(int argc_t, char **pargs){
    char *p;
    for(int i = 0; i < argc_t; i++){
        if(pargs[i][0] == '-' && pargs[i][1] == '-'){
            p = &pargs[i][2];
            for(int j = 0; j < strlen(short_arg); j++){
                if(!strcmp(p, long_args[j])){
                    pargs[i][1] = short_arg[j];
                    pargs[i][2] = '\0';
                    j = strlen(short_arg);
                }
            }
        }
    }
}
