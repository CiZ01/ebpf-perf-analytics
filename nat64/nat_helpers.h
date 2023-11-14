#ifndef NAT_HELPERS_H
# define NAT_HELPERS_H

int write_icmp(struct icmphdr*, struct icmp6hdr*);

__u16 csum_fold_helper(__u32);

#endif


