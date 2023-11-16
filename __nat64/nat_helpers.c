#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
/*
    convert icmp6 to icmp
*/

/*
    recalculate the checksum of the packet
*/
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;

    // suddivido il csum a 32 bit in due parti di 16 bit
    // la prima parte la ottengo facendo lo shift a destra e la seconda parte facendo l'and
    // con una stringa di 16 bit tutti settati a 1 scritta in hex
    sum = (csum >> 16) + (csum & 0xffff);

    // nel caso superi 0xffff ci sarà del riporto che aggiungo qua
    sum += (sum >> 16);

    // inverte la stringa di bit prima di ritornarla
    return ~sum;
}
