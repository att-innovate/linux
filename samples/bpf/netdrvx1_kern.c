#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") dropcnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("phys_dev1")
int bpf_prog1(struct bpf_phys_dev_md *ctx)
{
	int index = load_byte(ctx, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;

	value = bpf_map_lookup_elem(&dropcnt, &index);
	if (value)
		*value += 1;

	return BPF_PHYS_DEV_DROP;
}
char _license[] SEC("license") = "GPL";
