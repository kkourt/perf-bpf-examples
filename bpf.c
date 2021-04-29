//#include <linux/bpf.h>
//#include <linux/types.h>
#include "vmlinux.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
};


#define DEVNAME_SIZE 64
struct xevent {
	__u32 len;
	__u32 pad0;

	__u8  ip_summed;
	__u8  pad1;
	__u16  pad2;
	__u32  pad3;

	__u32 len2;
	__u32  pad4;
};

struct bpf_map_def SEC("maps") channel = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 8,
};

static int (*probe_read)(void *dst, int size, void *src) = (void *)BPF_FUNC_probe_read;
static int (*probe_read_str)(void *dst, int size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_str;
static int (*get_smp_processor_id)(void) = (void *)BPF_FUNC_get_smp_processor_id;
static int (*perf_event_output)(void *, struct bpf_map_def *, int, void *, unsigned long) = (void *)BPF_FUNC_perf_event_output;

/*
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:void * skbaddr;   offset:8;       size:8; signed:0;
        field:unsigned int len; offset:16;      size:4; signed:0;
        field:__data_loc char[] name;   offset:20;      size:4; signed:1;
*/

struct tp_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__u32 common_pid;
	__u64 skbaddr;
	__u32 len;
	char name[];
};

union xpkt_type {
	__u8 val;
	struct {
		__u8 pkt_type:3;
		__u8 ignore_df:1;
		__u8 nf_trace:1;
		__u8 ip_summed:2;
		__u8 ooo_okay:1;
	} fields;
};

SEC("net:netif_receive_skb")
int func (struct tp_ctx *ctx) {
	struct xevent ev = {0};
	struct sk_buff skb, *skb_ptr;
	probe_read(&ev.len, sizeof(__u32), &ctx->len);
	probe_read(&skb_ptr, sizeof(void *), &ctx->skbaddr);
	probe_read(&ev.len2, sizeof(__u32), &skb_ptr->len);
	union xpkt_type t;
	probe_read(&t.val, sizeof(__u8), &skb_ptr->__pkt_type_offset);
	ev.ip_summed = t.fields.ip_summed;
	perf_event_output(ctx, &channel, get_smp_processor_id(), &ev, sizeof(ev));
	return 0;
}

char _license[] SEC("license") = "GPL";
