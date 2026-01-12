#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct data_t {
    char msg[64];
};

SEC("uprobe")
int handle_uprobe(struct pt_regs *ctx) {
    struct data_t data = {};
    __builtin_memcpy(data.msg, "UPROBE triggered!\n", 18);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";