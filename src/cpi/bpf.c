// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

// Summarize cycles per instruction

#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#ifdef PERCPU
struct key_t {
    u32 cpu;
    u32 pid;
};
BPF_HASH(cycle_cnt, struct key_t);
BPF_HASH(instr_cnt, struct key_t);
#else
BPF_HASH(cycle_cnt, u32);
BPF_HASH(instr_cnt, u32);
#endif

int cnt_cycles(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

#ifdef PERCPU
    struct key_t key = {};
    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid;
#else
    u32 key = pid;
#endif

    cycle_cnt.increment(key, ctx->sample_period);
    return 0;
}

int cnt_instr(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

#ifdef PERCPU
    struct key_t key = {};
    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid;
#else
    u32 key = pid;
#endif

    instr_cnt.increment(key, ctx->sample_period);
    return 0;
}
