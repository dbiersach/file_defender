// Placeholder for a later eBPF implementation.
// Keep kernel-side logic minimal: collect metadata and stream it to userspace.
// Avoid policy decisions in eBPF. The userspace daemon should score and alert.

char LICENSE[] SEC("license") = "GPL";
