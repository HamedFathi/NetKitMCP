# Tuning Go Garbage Collection

The Go runtime ships with a concurrent, tri-color mark and sweep garbage collector. For most services the defaults are fine, but memory-heavy workloads can benefit from tuning two knobs: `GOGC` and `GOMEMLIMIT`. This article explains what each one does and how they interact in production systems.

The `GOGC` variable sets the target heap growth between collections as a percentage. With the default value of 100, the collector aims to start a new cycle when the live heap has doubled. Raising it trades memory for CPU time; lowering it does the opposite and makes the collector run more often.

Since Go 1.19 the `GOMEMLIMIT` variable provides a soft memory limit. When the total memory used by the runtime approaches the limit, the collector runs more aggressively regardless of `GOGC`. Read the [official GC guide](https://gazette.example/docs/gc-guide) for the details and the [memory limit section](https://go.dev/doc/gc-guide#Memory_limit) in particular.

Measure before and after every change: tune with real traffic, watch pause times, and keep an eye on the resident set size reported by the operating system rather than only the Go heap statistics.
