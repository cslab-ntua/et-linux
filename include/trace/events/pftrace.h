#undef TRACE_SYSTEM
#define TRACE_SYSTEM pftrace 

#if !defined(_TRACE_PFTRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PFTRACE_H

#include <linux/tracepoint.h>

TRACE_EVENT(fault,
	TP_PROTO(unsigned long cycles),
	TP_ARGS(cycles),

	TP_STRUCT__entry(
		__field(	unsigned long,	cycles	)
	),

	TP_fast_assign(
		__entry->cycles	= cycles;
	),

	TP_printk("cycles: %lu", __entry->cycles)
);

TRACE_EVENT(allocpages,
	TP_PROTO(unsigned long cycles),
	TP_ARGS(cycles),

	TP_STRUCT__entry(
		__field(	unsigned long,	cycles	)
	),

	TP_fast_assign(
		__entry->cycles	= cycles;
	),

	TP_printk("cycles: %lu", __entry->cycles)
);

TRACE_EVENT(getfreepage,
	TP_PROTO(unsigned long cycles),
	TP_ARGS(cycles),

	TP_STRUCT__entry(
		__field(	unsigned long,	cycles	)
	),

	TP_fast_assign(
		__entry->cycles	= cycles;
	),

	TP_printk("cycles: %lu", __entry->cycles)
);

TRACE_EVENT(rmqueue,
	TP_PROTO(unsigned long cycles),
	TP_ARGS(cycles),

	TP_STRUCT__entry(
		__field(	unsigned long,	cycles	)
	),

	TP_fast_assign(
		__entry->cycles	= cycles;
	),

	TP_printk("cycles: %lu", __entry->cycles)
);

#endif /* _TRACE_PFTRACE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
