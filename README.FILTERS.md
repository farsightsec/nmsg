A message filtering capability was added to the `libnmsg` I/O loop in `nmsg` 0.11.0.

Message filters are callbacks which can decide to accept a message into the output stream, silently drop it, or pass it to the next filter in the chain. Filters hook into the `nmsg_io` processing loop and can alter or replace messages. See [nmsg/filter.h](nmsg/filter.h) for the documentation on filter semantics.

A message filter callback can either be provided as a function pointer + data pointer via `nmsg_io_add_filter()`, or it can be contained in an external shared object (a "module" or "plugin") which can be loaded and initialized via `nmsg_io_add_filter_module()`. See [nmsg/fltmod_plugin.h](nmsg/fltmod_plugin.h) for the interface that filter plugin providers must implement, and see [nmsg/fltmod.h](nmsg/fltmod.h) for the interface used by filter plugin consumers, like `nmsg_io`.

`nmsg_io_add_filter()` and `nmsg_io_add_filter_module()` can be called repeatedly to build up a linear filter chain. The order of filters in the chain is the same as the order of calls to `nmsg_io_add_filter()` or `nmsg_io_add_filter_module()`. Each input message processed by the `nmsg_io` loop is passed to each filter in sequence, until a filter returns a terminal verdict (`ACCEPT` or `DROP`). If a filter returns a non-terminal verdict (`DECLINED`), the message is passed to the next filter in the chain. If the end of the filter chain is reached, the `nmsg_io` loop's filter policy is applied. (The default is `ACCEPT`, but it can be changed to `DROP` with `nmsg_io_set_filter_policy()`).

Two new command-line options have been added to `nmsgtool`. `-F` or `--filter` loads a filter module, and `--policy` sets the default filter chain policy. These are relatively thin wrappers around `nmsg_io_add_filter_module()` and `nmsg_io_set_filter_policy()`.

A [sample filter module](fltmod/nmsg_flt_sample.c) is provided, which functions as both a code sample of how to provide a filter plugin using the `nmsg/fltmod_plugin.h` interface, as well as providing message sampling functionality. It can perform either systematic count-based sampling or uniform probabilistic sampling. E.g., try `nmsgtool --filter sample,count=10 [...]` to systematically sample every 1-in-10 messages in the input stream, or `nmsgtool --filter sample,random=0.10 [...]` to probabilistically sample every message in the input stream with probability 10%.

## Sample Filter Rate Limiting

The sample filter module also supports rate limiting options to control the minimum and maximum message throughput:

- `min_per_sec=<N>`: Specifies a minimum messages-per-second threshold. When the incoming message rate is below this threshold, all messages are accepted without applying the sampling strategy. This allows low-rate traffic to pass through unsampled. For example, `--filter sample,count=10,min_per_sec=100` will accept all messages until the rate reaches 100 messages per second, then apply 1-in-10 systematic sampling to messages above that threshold.

- `max_per_sec=<N>`: Specifies a maximum messages-per-second throttle. Once the filter has accepted N messages in the current second, all subsequent messages are dropped until the next second begins. This provides an upper bound on the output rate. For example, `--filter sample,count=3,max_per_sec=1000` will apply 1-in-3 sampling but never allow more than 1000 messages per second through the filter.

Both `min_per_sec` and `max_per_sec` can be combined, and rate limiting windows are maintained per-thread. Examples:

- `--filter sample,count=5,min_per_sec=100` - Apply 1-in-5 sampling only after reaching 100 msg/sec
- `--filter sample,random=0.5,max_per_sec=500` - Apply 50% probabilistic sampling but cap at 500 msg/sec
- `--filter sample,count=10,min_per_sec=50,max_per_sec=1000` - Combine min and max thresholds with systematic sampling
