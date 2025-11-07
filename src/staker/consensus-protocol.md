The consensus protocol is a simple protocol passing tagged message frames over TCP (or any other sillad pipe, like sosistab3).

All stakers are assumed to know the total list of all stakers for each era, as well as how to reach each staker. This is information advertised within the on-chain stakes themselves.

We must ensure *reliable broadcast*. This is done by
- indefinitely storing all messages at each node (we'll figure some GC solution later)
- a two-layer system of both a fanout-based fast path, and a pull-based reliability path. This combo is quite necessary for all of
    - quick average-case latency
    - fast "tail" of the broadcast
    - complete eventual reliability