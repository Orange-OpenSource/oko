Oko
===

The original Open vSwitch README is available at [`README-original.md`].

What is Oko?
------------

Oko is an extension of Open vSwitch-DPDK that provides runtime extension with
BPF programs. BPF programs act as filters over packets: they are referenced as
an additional match field in the OpenFlow tables and cannot write to packets.
They can however read and write to persistent maps (array or hash table) to
retain information on flows.

Oko was based on Open vSwitch v2.5 (commit [`b63bf24`]) and relies on a
modified version of [the ubpf project] to execute BPF programs.

This version of Oko is a **research prototype**: it almost certainly contains
serious bugs and should only be used for experimentation and research purposes.


How to install?
---------------

To install Oko, you can follow the usual [guidelines to install Open
vSwitch-DPDK]. No additional dependencies are required.


How to use?
-----------

```
# ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk ofport_request=1
# ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk ofport_request=2
# ovs-vsctl show
509b64f2-a893-490a-9fd5-7582c29e8b89
    Bridge "br0"
        Port "dpdk0"
            Interface "dpdk0"
                type: dpdk
        Port "dpdk1"
            Interface "dpdk1"
                type: dpdk
# clang -O2 -target bpf -c examples/bpf/rate-limiter.c -o /tmp/rate-limiter.o
# ovs-ofctl load-filter-prog br0 1 /tmp/rate-limiter.o
# ovs-ofctl add-flow br0 priority=1,in_port=1,filter_prog=1,actions=output:2
# ovs-ofctl dump-flows br0
NXST_FLOW reply (xid=0x4):
 cookie=0x0, duration=103.730s, table=0, n_packets=0, n_bytes=0, idle_age=103, priority=1,in_port=1,filter_prog=1 actions=output:2
 cookie=0x0, duration=103.842s, table=0, n_packets=0, n_bytes=0, idle_age=103, priority=0 actions=NORMAL
```

We have also extended Oko with the CLI command to update the BPF maps of the given BPF program. Once the filter prog
is loaded, the below command can be used to write entry (key-value pair) to the given BPF program.

```
ovs-ofctl update-map br0 1 0 key 1 0 0 0 value 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0
```

License
-------

Except for the `lib/bpf/lookup3.c` file in the public domain, all new files
introduced by Oko compared to Open vSwitch are licensed under Apache 2.0.
Modified files from both Open vSwitch and ubpf are also licensed under their
original license, Apache 2.0.


Modifications to source codes:
------------------------------

For compliance with the Apache 2.0 license, the following lists our
modifications to the source codes of ubpf and Open vSwitch.

### ubpf

- Support for maps allocation (ELF parsing, memory allocation, and map
relocation).
- Support for Array, Hash table, Bloom filter, and Count-Min sketch maps.
- Increase the stack size of the virtual machine to 512.
- Fix warnings related to pointer arithmetic.
- Support for LDIND* and LDABS* bytecode instructions.
- BPF helpers to compute a hash value and retrieve the current time.
- BPF verifier for register types and variable-sized loops.

### Open vSwitch

- New `filter_prog` match field in OpenFlow table.
- New `LOAD_FILTER_PROG` OpenFlow message to send a BPF program to load to the
switch, as an ELF file.
- New 'UPDATE_MAP' OpenFlow message to write entry (key-value pair) to the BPF
map of the given BPF program.
- New `SEND_MAPS` action and message to send the content of maps to the
controller.
- New filter program chain structure in the datapath to cache a succession of
BPF programs.

Contacts
--------

Paul Chaignon &lt;paul.chaignon@orange.com&gt;

Tomasz Osiński &lt;tomasz.osinski2@orange.com&gt;

[`README-original.md`]:README-original.md
[`b63bf24`]:https://github.com/Orange-OpenSource/oko/commit/b63bf24882095cc45d3304455cc37e9df4a08c58
[the ubpf project]:https://github.com/iovisor/ubpf
[guidelines to install Open vSwitch-DPDK]:INSTALL.DPDK.md
