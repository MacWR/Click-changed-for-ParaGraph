// testdevice.click

// Tests whether Click can read packets from the network.
// You may need to modify the device name in FromDevice.
// You'll probably need to be root to run this.

// Run with
//    click testdevice.click
// (runs as a user-level program; uses Linux packet sockets or a similar
// mechanism), or
//    click-install testdevice.click
// (runs inside a Linux kernel).

// If you run this inside the kernel, your kernel's ordinary IP stack
// will stop getting packets from eth0. This might not be convenient.
// The Print messages are printed to the system log, which is accessible
// with 'dmesg' and /var/log/messages. The most recent 2-4K of messages are
// stored in /click/messages.
rrq::RoundRobinUnqueue

FromDevice(ens33,SNIFFER false,PROMISC true) -> Paint(250,1) -> t::Tee(3)
t[0] ->OrderedQueue(1)-> [0]rrq
t[1] ->OrderedQueue(1)-> [1]rrq
t[2] ->OrderedQueue(1)-> [2]rrq
rrq[0] -> Paint(251,1) -> Print(0,PRINTANNO true) -> Discard
rrq[1] -> Print(1,PRINTANNO true) -> Discard
rrq[2] -> Print(2,PRINTANNO true) -> Discard
