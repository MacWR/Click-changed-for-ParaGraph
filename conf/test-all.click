from::FromDevice(ens33)
to::ToDevice(ens34)
oc::OptionalCopy(64)
tee::Tee2(3)
adp::AutoDPaint(10)
//adp1::AutoDPaint(10)
//adp2::AutoDPaint(10)
p::Paint(250,1)
p0::Paint(250,1)
p1::Paint(251,1)
p2::Paint(252,1)
odq0::OrderedQueue(10)
odq1::OrderedQueue(10)
odq2::OrderedQueue(10)
rru0::RoundRobinUnqueue
rru1::RoundRobinUnqueue
rru2::RoundRobinUnqueue
qnq0::QuickNoteQueue
qnq1::QuickNoteQueue
qnq2::QuickNoteQueue
cpb0::Clipboard2(0/64)
cpb1::Clipboard2(0/64)
cpb2::Clipboard2(0/64)
// -> MarkIPHeader(14)
from -> Print(in,PRINTANNO true) -> CheckIPHeader(14) -> adp -> p -> oc

oc[0] -> ThreadSafeQueue -> [1]rru0[1] -> Print(in-[1]cpb0,PRINTANNO true) -> [1]cpb0
oc[1] -> Print(out-oc[1],PRINTANNO true) -> tee

tee[0] -> Print(out-tee[0],PRINTANNO true) -> p0 -> odq0 -> Print(test,PRINTANNO true) -> [0]rru0[0] -> Print(in-[0]cdp0,PRINTANNO true) -> [0]cpb0
tee[1] -> Print(out-tee[1],PRINTANNO true) -> p1 -> Print(test1,PRINTANNO true) -> odq1 -> Print(test11,PRINTANNO true)  -> [0]rru1[0] -> Print(in-[0]cpb1,PRINTANNO true) -> [0]cpb1
tee[2] -> Print(out-tee[2],PRINTANNO true) -> p2 -> odq2 -> [0]rru2[0] -> Print(in-[0]cpb2,PRINTANNO true) -> [0]cpb2

cpb0[0] -> Discard
cpb1[0] -> Discard
cpb2[0] -> Discard

cpb0[1] -> Print(out-cpb0[1],PRINTANNO true) -> qnq0 -> [1]rru1[1] -> [1]cpb1[1] -> Print(out-cpb1[1],PRINTANNO true) ->qnq1 -> [1]rru2[1] ->[1]cpb2[1] -> Print(in-checkpaint,PRINTANNO true) -> qnq2 -> CheckPaint2(252,1) -> Print(out-chekpaint,PRINTANNO true) -> to


