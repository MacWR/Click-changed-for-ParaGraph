from::FromDevice(ens33)
tee::Tee2(3)
rru0::RoundRobinUnqueue
qnq0::QuickNoteQueue
qnq1::QuickNoteQueue
qnq2::QuickNoteQueue
cpb0::ClipboardWithDiscard(0/64)

from -> tee[0] -> qnq0 -> [0]rru0[0] -> [0]cpb0
tee[1] -> qnq1 -> [1]rru0[1] -> [1]cpb0
tee[2] -> qnq2 -> [2]rru0[2] -> [2]cpb0
cpb0 -> Print(ok) -> Discard


