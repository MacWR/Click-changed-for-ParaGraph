from@fw::FromDevice(ens33,SNIFFER false,PROMISC true)
to@fw::ToDevice(ens34)
c0@fw::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
checkarp@fw::CheckARPHeader
checkip@fw::CheckIPHeader(14)
ipf@fw::IPFilter(allow src 10.0.0.0/24,deny all)
rrs@fw::RoundRobinSched

from@fw -> SetTimestamp -> Print(in,TIMESTAMP true) -> c0@fw

c0@fw[0] -> checkarp@fw -> QuickNoteQueue -> [0]rrs@fw
c0@fw[1] -> checkip@fw -> ipf@fw
c0@fw[2] -> Discard

ipf@fw[0] -> QuickNoteQueue -> [1]rrs@fw
ipf@fw[1] -> Discard

rrs@fw -> SetTimestamp -> Print(out,TIMESTAMP true) -> to@fw
