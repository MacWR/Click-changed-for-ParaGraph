from@m::FromDevice(ens33,SNIFFER false,PROMISC true)
to@m::ToDevice(ens34)
c@m::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
c1@m::IPClassifier(ip proto udp,ip proto tcp, -)
checkip@m::CheckIPHeader(14)
hash1@m::HashSwitch(16, 4)
hash2@m::HashSwitch(16, 4)
checkudp@m::CheckUDPHeader
checktcp@m::CheckTCPHeader

from@m -> SetTimestamp -> Print(in,TIMESTAMP true) -> c@m 
c@m[0] -> Discard
c@m[2] -> Discard

c@m[1] -> checkip@m -> c1@m

c1@m[0] -> checkudp@m -> hash1@m
hash1@m[0] -> AggregateCounter(ip dst) -> QuickNoteQueue -> [0]rrs@m
hash1@m[1] -> AggregateCounter(ip dst) -> QuickNoteQueue -> [1]rrs@m


c1@m[1] -> checktcp@m -> hash2@m
hash2@m[0] -> AggregateCounter(ip dst) -> QuickNoteQueue -> [2]rrs@m
hash2@m[1] -> AggregateCounter(ip dst) -> QuickNoteQueue -> [3]rrs@m

c1@m[2] -> Discard 

rrs@m -> SetTimestamp -> Print(out,TIMESTAMP true) -> to@m 