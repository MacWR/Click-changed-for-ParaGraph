from@ips::FromDevice(ens33,SNIFFER false,PROMISC true)
to@ips::ToDevice(ens34)
ee@ips::EnsureEther(0x0800, 00:0c:29:df:4f:45, 00:0c:29:a6:cd:fa)
c0@ips::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
c1@ips::IPClassifier(ip proto udp,ip proto tcp, -)
checkarp@ips::CheckARPHeader
checkip@ips::CheckIPHeader(14)
checkudp@ips::CheckUDPHeader
checktcp@ips::CheckTCPHeader
check0@ips::CheckLength(2048)
check1@ips::CheckLength(2048)
check2@ips::CheckLength(2048)
check3@ips::CheckLength(2048)
setudpchecksum@ips::SetUDPChecksum
settcpchecksum@ips::SetTCPChecksum
ipf@ips::IPFilter(allow src 10.0.0.0/24,deny all)
rrs@ips::RoundRobinSched

from@ips -> SetTimestamp -> Print(in,TIMESTAMP true) -> EnsureEther -> ee@ips -> c0@ips

c0@ips[0] -> checkarp@ips -> Discard
c0@ips[1] -> checkip@ips ->ipf@ips
c0@ips[2] -> Discard

ipf@ips[0] -> c1@ips 
c1@ips[0] -> checkudp@ips 
checkudp@ips[0] -> check0@ips -> QuickNoteQueue -> [0]rrs@ips
checkudp@ips[1] -> check2@ips -> setudpchecksum@ips[0] -> QuickNoteQueue -> [2]rrs@ips
setudpchecksum@ips[1] -> QuickNoteQueue -> [3]rrs@ips

c1@ips[1] -> checktcp@ips
checktcp@ips[0] -> check1@ips -> QuickNoteQueue -> [1]rrs@ips
checktcp@ips[1] -> check3@ips -> settcpchecksum@ips -> QuickNoteQueue -> [4]rrs@ips

c1@ips[2] -> Discard
ipf@ips[1] -> Discard

rrs@ips -> SetTimestamp -> Print(out,TIMESTAMP true) -> to@ips