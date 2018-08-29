//fw
from@fw::FromDevice(ens33,SNIFFER false,PROMISC true)
c0@fw::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
checkarp@fw::CheckARPHeader
checkip@fw::CheckIPHeader(14)
ipf@fw::IPFilter(allow src 10.0.0.0/24,deny all)
//ips
ee@ips::EnsureEther(0x0800, 00:0c:29:df:4f:45, 00:0c:29:a6:cd:fa)
c1@ips::IPClassifier(ip proto udp,ip proto tcp, -)
checkudp@ips::CheckUDPHeader
checktcp@ips::CheckTCPHeader
check0@ips::CheckLength(2048)
check1@ips::CheckLength(2048)
check2@ips::CheckLength(2048)
check3@ips::CheckLength(2048)
setudpchecksum@ips::SetUDPChecksum
settcpchecksum@ips::SetTCPChecksum
rrs@ips::RoundRobinSched
//ips2
ee@ips2::EnsureEther(0x0800, 00:0c:29:df:4f:45, 00:0c:29:a6:cd:fa)
c1@ips2::IPClassifier(ip proto udp,ip proto tcp, -)
checkudp@ips2::CheckUDPHeader
checktcp@ips2::CheckTCPHeader
check0@ips2::CheckLength(2048)
check1@ips2::CheckLength(2048)
check2@ips2::CheckLength(2048)
check3@ips2::CheckLength(2048)
setudpchecksum@ips2::SetUDPChecksum
settcpchecksum@ips2::SetTCPChecksum
rrs@ips2::RoundRobinSched
//nat
to@nat::ToDevice(ens34)
c@nat::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
AddressInfo(
  intern 	10.0.0.211	10.0.0.255	00:0c:29:a6:cd:fa,
  intern_server	10.0.0.212
);
ipc0@nat::IPClassifier(src net 10.0.0.0/24, -);k
ipc1@nat::IPClassifier(tcp or udp, -);
checkip@nat::CheckIPHeader(14)

IPRewriterPatterns(to_server_pat intern 50000-65535 intern_server -);
rw@nat::IPRewriter(
		 // external traffic redirected to 'intern_server'
		 pattern to_server_pat 0 0,
		 // virtual wire to output 1 if no mapping
		 pass 1);


//fw
from@fw -> CheckLength(1500) -> SetTimestamp -> Print(in,TIMESTAMP true,CONTENTS NONE) -> ee@ips -> c0@fw

c0@fw[0] -> checkarp@fw -> Discard
c0@fw[1] -> checkip@fw -> ipf@fw
c0@fw[2] -> Discard

ipf@fw[0] -> c1@ips
ipf@fw[1] -> Discard

//ips1
c1@ips[0] -> checkudp@ips 
checkudp@ips[0] -> check0@ips -> Queue -> [0]rrs@ips
checkudp@ips[1] -> check2@ips -> setudpchecksum@ips[0] -> Queue -> [2]rrs@ips
setudpchecksum@ips[1] -> Queue -> Discard

c1@ips[1] -> checktcp@ips
checktcp@ips[0] -> check1@ips -> Queue -> [1]rrs@ips
checktcp@ips[1] -> check3@ips -> settcpchecksum@ips -> Queue -> Discard

c1@ips[2] -> Discard

rrs@ips -> Unqueue -> c1@ips2

//ips2
c1@ips2[0] -> checkudp@ips 
checkudp@ips2[0] -> check0@ips2 -> Queue -> [0]rrs@ips2
checkudp@ips2[1] -> check2@ips2 -> setudpchecksum@ips2[0] -> Queue -> [2]rrs@ips2
setudpchecksum@ips2[1] -> Queue -> [3]rrs@ips2

c1@ips2[1] -> checktcp@ips2
checktcp@ips2[0] -> check1@ips2 -> Queue -> [1]rrs@ips2
checktcp@ips2[1] -> check3@ips2 -> settcpchecksum@ips2 -> Queue -> [4]rrs@ips2

c1@ips2[2] -> Discard

rrs@ips2 -> Unqueue -> c@nat

//nat
c@nat[0] -> Discard
c@nat[2] -> Discard

c@nat[1] -> checkip@nat -> ipc0@nat;

ipc0@nat[0] -> ipc1@nat;
  ipc1@nat[0] -> [0]rw@nat; // other TCP or UDP traffic, rewrite or to gw
  ipc1@nat[1] -> [1]rw@nat[1] -> Discard; // non TCP or UDP traffic is dropped

ipc0@nat[1] -> Discard;	// stuff for other people

rw@nat[0] -> Queue -> SetTimestamp -> Print(out,TIMESTAMP true,CONTENTS NONE) -> to@nat 
