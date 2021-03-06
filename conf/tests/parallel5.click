//parallel
from@parallel::FromDevice(ens33,SNIFFER false,PROMISC true)
to@parallel::ToDevice(ens34)
tee@parallel::Tee2(6)
adp@parallel::AutoDPaint(1000,250)
rru0@parallel::RoundRobinUnqueue
rru1@parallel::RoundRobinUnqueue
rru2@parallel::RoundRobinUnqueue
rru3@parallel::RoundRobinUnqueue
rru4@parallel::RoundRobinUnqueue
cpb0@parallel::Clipboard2(0/64)
cpb1@parallel::Clipboard2(0/64)
cpb2@parallel::Clipboard2(0/64)
cpb3@parallel::Clipboard2(0/64)
cpb4@parallel::Clipboard2(0/64)
tsq0@parallel::ThreadSafeQueue2(10000)
tsq1@parallel::ThreadSafeQueue2(10000)
tsq2@parallel::ThreadSafeQueue2(10000)
tsq3@parallel::ThreadSafeQueue2(10000)
tsq4@parallel::ThreadSafeQueue2(10000)
//fw
c0@fw::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
checkarp@fw::CheckARPHeader
checkip@fw::CheckIPHeader(14)
ipf@fw::IPFilter(allow src 10.0.0.0/24,deny all)
//ips
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
//nat
c@nat::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
AddressInfo(
  intern 	10.0.0.211	10.0.0.255	00:0c:29:a6:cd:fa,
  intern_server	10.0.0.212
);
ipc0@nat::IPClassifier(src net 10.0.0.0/24, -);
ipc1@nat::IPClassifier(tcp or udp, -);
checkip@nat::CheckIPHeader(14)

IPRewriterPatterns(to_server_pat intern 50000-65535 intern_server -);
rw@nat::IPRewriter(
		 // external traffic redirected to 'intern_server'
		 pattern to_server_pat 0 0,
		 // virtual wire to output 1 if no mapping
		 pass 1);

//fw2
c0@fw2::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
checkarp@fw2::CheckARPHeader
checkip@fw2::CheckIPHeader(14)
ipf@fw2::IPFilter(allow src 10.0.0.0/24,deny all)
//ips2
ee@ips2::EnsureEther(0x0800, 00:0c:29:df:4f:45, 00:0c:29:a6:cd:fa)
c0@ips2::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
c1@ips2::IPClassifier(ip proto udp,ip proto tcp, -)
checkarp@ips2::CheckARPHeader
checkip@ips2::CheckIPHeader(14)
checkudp@ips2::CheckUDPHeader
checktcp@ips2::CheckTCPHeader
check0@ips2::CheckLength(2048)
check1@ips2::CheckLength(2048)
check2@ips2::CheckLength(2048)
check3@ips2::CheckLength(2048)
setudpchecksum@ips2::SetUDPChecksum
settcpchecksum@ips2::SetTCPChecksum
ipf@ips2::IPFilter(allow src 10.0.0.0/24,deny all)

//parallel
from@parallel  -> CheckLength(1500) -> SetTimestamp -> Print(in,TIMESTAMP true,CONTENTS NONE) -> adp@parallel -> tee@parallel

tee@parallel[0] -> QuickNoteQueue -> [1]rru0@parallel[1] -> [1]cpb0@parallel

//fw
tee@parallel[1] -> c0@fw 
c0@fw[0] -> checkarp@fw -> Paint(250,7) -> tsq0@parallel
c0@fw[1] -> checkip@fw -> ipf@fw
c0@fw[2] -> Paint(252,7) -> tsq0@parallel

ipf@fw[0] -> Paint(250,7) -> tsq0@parallel
ipf@fw[1] -> Paint(252,7) -> tsq0@parallel

tsq0@parallel -> [0]rru0@parallel[0] -> [0]cpb0@parallel[0] -> Discard


//ips
tee@parallel[2] -> ee@ips -> c0@ips
c0@ips[0] -> checkarp@ips -> Paint(250,7) -> tsq1@parallel
c0@ips[1] -> checkip@ips -> ipf@ips
c0@ips[2] -> Paint(252,7) -> tsq1@parallel

ipf@ips[0] -> c1@ips 
c1@ips[0] -> checkudp@ips 
checkudp@ips[0] -> check0@ips -> Paint(250,7) -> tsq1@parallel
checkudp@ips[1] -> check2@ips -> setudpchecksum@ips[0] -> Paint(251,7) -> tsq1@parallel
setudpchecksum@ips[1] -> Paint(252,7) -> tsq1@parallel

c1@ips[1] -> checktcp@ips
checktcp@ips[0] -> check1@ips -> Paint(250,7) -> tsq1@parallel
checktcp@ips[1] -> check3@ips -> settcpchecksum@ips -> Paint(251,7) -> tsq1@parallel


c1@ips[2] -> Paint(252,7) -> tsq1@parallel
ipf@ips[1] -> Paint(252,7) -> tsq1@parallel

tsq1@parallel -> [0]rru1@parallel[0] -> [0]cpb1@parallel[0] -> Discard


//nat
tee@parallel[3] -> c@nat

c@nat[0] -> Paint(252,7) -> tsq2@parallel
c@nat[2] -> Paint(252,7) -> tsq2@parallel

c@nat[1] -> checkip@nat -> ipc0@nat;

ipc0@nat[0] -> ipc1@nat;
  ipc1@nat[0] -> [0]rw@nat; // other TCP or UDP traffic, rewrite or to gw
  ipc1@nat[1] -> [1]rw@nat[1] -> Paint(252,7) -> tsq2@parallel // non TCP or UDP traffic is dropped

ipc0@nat[1] -> Paint(252,7) -> tsq2@parallel	// stuff for other people

rw@nat[0] -> Paint(251,7) -> tsq2@parallel 
tsq2@parallel -> [0]rru2@parallel[0] -> [0]cpb2@parallel[0] -> Discard

//fw2
tee@parallel[4] -> c0@fw2 
c0@fw2[0] -> checkarp@fw2 -> Paint(250,7) -> tsq3@parallel
c0@fw2[1] -> checkip@fw2 -> ipf@fw2
c0@fw2[2] -> Paint(252,7) -> tsq3@parallel

ipf@fw2[0] -> Paint(250,7) -> tsq3@parallel
ipf@fw2[1] -> Paint(252,7) -> tsq3@parallel

tsq3@parallel -> [0]rru3@parallel[0] -> [0]cpb3@parallel[0] -> Discard


//ips2
tee@parallel[5] -> ee@ips2 -> c0@ips2
c0@ips2[0] -> checkarp@ips2 -> Paint(250,7) -> tsq4@parallel
c0@ips2[1] -> checkip@ips2 -> ipf@ips2
c0@ips2[2] -> Paint(252,7) -> tsq4@parallel

ipf@ips2[0] -> c1@ips2 
c1@ips2[0] -> checkudp@ips2
checkudp@ips2[0] -> check0@ips2 -> Paint(250,7) -> tsq4@parallel
checkudp@ips2[1] -> check2@ips2 -> setudpchecksum@ips2[0] -> Paint(251,7) -> tsq4@parallel
setudpchecksum@ips2[1] -> Paint(252,7) -> tsq4@parallel

c1@ips2[1] -> checktcp@ips2
checktcp@ips2[0] -> check1@ips2 -> Paint(250,7) -> tsq2@parallel
checktcp@ips2[1] -> check3@ips2 -> settcpchecksum@ips2 -> Paint(251,7) -> tsq4@parallel


c1@ips2[2] -> Paint(252,7) -> tsq4@parallel
ipf@ips2[1] -> Paint(252,7) -> tsq4@parallel

tsq4@parallel -> [0]rru4@parallel[0] -> [0]cpb4@parallel[0] -> Discard

//parallel
cpb0@parallel[1] -> QuickNoteQueue -> [1]rru1@parallel[1] -> [1]cpb1@parallel
cpb1@parallel[1] -> QuickNoteQueue -> [1]rru2@parallel[1] -> [1]cpb2@parallel
cpb2@parallel[1] -> QuickNoteQueue -> [1]rru3@parallel[1] -> [1]cpb3@parallel
cpb3@parallel[1] -> QuickNoteQueue -> [1]rru4@parallel[1] -> [1]cpb4@parallel
cpb4@parallel[1] -> QuickNoteQueue -> SetTimestamp -> Print(out,TIMESTAMP true,CONTENTS NONE) ->CheckPaint2(252,7) -> to@parallel








