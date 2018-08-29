//parallel
from@parallel::FromDevice(ens33,SNIFFER false,PROMISC true)
to@parallel::ToDevice(ens34)
oc@parallel::OptionalCopy(64)
tee@parallel::Tee2(2)
rru0@parallel::RoundRobinUnqueue
rru1@parallel::RoundRobinUnqueue
cpb0@parallel::Clipboard2(0/64)
cpb1@parallel::Clipboard2(0/64)
rrs0@parallel::PrioSched2(100)
rrs1@parallel::PrioSched2(100)
//fw
c0@fw::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
ipf@fw::IPFilter(allow src 10.0.0.0/24,deny all)
//ips
ee@ips::EnsureEther(0x0800, 00:0c:29:df:4f:45, 00:0c:29:a6:cd:fa)
c0@ips::Classifier(12/0806,//ARP
               12/0800,//IPv4
               -)//others
c1@ips::IPClassifier(ip proto udp,ip proto tcp, -)
checkudp@ips::CheckUDPHeader
checktcp@ips::CheckTCPHeader
check0@ips::CheckLength(2048)
check1@ips::CheckLength(2048)
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
IPRewriterPatterns(to_server_pat intern 50000-65535 intern_server -);
rw@nat::IPRewriter(
		 // external traffic redirected to 'intern_server'
		 pattern to_server_pat 0 0,
		 // virtual wire to output 1 if no mapping
		 pass 1);

//parallel
from@parallel -> MarkIPHeader(14)-> CheckIPHeader(14) -> AutoDPaint(10,250) -> SetTimestamp -> Print(in,TIMESTAMP true,PRINTANNO true)-> oc@parallel

oc@parallel[0] -> SetTimestamp -> Print(oc,TIMESTAMP true,PRINTANNO true)-> QuickNoteQueue -> [1]rru0@parallel
rru0@parallel[1] -> [1]cpb0@parallel
oc@parallel[1] -> tee@parallel

//fw+nat
//fw
tee@parallel[0] -> c0@fw 
c0@fw[0] -> Paint(252,7) -> QuickNoteQueue -> [0]rrs0@parallel
c0@fw[1] -> ipf@fw
c0@fw[2] -> Paint(252,7) -> QuickNoteQueue ->[1]rrs0@parallel
ipf@fw[1] -> Paint(252,7) -> QuickNoteQueue -> [2]rrs0@parallel
//nat
ipf@fw[0] -> c@nat 
c@nat[0] -> Paint(252,7) -> QuickNoteQueue -> [3]rrs0@parallel
c@nat[2] -> Paint(252,7) -> QuickNoteQueue -> [4]rrs0@parallel

c@nat[1] -> ipc0@nat;

ipc0@nat[0] -> ipc1@nat;
  ipc1@nat[0] -> [0]rw@nat; // other TCP or UDP traffic, rewrite or to gw
  ipc1@nat[1] -> [1]rw@nat[1] -> Paint(252,7) -> QuickNoteQueue -> [5]rrs0@parallel // non TCP or UDP traffic is dropped

ipc0@nat[1] -> Paint(252,7) -> QuickNoteQueue -> [6]rrs0@parallel	// stuff for other people

rw@nat[0] ->Paint(251,7) -> QuickNoteQueue -> [7]rrs0@parallel 

rrs0@parallel -> [0]rru0@parallel 
rru0@parallel[0] -> [0]cpb0@parallel
cpb0@parallel[0] -> Discard


//ips
tee@parallel[1] -> ee@ips -> c0@ips
c0@ips[0] -> Paint(252,7) -> QuickNoteQueue -> [0]rrs1@parallel
c0@ips[1] -> ipf@ips
c0@ips[2] -> Paint(252,7) -> QuickNoteQueue -> [1]rrs1@parallel

ipf@ips[0] -> c1@ips 
c1@ips[0] -> checkudp@ips 
checkudp@ips[0] -> check0@ips -> Paint(250,7) -> QuickNoteQueue -> [2]rrs1@parallel
checkudp@ips[1] -> Paint(252,7) -> QuickNoteQueue -> [3]rrs1@parallel

c1@ips[1] -> checktcp@ips
checktcp@ips[0] -> check1@ips -> Paint(250,7) -> QuickNoteQueue -> [4]rrs1@parallel
checktcp@ips[1] -> Paint(252,7) -> QuickNoteQueue -> [5]rrs1@parallel

c1@ips[2] -> Paint(252,7) -> QuickNoteQueue -> [6]rrs1@parallel
ipf@ips[1] -> Paint(252,7) -> QuickNoteQueue -> [7]rrs1@parallel

rrs1@parallel -> [0]rru1@parallel
rru1@parallel[0] -> [0]cpb1@parallel
cpb1@parallel[0] -> Discard


//parallel
cpb0@parallel[1] -> [1]cpb1@parallel//-> QuickNoteQueue -> [1]rru1@parallel
//rru1@parallel[1] 
cpb1@parallel[1] -> QuickNoteQueue -> SetTimestamp -> Print(out,TIMESTAMP true,PRINTANNO true) ->CheckPaint2(252,7) -> to@parallel








