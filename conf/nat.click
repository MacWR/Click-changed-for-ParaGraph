from@nat::FromDevice(ens33,SNIFFER false,PROMISC true)
to@nat::ToDevice(ens34)
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


from@nat -> CheckLength(1500)-> SetTimestamp -> Print(in,TIMESTAMP true, CONTENTS NONE) -> c@nat 

c@nat[0] -> Discard
c@nat[2] -> Discard

c@nat[1] -> checkip@nat -> ipc0@nat;

ipc0@nat[0] -> ipc1@nat;
  ipc1@nat[0] -> [0]rw@nat; // other TCP or UDP traffic, rewrite or to gw
  ipc1@nat[1] -> [1]rw@nat[1] -> Discard; // non TCP or UDP traffic is dropped

ipc0@nat[1] -> Discard;	// stuff for other people

rw@nat[0] -> QuickNoteQueue -> SetTimestamp -> Print(out,TIMESTAMP true, CONTENTS NONE) -> to@nat 
