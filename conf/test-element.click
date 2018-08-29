fs0::FrequencySample(100,start,true,false,true)
fs1::FrequencySample(100,end,false,true,true)

oc::OptionalCopy(64)

FromDevice(ens33,BURST 1,SNIFFER false,PROMISC true)  -> CheckLength(1500)-> Queue -> Unqueue(BURST 1)->fs0 -> oc[1]-> fs1 -> Discard

oc[0]->Discard 

//FromDevice(ens33,BURST 100,SNIFFER false,PROMISC true) -> Queue -> Unqueue(BURST 100) -> SetTimestamp ->Print(in,TIMESTAMP true,CONTENTS NONE) -> SetTimestamp ->Print(out,TIMESTAMP true,CONTENTS NONE) -> Discard
//->CheckIPHeader(14)
