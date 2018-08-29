// -*- c-basic-offset: 4 -*-
/*
 * clipboard2.{cc,hh} -- copies data from one packet to another
 * Rui Wang
 */
#include <click/config.h>
#include "clipboard2.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/tcp.h>
CLICK_DECLS


Clipboard2::Clipboard2():_0_is_ok(false),_1_is_ok(0),_chain0(0),_chain1(0),_chain_out(0)
{
}


int
Clipboard2::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Vector<Range2> ranges = Vector<Range2>();
    Range2 range;
    int clipboardSize = 0;
    _minPacketLength = 0;

    for (int argNo = 0; argNo < conf.size(); argNo++) {
        String arg = conf[argNo];
        int i = arg.find_left('/');
        if (i <= 0 || i >= arg.length() - 1) {
            errh->error("range %d: expected '/' between offset and length", argNo);
            return -1;
        }

        if (Args(this, errh)
            .push_back(arg.substring(0, i))
            .push_back(arg.substring(i + 1))
            .read_mp("OFFSET", range.offset)
            .read_mp("LENGTH", range.length)
            .complete() < 0) {
            errh->error("range %d: invalid offset or length", argNo);
            return -1;
        }

        ranges.push_back(range);
        clipboardSize += range.length;
        if (range.offset + range.length > _minPacketLength)
            _minPacketLength = range.offset + range.length;
    }

    _ranges = ranges;
    _clipboard2.resize(clipboardSize);
    return 0;
}


Packet *
Clipboard2::pull(int port)
{
    Packet *p = input(port).pull();
    if (!p) return NULL;
    if (port == 0) {
        if ( _1_is_ok == 0 ){//_chain1 is empty
            new PacketBufferElt(&_chain0, p);
            _0_is_ok++;
        }else{ //_chain1 is not empty
            Packet *q0 = _chain0->packet();
            Packet *q1 = _chain1->packet();
            if ( !q0 ){ //__chain0 is empty
                if( (unsigned)q1->anno_u8(1) != 252) { 
                    if ( (unsigned)p->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(p);  
                        q1 = paste(q1);
                    }
//                  if ( (unsigned)p->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                  if ( (unsigned)p->anno_u8(1) == 252 ) {} //dopping: outport connect to Discard to realize the dorpping operation
                    q1->set_anno_u8(1,p->anno_u8(1));
                }
            }else{ //_chain0 is not empty
                new PacketBufferElt(&_chain0, p);
                if( (unsigned)q1->anno_u8(1) != 252) {
                    if ( (unsigned)q0->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(q0);  
                        q1 = paste(q1);
                    }
//                  if ( (unsigned)q0->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                  if ( (unsigned)q0->anno_u8(1) == 252 ) {}//dopping: outport connect to Discard to realize the dorpping operation
                    q1->set_anno_u8(1,q0->anno_u8(1));
                    _chain0->kill_elt();
                    _0_is_ok--;
                }
            }
            _chain1->kill_elt();
            _1_is_ok--;
            new PacketBufferElt(&_chain_out, q1);
        }
        return p;
    }else{ //port == 1 
        if ( !_0_is_ok ){ //_chain0 is empty
            new PacketBufferElt(&_chain1, p);
            _1_is_ok++;
        }else{ // _chain0 is not empty
            Packet *q1 = _chain1->packet();
            Packet *q0 = _chain0->packet();
            if ( !q1 ){//_chain1 is empty
                if ( (unsigned)p->anno_u8(1) != 252 ){ 
                    if ( (unsigned)q0->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(q0);  
                        p = paste(p);
                    }
//                    if ( (unsigned)q0->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                    if ( (unsigned)q0->anno_u8(1) == 252 ) {} //dopping: outport connect to Discard to realize the dorpping operation
                    p->set_anno_u8(1,q0->anno_u8(1));
                    q1 = p;
                }
//                else{}//dopping
            }else{ //_chain1 is not empty
                new PacketBufferElt(&_chain1, p);
                if ( (unsigned)q1->anno_u8(1) != 252 ){
                    if ( (unsigned)q0->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(q0);  
                        q1 = paste(q1);
                    }
//                    if ( (unsigned)q0->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                    if ( (unsigned)q0->anno_u8(1) == 252 ) {} //dopping: outport connect to Discard to realize the dorpping operation
                    q1->set_anno_u8(1,q0->anno_u8(1));
                }
//                else{}//dopping
                _chain1->kill_elt();
                _1_is_ok--;
            }
            _chain0->kill_elt();
            _0_is_ok--;
            new PacketBufferElt(&_chain_out, q1);
        }
        Packet *p_out = _chain_out->packet();
        if ( p_out ){
            _chain_out->kill_elt();
            return p_out;
        }
    }
    return NULL;
}


void
Clipboard2::push(int port, Packet *p)
{   
    if ( port == 0 ){
        if ( _1_is_ok == 0 ){//_chain1 is empty
            new PacketBufferElt(&_chain0, p);
            _0_is_ok++;
        }else{ //_chain1 is not empty
            Packet *q0 = _chain0->packet();
            Packet *q1 = _chain1->packet();
            if ( !q0 ){ //__chain0 is empty
                if( (unsigned)q1->anno_u8(1) != 252) { 
                    if ( (unsigned)p->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(p);  
                        q1 = paste(q1);
                    }
//                  if ( (unsigned)p->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                  if ( (unsigned)p->anno_u8(1) == 252 ) {} //dopping: outport connect to Discard to realize the dorpping operation
                    q1->set_anno_u8(1,p->anno_u8(1));
                }
            }else{ //_chain0 is not empty
                new PacketBufferElt(&_chain0, p);
                if( (unsigned)q1->anno_u8(1) != 252) {
                    if ( (unsigned)q0->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(q0);  
                        q1 = paste(q1);
                    }
//                  if ( (unsigned)q0->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                  if ( (unsigned)q0->anno_u8(1) == 252 ) {}//dopping: outport connect to Discard to realize the dorpping operation
                    q1->set_anno_u8(1,q0->anno_u8(1));
                    _chain0->kill_elt();
                    _0_is_ok--;
                }
            }
            _chain1->kill_elt();
            _1_is_ok--;
            new PacketBufferElt(&_chain_out, q1);
        }
        output(port).push(p);
    }else{  //port == 1
       if ( !_0_is_ok ){ //_chain0 is empty
            new PacketBufferElt(&_chain1, p);
            _1_is_ok++;
        }else{ // _chain0 is not empty
            Packet *q1 = _chain1->packet();
            Packet *q0 = _chain0->packet();
            if ( !q1 ){//_chain1 is empty
                if ( (unsigned)p->anno_u8(1) != 252 ){ 
                    if ( (unsigned)q0->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(q0);  
                        p = paste(p);
                    }
//                    if ( (unsigned)q0->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                    if ( (unsigned)q0->anno_u8(1) == 252 ) {} //dopping: outport connect to Discard to realize the dorpping operation
                    p->set_anno_u8(1,q0->anno_u8(1));
                    q1 = p;
                }
//                else{}//dopping
            }else{ //_chain1 is not empty
                new PacketBufferElt(&_chain1, p);
                if ( (unsigned)q1->anno_u8(1) != 252 ){
                    if ( (unsigned)q0->anno_u8(1) == 251 ) { //writing: store the packet and output to Discard
                        copy(q0);  
                        q1 = paste(q1);
                    }
//                    if ( (unsigned)q0->anno_u8(1) == 250 ) {}//reading: outport connect to Discard to realize the dorpping operation
//                    if ( (unsigned)q0->anno_u8(1) == 252 ) {} //dopping: outport connect to Discard to realize the dorpping operation
                    q1->set_anno_u8(1,q0->anno_u8(1));
                }
//                else{}//dopping
                _chain1->kill_elt();
                _1_is_ok--;
            }
            _chain0->kill_elt();
            _0_is_ok--;
            new PacketBufferElt(&_chain_out, q1);
        }
        Packet *p_out = _chain_out->packet();
        if ( p_out ){
            output(port).push(p_out);
            _chain_out->kill_elt();
        }
    }
    return;
}


void
Clipboard2::copy(Packet *p)
{
    // Configure guarantees us that _clipboard2 is big enough to hold all ranges.
    unsigned char *dst = &_clipboard2[0];
    for (int i = 0; i < _ranges.size(); i++) {
        Range2 range = _ranges[i];
        const unsigned char *src = p->data() + range.offset;
        memcpy(dst, src, range.length);
        dst += range.length;
    }
}


Packet *
Clipboard2::paste(Packet *p)
{
    if (p->length() < _minPacketLength) return p;

    WritablePacket *q = p->uniqueify();
    if (!q) return NULL;

    const unsigned char *src = &_clipboard2[0];
    unsigned char *dst = q->data();

    for (int i = 0; i < _ranges.size(); i++) {
        Range2 range = _ranges[i];
        memcpy(dst + range.offset, src, range.length);
        src += range.length;
    }

    assert(q->has_mac_header());
    assert(q->has_network_header());
    assert(q->has_transport_header());
    click_ip *iph = q->ip_header();
    if ( iph->ip_p == IP_PROTO_TCP ){
        set_TCPchecksum(q);
    }
    if ( iph->ip_p == IP_PROTO_UDP ){
        set_UDPchecksum(q);
    }
    set_IPchecksum(q);

    return q;
}

void
Clipboard2::cleanup(CleanupStage)
{
    PacketBufferElt *elt0 = _chain0;
    while (elt0) {
        PacketBufferElt *t = elt0;
        elt0 = elt0->next();
        Packet *p = t->kill_elt();
        p->kill();
    }
    PacketBufferElt *elt1 = _chain1;
    while (elt1) {
        PacketBufferElt *t = elt1;
        elt1 = elt1->next();
        Packet *p = t->kill_elt();
        p->kill();
    }
    PacketBufferElt *elt_out = _chain_out;
    while (elt_out) {
        PacketBufferElt *t = elt_out;
        elt_out = elt_out->next();
        Packet *p = t->kill_elt();
        p->kill();
    }
    assert(_chain0 == 0);
    assert(_chain1 == 0);
    assert(_chain_out == 0);
}

void
Clipboard2::set_IPchecksum(WritablePacket *p_in) {
    unsigned char *nh_data = p_in->network_header();
    click_ip *iph = reinterpret_cast<click_ip *>(nh_data);
    unsigned plen = p_in->end_data() - nh_data;
    unsigned hlen;

    if (likely(plen >= sizeof(click_ip))
        && likely((hlen = iph->ip_hl << 2) >= sizeof(click_ip))
        && likely(hlen <= plen)) {
	    iph->ip_sum = 0;
	    iph->ip_sum = click_in_cksum((unsigned char *) iph, hlen);
	}
}

void
Clipboard2::set_UDPchecksum(WritablePacket *p_in) {
    // check IP header/UDP protocol?
    click_ip *iph = p_in->ip_header();
    click_udp *udph = reinterpret_cast<click_udp *>(p_in->network_header()+ (iph->ip_hl << 2));
    int len= ntohs(udph->uh_ulen);

    udph->uh_sum = 0;
    unsigned csum = click_in_cksum((unsigned char *)udph, len);
    udph->uh_sum = click_in_cksum_pseudohdr(csum, iph, len);

}

void
Clipboard2::set_TCPchecksum(WritablePacket *p_in) {
    click_ip *iph = p_in->ip_header();
    click_tcp *tcph = reinterpret_cast<click_tcp *>(p_in->network_header() + (iph->ip_hl << 2));
    unsigned plen = ntohs(iph->ip_len) - (iph->ip_hl << 2);
    unsigned csum;

    unsigned off = tcph->th_off << 2;
    if (off < sizeof(click_tcp)) {
        tcph->th_off = sizeof(click_tcp) >> 2;
    }
    else if (off > plen && !IP_ISFRAG(iph)) {
        tcph->th_off = plen >> 2;
    }

    tcph->th_sum = 0;
    csum = click_in_cksum((unsigned char *)tcph, plen);
    tcph->th_sum = click_in_cksum_pseudohdr(csum, iph, plen);

}


CLICK_ENDDECLS
EXPORT_ELEMENT(Clipboard2)
