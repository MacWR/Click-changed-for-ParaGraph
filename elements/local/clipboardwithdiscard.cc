// -*- c-basic-offset: 4 -*-
/*
 * ClipboardWithDiscard.{cc,hh} -- copies data from one packet to another
 * Rui Wang
 */
#include <click/config.h>
#include "clipboardwithdiscard.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/tcp.h>
CLICK_DECLS


ClipboardWithDiscard::ClipboardWithDiscard():_dropped(false),_copied(false)
{
}


int
ClipboardWithDiscard::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Vector<Range3> ranges = Vector<Range3>();
    Range3 range;
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
    _ClipboardWithDiscard.resize(clipboardSize);
    return 0;
}


Packet *
ClipboardWithDiscard::pull(int port)
{
    Packet *p = input(port).pull();
    if (!p) return NULL;
    if (port < ninputs()-1) {
        if ( p->anno_u8(7) == (uint8_t)251 ) { //writing: store the packet and set the flag _copied to true
            copy(p);  
            _copied = true;
        }
        //if ( p->anno_u8(7) == (uint8_t)250 ){} //reading: perform no operation
        if ( p->anno_u8(7) == (uint8_t)252 ) { //dopping: set the flag _dropped to true
            _dropped = true;
        }
        p->kill();                          //  discard all the packets got from other input ports
        p = NULL;                         
    }else{ //the last input port 
        if ( _dropped ){ 
            _dropped = false;
            p->kill();                      //  discard the packet got from the last input port while the flag _dropped is true and reset it to false
            p = NULL;
        }else{
            if ( p->anno_u8(7) == (uint8_t)252 ){
                _copied = false;
                p->kill();                  //  discard the packet got from the last input port 
                p = NULL;
            }
            if ( _copied ){
                p = paste(p);
                p->set_anno_u8(7,(uint8_t)251);
                _copied = false;
            }
        }
    }
    return p;
}


void
ClipboardWithDiscard::push(int port, Packet *p)
{   
    bool discard_this_packet = false;
    if ( port < ninputs() - 1  ){
        if ( p->anno_u8(7) == (uint8_t)251 ) { //writing: store the packet and set the flag _copied to true
            copy(p);  
            _copied = true;
        }
        //if ( p->anno_u8(7) == (uint8_t)250 ){} //reading: perform no operation
        if ( p->anno_u8(7) == (uint8_t)252 ) { // dopping: set the flag _dropped to true
            _dropped = true;
        }
	discard_this_packet = true;
    }else{  //the last input port
        if ( _dropped ){ 
            _dropped = false;
            discard_this_packet = true;
        }else{
            if ( p->anno_u8(7) == (uint8_t)252 ){
                    _copied = false;
                    discard_this_packet = true;
            }
            if ( _copied ){
                p = paste(p);
                p->set_anno_u8(7,(uint8_t)251);
                _copied = false;
            }
        }
    }
    if ( discard_this_packet ){
	discard_this_packet = false;
	checked_output_push(1, p);
    }
    else{
	output(0).push(p);
    }
    
}


void
ClipboardWithDiscard::copy(Packet *p)
{
    // Configure guarantees us that _ClipboardWithDiscard is big enough to hold all ranges.
    unsigned char *dst = &_ClipboardWithDiscard[0];
    for (int i = 0; i < _ranges.size(); i++) {
        Range3 range = _ranges[i];
        const unsigned char *src = p->data() + range.offset;
        memcpy(dst, src, range.length);
        dst += range.length;
    }
}


Packet *
ClipboardWithDiscard::paste(Packet *p)
{
    if (p->length() < _minPacketLength) return p;

    WritablePacket *q = p->uniqueify();
    if (!q) return NULL;

    const unsigned char *src = &_ClipboardWithDiscard[0];
    unsigned char *dst = q->data();

    for (int i = 0; i < _ranges.size(); i++) {
        Range3 range = _ranges[i];
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
ClipboardWithDiscard::set_IPchecksum(WritablePacket *p_in) {
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
ClipboardWithDiscard::set_UDPchecksum(WritablePacket *p_in) {
    // check IP header/UDP protocol?
    click_ip *iph = p_in->ip_header();
    click_udp *udph = reinterpret_cast<click_udp *>(p_in->network_header()+ (iph->ip_hl << 2));
    int len= ntohs(udph->uh_ulen);

    udph->uh_sum = 0;
    unsigned csum = click_in_cksum((unsigned char *)udph, len);
    udph->uh_sum = click_in_cksum_pseudohdr(csum, iph, len);

}

void
ClipboardWithDiscard::set_TCPchecksum(WritablePacket *p_in) {
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
EXPORT_ELEMENT(ClipboardWithDiscard)

