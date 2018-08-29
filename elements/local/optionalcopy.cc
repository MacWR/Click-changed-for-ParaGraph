// -*- c-basic-offset: 4 -*-
/*
 * optionalcopy.{cc,hh} -- copies data from one packet optionally
 * Rui Wang
 */
#include <click/config.h>
#include "optionalcopy.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/crc32.h>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/tcp.h>
#include <click/straccum.hh>
#include <cmath>
CLICK_DECLS


OptionalCopy::OptionalCopy()
{
}


int
OptionalCopy::configure(Vector<String> &conf, ErrorHandler *errh)
{   
    if (Args(conf, this, errh)
        .read_mp("LENGTH", _length)
        .complete() < 0) {
        return -1;
    }

    if (_length < 64)
        _length = 64;
    
    return 0;
}

void
OptionalCopy::push(int, Packet *p)
{
    output(0).push(p);
    WritablePacket *q = create(p);
    if (!q) return;
    q->copy_annotations(p);
    output(1).push(q);
}

WritablePacket *
OptionalCopy::create(Packet *p)
{   
    unsigned int copylength = _length;
   
    WritablePacket *q = p->uniqueify();
    
    q->set_mac_header(q->data(),14);
    unsigned plen = q->length();
    unsigned int mac_header_len = 14;
    click_ip *ipv4_header =  reinterpret_cast<click_ip *>(q->mac_header() + mac_header_len);
    unsigned int ipv4_header_len = ipv4_header->ip_hl << 2;
    q->set_network_header(q->mac_header() + 14, ipv4_header_len);

    // tcp or udp 
    if ( q->has_transport_header() ){ 

        // udp
        if ( ipv4_header->ip_p == IP_PROTO_UDP )  {
            unsigned int udp_header_len = 8;
            unsigned int header_total_len = mac_header_len + ipv4_header_len + udp_header_len;
            click_udp *udp_header = q->udp_header();

            // @header_total_len < @copylength, copy @copylength bytes data
            if ( header_total_len < copylength ){ 
                ipv4_header->ip_len = htons(copylength - mac_header_len);
                udp_header->uh_ulen = htons(copylength - mac_header_len - ipv4_header_len);
                q->take(plen - copylength);
            // @header_total_len > @copylength, copy @header_total_len bytes data    
            }else{
                ipv4_header->ip_len = htons(ipv4_header_len + udp_header_len);
                udp_header->uh_ulen = htons(udp_header_len); 
                q->take(plen - header_total_len);
            }
            q = set_UDPchecksum(q);
            q = set_IPchecksum(q);
            return q;
        }

        // tcp
        if( ipv4_header->ip_p == IP_PROTO_TCP ) {
            click_tcp *tcp_header = q->tcp_header();
            unsigned int transport_header_len = tcp_header->th_off << 2;
            unsigned int header_total_len = mac_header_len + ipv4_header_len + transport_header_len;

            // @header_total_len < @copylength, copy @copylength bytes data
            if ( header_total_len < copylength){
                ipv4_header->ip_len = htons(copylength - mac_header_len);
                q->take(plen - copylength);
            // @header_total_len > @copylength, copy @header_len bytes data 
            }else{
                ipv4_header->ip_len = htons(ipv4_header_len + transport_header_len);
                q->take(plen - header_total_len);
            }
            q = set_TCPchecksum(q);
            q = set_IPchecksum(q);
            return q; 
        }
        
    // not tcp and udp 
    }else{
        ipv4_header->ip_len = copylength - mac_header_len;
        q->take(plen - copylength);
        q = set_IPchecksum(q);
        return q;
    }
}


WritablePacket *
OptionalCopy::set_IPchecksum(WritablePacket *p_in) {
    if (WritablePacket *p = p_in->uniqueify()) {
        unsigned char *nh_data = p->network_header();
        click_ip *iph = reinterpret_cast<click_ip *>(nh_data);
        unsigned plen = p->end_data() - nh_data, hlen;

        if (likely(plen >= sizeof(click_ip))
            && likely((hlen = iph->ip_hl << 2) >= sizeof(click_ip))
            && likely(hlen <= plen)) {
	        iph->ip_sum = 0;
	        iph->ip_sum = click_in_cksum((unsigned char *) iph, hlen);
	        return p;
	    }
    }
    return 0;
}

WritablePacket *
OptionalCopy::set_UDPchecksum(WritablePacket *p_in) {
    WritablePacket *p = p_in->uniqueify();
    if (!p)
	return 0;

    // check IP header/UDP protocol?
    click_ip *iph = p->ip_header();
    click_udp *udph = reinterpret_cast<click_udp *>(p->data() + 14 + (iph->ip_hl << 2));
    int len= ntohs(udph->uh_ulen);

    udph->uh_sum = 0;
    unsigned csum = click_in_cksum((unsigned char *)udph, len);
    udph->uh_sum = click_in_cksum_pseudohdr(csum, iph, len);

    return p;
}

WritablePacket *
OptionalCopy::set_TCPchecksum(WritablePacket *p_in) {
    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();
    click_tcp *tcph = reinterpret_cast<click_tcp *>(p->data() + 14 + (iph->ip_hl << 2));
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
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(OptionalCopy)
ELEMENT_MT_SAFE(OptionalCopy)
