// -*- c-basic-offset: 4 -*-
/*
 * optionalcopy.{cc,hh} -- copies data from one packet optionally
 */
#include <click/config.h>
#include "optionalcopy.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/tcp.h>
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
   WritablePacket *q = create(p);
   if (!q) return;
   output(1).push(q);
   output(0).push(p);
}

WritablePacket *
OptionalCopy::create(Packet *p) {  

    WritablePacket *q = p->uniqueify();
    if (!q) {
        return 0;
    }

    assert(q->has_mac_header());
    assert(q->has_network_header()); 

    click_ether *mac_header = reinterpret_cast<click_ether *>q->data();
     
    
    unsigned int mac_header_len = 14;
    

    // ipv4 
    if ( mac_header->ether_type == ETHERTYPE_IP ){     
        click_ip *ipv4_header = reinterpret_cast<click_ip *>(q->data() + mac_header_len);
        unsigned int ipv4_header_len = ipv4_header->ip_hl << 2;

        // tcp or udp 
        if ( q->has_transport_header() ){ 

            // udp
            if (ipv4_header->ip_p == IP_PROTO_UDP) {

                click_udp *udp_header = reinterpret_cast<click_udp *>(q->data() + mac_header_len + ipv4_header_len);
                unsigned int udp_header_len = 8;   
                unsigned int header_total_len = mac_header_len + ipv4_header_len + udp_header_len;

                // @header_total_len < copylength, copy @copylength bytes data
                if ( header_total_len < _length ){ 
                    
                    // set ip packet total length field
                    if ( q->length() > _length ) {
                        ipv4_header->ip_len = htons(_length - mac_header_len);
                        p->take( q->length() - _length );
                    }

                    // set udp packet total length field
                    if ( q->length() > _length ) {
                        udp_header->uh_ulen = htons(_length - mac_header_len - ipv4_header_len);
                        p->take( q->length() - _length );
                    }
                    q = set_IPchecksum(q);
                    q = set_UDPchecksum(q);

                // @header_total_len > copylength, copy @header_len bytes data    
                }else{
                    // set ip packet total length field
                    if ( q->length() > header_total_len ) {
                        ipv4_header->ip_len = htons(header_total_len - mac_header_len);
                        p->take( q->length() - header_total_len );
                    }

                    // set udp packet total length field
                    if ( q->length() > header_total_len ) {
                        udp_header->uh_ulen = htons(header_total_len - mac_header_len - ipv4_header_len);
                        p->take( q->length() - header_total_len );
                    }
                    q = set_IPchecksum(q);
                    q = set_UDPchecksum(q);
                }

                return q;
            }

            // tcp
            if( ipv4_header->ip_p == IP_PROTO_TCP ) {
                click_tcp *tcp_header =  reinterpret_cast<click_tcp *>(p->mac_header() + mac_header_len + ipv4_header_len);
                unsigned int tcp_header_len = tcp_header->th_off << 2;   
                unsigned int header_total_len = mac_header_len + ipv4_header_len + tcp_header_len;

                // @header_total_len < copylength, copy @copylength bytes data
                if ( header_total_len < _length ){ 
                    
                    // set ip packet total length field
                    if ( q->length() > _length ) {
                        ipv4_header->ip_len = _length - mac_header_len;
                        p->take( q->length() - _length );
                    }
                    q = set_IPchecksum(q);
                    q = set_TCPchecksum(q);

                // @header_total_len > copylength, copy @header_len bytes data    
                }else{

                    // set ip packet total length field
                    if ( q->length() > header_total_len ) {
                        ipv4_header->ip_len = header_total_len - mac_header_len;
                        p->take( q->length() - header_total_len );
                    }
                    q = set_IPchecksum(q);
                    q = set_TCPchecksum(q);

                }
   
                return q;
            }
        // not tcp and udp 
        }else{
            if ( q->length() > _length ) {
                ipv4_header->ip_len = htons(_length - mac_header_len);
                p->take( q->length() - _length );
            }
            q = set_IPchecksum(q);
            return q;
        }
    }
    return q;
}

WritablePacket *
OptionalCopy::set_IPchecksum(WritablePacket *p_in) {
    if (WritablePacket *p = p_in->uniqueify()) {
	unsigned char *nh_data = (p->has_network_header() ? p->network_header() : p->data());
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
    click_udp *udph = p->udp_header();
    int len;
    if (IP_ISFRAG(iph)
	|| p->transport_length() < (int) sizeof(click_udp)
	|| (len = ntohs(udph->uh_ulen),
	    p->transport_length() < len)) {
	    return 0;
    }

    udph->uh_sum = 0;
    unsigned csum = click_in_cksum((unsigned char *)udph, len);
    udph->uh_sum = click_in_cksum_pseudohdr(csum, iph, len);

    return p;
}

WritablePacket *
OptionalCopy::set_TCPchecksum(WritablePacket *p_in) {
    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();
    click_tcp *tcph = p->tcp_header();
    unsigned plen = ntohs(iph->ip_len) - (iph->ip_hl << 2);
    unsigned csum;

    if (!p->has_transport_header() || plen < sizeof(click_tcp) || plen > (unsigned)p->transport_length()){
            p->kill();
            return 0;
    }

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
