/*
 * merge.{cc,hh} -- element duplicates packets
 * Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "merge.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/router.hh>
#include <click/crc32.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/tcp.h>
#include <cmath>
CLICK_DECLS


//class Merge

Merge::Merge(){
}

int
Merge::configure(Vector<String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
    .read_mp("BURST", _burstsize)
    .read_mp("NOCOPY", _nocopy)
    .complete() < 0)
	{return -1;}
    
    return 0;
}

int
Merge::initialize(ErrorHandler *errh){
   _packet_buffer = new PacketBuffer [_burstsize];
    for ( unsigned int i = 0; i < _burstsize; i++ ){
        _packet_buffer[i] = PacketBuffer(_nocopy);
    }
    _copies_blacklist = new int [_burstsize]();
    _packet_blacklist = new int [_burstsize]();
    _next = 0;
    return 0; 
}
WritablePacket *
Merge::pull(int) {

    //for ( unsigned int j = _next; j < _burstsize; j++ ){
        unsigned int j = _next;
        WritablePacket *q_out = NULL;
        if ( check_packet_buffer_is_ok(j) == 0 ){ 
            Packet *p = input(0).pull();
            unsigned int packet_no = (unsigned int)p->anno_u8(0);
            if ( _packet_blacklist[packet_no] == 1 ){ 
                p->kill();
                p = NULL;
                _packet_blacklist[packet_no] = 0;
                if ( _copies_blacklist[packet_no] == 0 && _packet_blacklist[packet_no] == 0){ //if this p is the last one 
                    _packet_buffer[packet_no].reset();
                }
            }else{
                _packet_buffer[packet_no].set_original_packet(p);
            }
        }

        if ( check_packet_buffer_is_ok(j) == 1 ){ 
            Packet *q = input(1).pull();
            unsigned int packet_no = (unsigned int)q->anno_u8(0);
            if ( _packet_buffer[packet_no].check_and_set_packet_copies(q) == false ){//determine whether q has the dropping operation
                _copies_blacklist[packet_no] = _nocopy - _packet_buffer[packet_no].get_next_position();
                if ( _packet_buffer[packet_no].get_original_packet() ){
                    _packet_blacklist[packet_no] = 0;
                }else{
                    _packet_blacklist[packet_no] = 1;
                }
                if ( _copies_blacklist[packet_no] == 0 && _packet_blacklist[packet_no] == 0){ //if this q is the last one
                    _packet_buffer[packet_no].reset();
                }
            }
            if ( _copies_blacklist[(unsigned int)q->anno_u8(0)] > 0 ){//detetmine whether q belongs to the dropped packet's copies
                _copies_blacklist[(unsigned int)q->anno_u8(0)]--;
                q->kill();
                q = NULL;
                if ( _copies_blacklist[packet_no] == 0 && _packet_blacklist[packet_no] == 0){ //if this q is the last one
                    _packet_buffer[packet_no].reset();
                }
            }
        }
        
        if ( check_packet_buffer_is_ok(j) == 2 && _copies_blacklist[j] == 0 && _packet_blacklist[j] == 0 ){
            q_out = merge_packets(j);
            _packet_buffer[j].reset();
//            _next = (j + 1) % _burstsize; 
//            return q_out;
        } 
        _next = (j + 1) % _burstsize;
        if ( q_out ){
            return q_out;
        }else{
            return NULL;
        }

//    }
}

int 
Merge::check_packet_buffer_is_ok(unsigned int packet_no) {
    if ( !_packet_buffer[packet_no].get_original_packet() ){ // if there is not original packet with the anno_u8(0)
        return 0;
    }
    if ( !_packet_buffer[packet_no].copies_is_full() ){ //  if there are not all copies with the anno_u8(0) 
        return 1;
    }
    return 2; //all is ok
}

WritablePacket *
Merge::merge_packets(unsigned int packet_no) {

    unsigned int *mergeorder = new unsigned int [_nocopy + 1];

    //initialize mergeorder. if *(mergeorder+m) == 255 means the priority m without packet copy.
    for ( int m = 0; m < _nocopy + 1; m++ ) {  
        *(mergeorder + m) = 255;
    }

    //after then, mergeorder[] means which copy mergeorder[i] has the priority i
    for ( int i = 0; i < _nocopy; i++ ) {
        if ( _packet_buffer[packet_no].get_packet_copies_priority(i) == 0 ) { //this position's copy was dropped, because of read operation
            continue;
        }else{ 
            *(mergeorder + _packet_buffer[packet_no].get_packet_copies_priority(i)) = i; 
        }
    }

    //merge the copies according to their priority, the result stores in copymerge[], 
    unsigned char copymerge[2048]; 
    int k, j;
    unsigned char *op = _packet_buffer[packet_no].get_original_packet();
    unsigned char **pc = _packet_buffer[packet_no].get_packet_copies();
    unsigned int op_ipv4_header_len = _packet_buffer[packet_no].get_original_packet_ipv4_header_len();
    unsigned int op_transport_header_len = _packet_buffer[packet_no].get_original_packet_transport_header_len();
    //(1) merge the mac+ipv4 header
    for ( k = 0; k < 14 + op_ipv4_header_len; k++ ) {
        copymerge[k] = *(op + k);
    }
    int max_length = 0;
    for ( j = 1; j < _nocopy + 1; j++ ) {
        for ( k = 0; k < 14 + _packet_buffer[packet_no].get_packet_copies_ipv4_header_len(j-1); k++){
            if ( copymerge[k] != pc[mergeorder[j]][k] ) {
                copymerge[k] = pc[mergeorder[j]][k];
            }
        
            if ( k > max_length ){
                max_length = k;
            }
        }
    }
    //(2) merge the UDP/TCP header
    for ( k = max_length; k < max_length + op_transport_header_len; k++ ){
        copymerge[k] = *(op + k - max_length + 14 + op_ipv4_header_len); 
    }
    int start = max_length;
    if ( op_transport_header_len == 8 ){//UDP
        for ( j = 1; j < _nocopy + 1; j++) {
            for ( k = start; k < start + 8; k++){
                if ( copymerge[k] != pc[mergeorder[j]][k] ) {
                    copymerge[k] = pc[mergeorder[j]][k];
                }
            }
        }
        max_length += 8;  
    }
    
    if ( op_transport_header_len > 8 ){//TCP
       for ( j = 1; j < _nocopy + 1; j++) {
            for ( k = start; k < start + _packet_buffer[packet_no].get_packet_copies_tcp_header_len(j-1); k++){
                if ( copymerge[k] != pc[mergeorder[j]][k] ) {
                    copymerge[k] = pc[mergeorder[j]][k];
                }
            }
        }  
        if ( k > max_length ){
            max_length = k;
        }
    }
    //(3) copy the data in original packet 
    for ( k = max_length; *(op + k) != '\0'; k++ ){
        copymerge[k] = *(op + k + 14 +  op_ipv4_header_len + op_transport_header_len);
    }
    copymerge[k] = '\0';

    //(4) create the merged new packet and return
    WritablePacket *q_out = Packet::make(copymerge,k);
    q_out->set_mac_header(q_out->data());
    q_out->set_network_header((q_out->data() + 14), (start - 14));
    set_length_field(q_out);
    return q_out;
}

void
Merge::set_length_field(WritablePacket *p) {
    assert(p->has_mac_header());
    assert(p->has_network_header());

    click_ip *ipv4_header = p->ip_header();

    // udp 
    if ( ipv4_header->ip_p == IP_PROTO_UDP ){ 
        unsigned char *udp_header_pointer = p->transport_header();
        unsigned int udp_packet_len = p->transport_length();
        //change udp packet length field
        const unsigned char udp_len[2] = {udp_packet_len / 256, udp_packet_len % 256};
        memcpy(udp_header_pointer + 4, udp_len, 2);
        p = set_UDPchecksum(p);
    }
    // tcp
    if ( ipv4_header->ip_p == IP_PROTO_TCP ){
        p = set_TCPchecksum(p);
    }
    //set ip packet length field
    unsigned char *ipv4_header_pointer = p->network_header(); 
    unsigned int ipv4_packet_len = p->network_length();
    const unsigned char ip_len[2] = {ipv4_packet_len / 256, ipv4_packet_len % 256};
    memcpy(ipv4_header_pointer + 2, ip_len, 2);
    p = set_IPchecksum(p);
    p = set_crc32(p);
}

WritablePacket *
Merge::set_crc32(WritablePacket *p) {
    int len = p->length();
    unsigned int crc = 0xffffffff;
    crc = update_crc(crc, (char *) p->data(), len);
    WritablePacket *q = p->put(4);
    memcpy(q->data() + len, &crc, 4);
    return q;
}

WritablePacket *
Merge::set_IPchecksum(WritablePacket *p_in) {
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
Merge::set_UDPchecksum(WritablePacket *p_in) {
    WritablePacket *p = p_in->uniqueify();
    if (!p)
	return 0;

    // XXX check IP header/UDP protocol?
    click_ip *iph = p->ip_header();
    click_udp *udph = p->udp_header();
    int len = ntohs(udph->uh_ulen);
    udph->uh_sum = 0;
    unsigned csum = click_in_cksum((unsigned char *)udph, len);
    udph->uh_sum = click_in_cksum_pseudohdr(csum, iph, len);
    return p;
}

WritablePacket *
Merge::set_TCPchecksum(WritablePacket *p_in) {
    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();
    click_tcp *tcph = p->tcp_header();
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


//class PacketBuffer

PacketBuffer::PacketBuffer( int copies_count ){
    _next_position = 0;
    _copies_count = copies_count;

    _original_packet = NULL;
    _original_packet_ipv4_header_len = 0;
    _original_packet_transport_header_len = 0;

    _packet_copies = new unsigned char *[_copies_count];
    _packet_copies_ipv4_header_len = new uint32_t[_copies_count]();
    _packet_copies_tcp_header_len = new unsigned int[_copies_count]();
    _packet_copies_priority = new unsigned int [_copies_count]();
}

PacketBuffer::PacketBuffer(){
    _next_position = 0;
    _copies_count = 0;

    _original_packet = NULL;
    _original_packet_ipv4_header_len = 0;
    _original_packet_transport_header_len = 0;

    _packet_copies = NULL;
    _packet_copies_ipv4_header_len = NULL;
    _packet_copies_tcp_header_len = NULL;
    _packet_copies_priority = NULL;
}

PacketBuffer::~PacketBuffer(){
    _next_position = 0;
    _copies_count = 0;

    delete[] _original_packet;
    _original_packet_ipv4_header_len = 0;
    _original_packet_transport_header_len = 0;

    for( int j = 0; j < _copies_count; j++ ) {
        delete[] _packet_copies[j];
    }
    delete[] _packet_copies;
    delete[] _packet_copies_ipv4_header_len;
    delete[] _packet_copies_tcp_header_len;
    delete[] _packet_copies_priority;
}

void
PacketBuffer::reset(){
    _next_position = 0;
    
    _original_packet = NULL;
    _original_packet_ipv4_header_len = 0;
    _original_packet_transport_header_len = 0;

    _packet_copies = new unsigned char *[_copies_count];
    for (int i = 0; i < _copies_count; i++ ){
        _packet_copies[i] = NULL;
        _packet_copies_ipv4_header_len[i] = 0;
        _packet_copies_tcp_header_len[i] = 0;
        _packet_copies_priority[i] = 0;
    }
}

void 
PacketBuffer::set_original_packet(Packet *p){
    assert( p->has_mac_header() );
    assert( p->has_network_header() );

    const unsigned char *src = p->mac_header();
    int mac_packet_len = p->mac_length();
    _original_packet_ipv4_header_len = p->network_header_length();
    const click_ip *ipv4_header = p->ip_header();
    if ( ipv4_header->ip_p == IP_PROTO_TCP ){
        const click_tcp *tcp_header = p->tcp_header();
        _original_packet_transport_header_len = tcp_header->th_off << 2;
    }
    if ( ipv4_header->ip_p == IP_PROTO_UDP ){
        _original_packet_transport_header_len = 8;
    }
    _original_packet = new unsigned char [mac_packet_len + 1];
    memcpy(_original_packet, src, mac_packet_len);
    p->kill();
    p = NULL;
}

int
PacketBuffer::check_operation(Packet *q) {
    unsigned int operation = (unsigned int)q->anno_u8(1);
    if ( operation == 250 ){        //read operation: drop this copy
        return 0;
    }
    if ( operation == 252 ){        //drop operation: drop the packet and its all copies
        return 2;
    }
    if ( operation == 251 ){        //write operation: reserve this copy
        return 1;
    }
}

void 
PacketBuffer::set_packet_copies(Packet *q){
    //supposed that check_operation == 1
    assert( q->has_mac_header() );
    assert( q->has_network_header() );

    const unsigned char *src = q->mac_header();
    int mac_packet_len = q->mac_length();
    _packet_copies_ipv4_header_len[_next_position] = q->network_header_length();
    const click_ip *ipv4_header = q->ip_header();
    
    if ( ipv4_header->ip_p == IP_PROTO_TCP ){//store TCP header length
        const click_tcp *tcp_header = q->tcp_header();
        _packet_copies_tcp_header_len[_next_position] = tcp_header->th_off << 2;
    }
    _packet_copies_priority[_next_position] = (unsigned int)q->anno_u8(2);
    _packet_copies[_next_position] = new unsigned char [mac_packet_len + 1];
    memcpy(_packet_copies[_next_position], src, mac_packet_len);
    if ( copies_is_full() == false ){
           _next_position++; 
    }
    q->kill();
    q = NULL;
}

bool 
PacketBuffer::check_and_set_packet_copies(Packet *q){
    if ( check_operation(q) == 0 ){
        if ( copies_is_full() == false ){
           _next_position++; 
        }
    }
    if ( check_operation(q) == 2 ){
        return false;
    }
    if ( check_operation(q) == 1 ){
        set_packet_copies(q);
    }
    return true;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Merge)
ELEMENT_MT_SAFE(Merge)
