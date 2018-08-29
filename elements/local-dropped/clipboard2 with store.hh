// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CLIPBOARD2_HH
#define CLICK_CLIPBOARD2_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
Clipboard2(RANGE_1, ..., RANGE_N)

=s basicmod
copies data from one packet to another and set checksums

=d
Takes as arguments one or more byte ranges to copy. When Clipboard receives a
packet on input 0, it copies the selected bytes to the clipboard buffer and
emits the packet unchanged on output 0. When receiving a packet on input 1,
Clipboard updates the packet with the bytes from the buffer and outputs the
modified packet on output 1. This way, data from a single packet can be copied
to 0 or more packets.

Each RANGE is on the form C<x/n>, where C<x> is the offset and C<n> the number
of bytes.

Each Clipboard input/output pair can work in either a push or a pull context.

Clipboard can also be used to copy data from one place in a packet to another,
by looping the same packet back through Clipboard and using Strip and Unstrip
to offset the packet data.

Passing a packet through input/output 1 before any packets have passed through
input/output 0 will cause undefined data to be written into the packet. Passing
a packet through input/output 1 which is too small for any one of the ranges
will cause the packet contents to be undefined.

=a StoreData, Strip, Unstrip
*/


struct Range2 {
    uint32_t offset;
    uint32_t length;
};


class Clipboard2 : public Element {
public:
    Clipboard2() CLICK_COLD;

    const char *class_name() const { return "Clipboard2"; }
    const char *flags()      const { return "S0"; }
    const char *flow_code()  const { return "#/#"; }
    const char *port_count() const { return "2/2"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const { return true; }

    Packet *pull(int port);
    void push(int port, Packet *p);

    void set_IPchecksum(WritablePacket *p_in);
    void set_UDPchecksum(WritablePacket *p_in);
    void set_TCPchecksum(WritablePacket *p_in);

private:

    static const int _capacity = 1000;

    class PacketBufferElt {
    private:
        Packet *_packet;
        PacketBufferElt **_chain_ptr;
        PacketBufferElt *_next;
        PacketBufferElt *_prev;

    public:
        PacketBufferElt(PacketBufferElt **chain, Packet *p);

        PacketBufferElt *next() const		{ return _next; }
        PacketBufferElt *prev() const		{ return _prev; }
        Packet* packet() const		{ return _packet; }

        Packet* kill_elt();
    };

    Vector<unsigned char> _clipboard2;
    Vector<Range2> _ranges;
    uint32_t _minPacketLength;
    int _0_is_ok;
    int _1_is_ok;

    PacketBufferElt *_chain0;
    PacketBufferElt *_chain1;
    PacketBufferElt  *_chain_out;
    
    void copy(Packet *p);
    Packet *paste(Packet *p);
    void cleanup(CleanupStage);

};

inline
Clipboard2::PacketBufferElt::PacketBufferElt(PacketBufferElt **chain_ptr, Packet *p)
{
    _chain_ptr = chain_ptr;
    _packet = p;
 
    if (*chain_ptr == 0) {
        *chain_ptr = this;
        _next = 0;
        _prev = 0;
        return;
    }else{
        PacketBufferElt *list = *chain_ptr;
        PacketBufferElt *lprev = 0L;
        do {
            lprev = list;
            list = list->_next;
        } while(list);
        if (!list) {
            /* add to end of list */
            _next = 0;
            _prev = lprev;
            lprev->_next = this;
            return;
        }
    }
}

inline Packet *
Clipboard2::PacketBufferElt::kill_elt()
{
    Packet *p = _packet;
    if (_chain_ptr && *_chain_ptr == this) {
        /* head of chain */
        if (_next)
        _next->_prev = 0;
        *_chain_ptr = _next;
    }else if (_prev || _next) {
        if (_prev)
        _prev->_next = _next;
        if (_next)
        _next->_prev = _prev;
    }
    _prev = 0;
    _next = 0;
    _packet = 0;
    delete this;
    return p;
}



CLICK_ENDDECLS
#endif
