// -*- c-basic-offset: 4 -*-
#ifndef CLICK_CLIPBOARDWITHDISCARD_HH
#define CLICK_CLIPBOARDWITHDISCARD_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
ClipboardWithDiscard(RANGE_1, ..., RANGE_N)

=s basicmod
copies data from one packet to another and set checksums

=d
Takes as arguments one or more byte ranges to copy. When Clipboard receives a
packet on other input, it copies the selected bytes to the clipboard buffer and
discards these packets. When receiving a packet on the last input,
Clipboard updates the packet with the bytes from the buffer and outputs the
modified packet on output 0. This way, data from a single packet can be copied
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


struct Range3 {
    uint32_t offset;
    uint32_t length;
};


class ClipboardWithDiscard : public Element {
public:
    ClipboardWithDiscard() CLICK_COLD;

    const char *class_name() const { return "ClipboardWithDiscard"; }
    const char *flags()      const { return "S0"; }
    const char *flow_code()  const { return "#/#"; }
    const char *port_count() const { return "-/1"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const { return true; }

    Packet *pull(int port);
    void push(int port, Packet *p);

    void set_IPchecksum(WritablePacket *p_in);
    void set_UDPchecksum(WritablePacket *p_in);
    void set_TCPchecksum(WritablePacket *p_in);

private:
    Vector<unsigned char> _ClipboardWithDiscard;
    Vector<Range3> _ranges;
    uint32_t _minPacketLength;
    bool _dropped;
    bool _copied;

    void copy(Packet *p);
    Packet *paste(Packet *p);
};


CLICK_ENDDECLS
#endif

