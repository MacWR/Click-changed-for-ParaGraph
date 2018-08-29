// -*- c-basic-offset: 4 -*-
#ifndef CLICK_OPTIONALCOPY_HH
#define CLICK_OPTIONALCOPY_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c
OptionalCopy(LENGTH)

=s basicmod
copies data from one packet optionally

=d
Takes as arguments one or more byte ranges to copy. When Optionalcopy receives a
packet on input 0, it copies the selected bytes to the Optionalcopy buffer and
emits the packet unchanged on output 0. Optionalcopy creates a new packet with
the bytes from the buffer and outputs the packet on output 1. This way，Optionalcopy
can realize the optional copy operation on the input packets.

Optionalcopy input/output work in a push context.

=a Clipboard, StoreData, Strip, Unstrip
*/


class OptionalCopy : public Element {
public:
	OptionalCopy() CLICK_COLD;

    const char *class_name() const { return "OptionalCopy"; }
    const char *flags()      const { return "S0"; }
    const char *flow_code()  const { return "#/#"; }
    const char *port_count() const { return "1/1-2"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const { return true; }
    void push(int, Packet *p);
    WritablePacket *set_IPchecksum(WritablePacket *p_in);
    WritablePacket *set_UDPchecksum(WritablePacket *p_in);
    WritablePacket *set_TCPchecksum(WritablePacket *p_in);

private:
    unsigned int _length;
    WritablePacket *create(Packet *p);

};


CLICK_ENDDECLS
#endif
