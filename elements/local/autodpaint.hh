#ifndef CLICK_AUTODPAINT_HH
#define CLICK_AUTODPAINT_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c

AutoDPaint(COLORANGE,OPERATIONCOLOR)

=s autoDpaint

sets packet two layers' autodpaint annotations

=d

The first layer Paint is to protect the consistency of the packet copys: 
Sets each packet's first Paint annotation (default is startanno=8 )to STARTCOLOR, an integer 0-2^16-1, default is startcolor=0;
The second layer Paint is to mark the operation on the packert copys: 
Set each packert's second Paint annotation ( default is startanno+1 ) to COLOR, an integer 250..254, default is color=0（operation: read）;
The ANNO argument can specify any one-byte annotation.

=h color read/write

Get/set the color to autodpaint.

=a Paint, PaintTee */

class AutoDPaint : public Element { public:

    AutoDPaint() CLICK_COLD;

    const char *class_name() const		{ return "AutoDPaint"; }
    const char *port_count() const		{ return PORTS_1_1; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const		{ return true; }
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:

    uint16_t _startcolor;
    uint16_t _nowcolor;
    uint8_t _operationcolor;
    int _colorange;
    uint16_t _nowrange;

};

CLICK_ENDDECLS
#endif
