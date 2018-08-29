/*
 * autodpaint.{cc,hh} -- element sets packets' two layers' paint annotation
 * Rui Wang
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Meraki, Inc.
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
#include "autodpaint.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
CLICK_DECLS

AutoDPaint::AutoDPaint()
{
}

int
AutoDPaint::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
    .read_mp("COLORANGE", _colorange)
    .read_mp("OPERATIONCOLOR", _operationcolor)
    .complete() < 0)
	return -1;
    _startcolor = 0;
    _nowcolor = 0;
    _nowrange = _colorange;
    return 0;
}

Packet *
AutoDPaint::simple_action(Packet *p)
{
    int range = _nowrange;
    uint16_t color = _nowcolor;
    //First layer paint annotation 8
    if ( range > 0 ){
        p->set_anno_u16(8, color);
        _nowcolor = ++color;
        _nowrange = --range;
    }
    if ( range == 0 ) {
        _nowrange = _colorange;
        _nowcolor = _startcolor;
    }
    p->set_anno_u8(7, _operationcolor);        //second layer paint annotation 7: 250 means reading operation;252 means dropping operation;251 means writing operation;
    return p;
}

void
AutoDPaint::add_handlers()
{
    add_data_handlers("startcolor", Handler::OP_READ | Handler::OP_WRITE, &_startcolor);
    add_data_handlers("colorange", Handler::OP_READ | Handler::OP_WRITE, &_colorange);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(AutoDPaint)
ELEMENT_MT_SAFE(AutoDPaint)
