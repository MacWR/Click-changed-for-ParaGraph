/*
 * tee2.{cc,hh} -- element duplicates packets
 * Rui Wang
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
#include "tee2.hh"
#include <click/args.hh>
#include <click/error.hh>
CLICK_DECLS

Tee2::Tee2()
{
}

int
Tee2::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned n = noutputs();
    if (Args(conf, this, errh).read_p("N", n).complete() < 0)
	return -1;
    if (n != (unsigned) noutputs())
	return errh->error("%d outputs implies %d arms", noutputs(), noutputs());
    return 0;
}

void
Tee2::push(int, Packet *p)
{
    int n = noutputs();
    _anno8 = p->anno_u16(8);
    _anno7 = p->anno_u8(7);
    for (int i = 0; i < n; i++){
        if (WritablePacket *q = p->uniqueify()){
            if (!q){ return;}
            q->set_anno_u16(8,_anno8);
            q->set_anno_u8(7,_anno7);
            output(i).push(q);
        }
    }
}

//
// PULLTEE2
//

PullTee2::PullTee2()
{
}

int
PullTee2::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned n = noutputs();
    if (Args(conf, this, errh).read_p("N", n).complete() < 0)
	return -1;
    if (n != (unsigned) noutputs())
	return errh->error("%d outputs implies %d arms", noutputs(), noutputs());
    return 0;
}

Packet *
PullTee2::pull(int)
{
  Packet *p = input(0).pull();
    if (p) {
        int n = noutputs();
        for (int i = 0; i < n; i++){
            if (WritablePacket *q = p->uniqueify()){
                if (!q) { return 0;}
                q->copy_annotations(p);
                output(i).push(q);
            }
        }
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Tee2 PullTee2)
ELEMENT_MT_SAFE(Tee2)
ELEMENT_MT_SAFE(PullTee2)
