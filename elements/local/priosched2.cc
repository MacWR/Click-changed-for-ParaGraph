// -*- c-basic-offset: 4 -*-
/*
 * priosched.{cc,hh} -- priority scheduler element
 * Robert Morris, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2003 International Computer Science Institute
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
#include <click/error.hh>
#include <click/args.hh>
#include "priosched2.hh"
CLICK_DECLS

PrioSched2::PrioSched2()
    : _start(0),_signals(0)
{
}

int 
PrioSched2::configure(Vector<String> &conf, ErrorHandler *errh)
{   
    if (Args(conf, this, errh)
        .read_mp("THRESHOLD", _threshold)
        .complete() < 0) {
        return -1;
    }
    return 0;
}

int 
PrioSched2::initialize(ErrorHandler *errh)
{
    if (!(_signals = new NotifierSignal[ninputs()]))
	return errh->error("out of memory!");
    for (int i = 0; i < ninputs(); i++){
        _signals[i] = Notifier::upstream_empty_signal(this, i);
    }
    _inport_prio = new int [ninputs()];
    return 0;
}

void
PrioSched2::cleanup(CleanupStage)
{
    delete[] _signals;
}

Packet *
PrioSched2::pull(int)
{
    int n = ninputs();
    int i = _start;
    for (int j = 0; j < n; j++) {
	    Packet *p = (_signals[i] ? input(i).pull() : 0);
	    if (p) {
            if ( i != _start ){
                calculate_prio(i);
            }
	        return p;
	    }
        i++;
        if (i >= n){
           i = 0; 
        }
    }
    return 0;
}

void 
PrioSched2::calculate_prio(int inport){
    _inport_prio[inport]++;
    if ( _inport_prio[inport] > _threshold ){
        _start = inport;
        _inport_prio[inport] = 0;
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PrioSched2)
ELEMENT_MT_SAFE(PrioSched2)
