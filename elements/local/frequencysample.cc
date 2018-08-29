// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * FrequencySample.{cc,hh} -- element probabilistically samples packets
 * Rui Wang
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2001 International Computer Science Institute
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
#include "frequencysample.hh"
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/error.hh>

CLICK_DECLS

FrequencySample::FrequencySample()
:_counter(0),_round(0)
{
}

int
FrequencySample::configure(Vector<String> &conf, ErrorHandler *errh)
{   
    _start = false;
    _end = false;
    _verbose = false;
    if (Args(conf, this, errh)
	.read_mp("FREQUENCY", _frequency)
    .read_mp("LABEL", _label)
    .read_p("START", _start)
    .read_p("END", _end)
    .read_p("VERBOSE", _verbose)
	.complete() < 0)
	return -1;
    return 0;
}

void
FrequencySample::push(int, Packet *p)
{   
    p->timestamp_anno().assign_now();
    output(0).push(p);
    if ( _counter < _frequency ){
        if ( _counter == 0 && _start ){
            dump(p);  
        }
        _counter++; 
    }else{
        if ( _counter == _frequency && _end ){
            dump(p);
        }
        _counter = 0;
        if ( _round > 30000 ){
            _round = 0;
        }else{
            _round++;  
        }
    }
}

void 
FrequencySample::dump(Packet *p){
    StringAccum sa(_label.length() + 2 // label:
		   + 28 + 4 );	// timestamp: //if _counter+_round then 8
    const char *sep = "";
    sa << _label;
	sep = ": ";
    sa << sep << p->timestamp_anno();
    if ( _verbose ){
//        sa << sep << _counter;
        sa << sep << _round;
    }
    click_chatter("%s", sa.c_str());
}



CLICK_ENDDECLS
EXPORT_ELEMENT(FrequencySample)
ELEMENT_MT_SAFE(FrequencySample)
