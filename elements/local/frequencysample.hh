// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_FREQUENCYSAMPLE_HH
#define CLICK_FREQUENCYSAMPLE_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS

/*
 * =c
 *
 * FrequencySample(FREQUENCY,LABEL,[START,END,VERBOSE])
 *
 * =s classification
 *
 * samples the start or the end packet with the frequency 
 *
 */

class FrequencySample : public Element { public:

    FrequencySample() CLICK_COLD;

    const char *class_name() const		{ return "FrequencySample"; }
    //const char *port_count() const		{ return PORTS_1_1X2; }
    const char *port_count() const		{ return PORTS_1_1; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

    void push(int port, Packet *);

  private:
    int _frequency;
    int _counter;
    int _round;
    String _label;
    bool _start;
    bool _end;
    bool _verbose;

    void dump(Packet *p);

};

CLICK_ENDDECLS
#endif
