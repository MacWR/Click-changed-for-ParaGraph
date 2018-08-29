// -*- c-basic-offset: 4 -*-
#ifndef CLICK_PRIOSCHED2_HH
#define CLICK_PRIOSCHED2_HH
#include <click/element.hh>
#include <click/notifier.hh>
CLICK_DECLS

/*
 * =c
 * PrioSched(THRESHOLD)
 * =s scheduling
 * pulls from priority-scheduled inputs
 * =d
 * Each time a pull comes in the output, PrioSched pulls from
 * each of the inputs starting from the dynamic start inport selected by the frequncy of the incoming packets.
 * The packet from the first successful pull is returned.
 * This amounts to a strict priority scheduler.
 *
 * The inputs usually come from Queues or other pull schedulers.
 * PrioSched uses notification to avoid pulling from empty inputs.
 *
 * =a Queue, RoundRobinSched, StrideSched, DRRSched, SimplePrioSched
 */

class PrioSched2 : public Element { public:

    PrioSched2() CLICK_COLD;

    const char *class_name() const	{ return "PrioSched2"; }
    const char *port_count() const	{ return "-/1"; }
    const char *processing() const	{ return PULL; }
    const char *flags() const		{ return "S0"; }

    int initialize(ErrorHandler *) CLICK_COLD;
    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;

    void calculate_prio(int inport);
    Packet *pull(int port);

  private:
    int _start;
    int *_inport_prio;
    int _threshold;
    NotifierSignal *_signals;

};

CLICK_ENDDECLS
#endif
