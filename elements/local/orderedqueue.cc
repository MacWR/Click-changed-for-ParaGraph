/*
 * OrderedQueue.{cc,hh} -- provides a packet buffer
 * Rui Wang
 *
 * Copyright (c) 2001 Massachusetts Institute of Technology
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
#include <click/args.hh>
#include "orderedqueue.hh"
CLICK_DECLS

OrderedQueue::OrderedQueue()
  : _chain(0)
{
}

OrderedQueue::~OrderedQueue()
{
}

int
OrderedQueue::configure(Vector<String> &conf, ErrorHandler *errh)
{
  _skip = false;
  return Args(conf, this, errh)
  .read_mp("BURST", _burst)
  .read_p("SKIP", _skip)
  .complete();
}


int
OrderedQueue::initialize(ErrorHandler *)
{
  _start_push = false;
  _start_pull = false;
  return 0;
}

void
OrderedQueue::cleanup(CleanupStage)
{
  OrderedQueueElt *elt = _chain;
  while (elt) {
    OrderedQueueElt *t = elt;
    elt = elt->next();
    Packet *p = t->kill_elt();
    p->kill();
  }
  assert(_chain == 0);
}

void
OrderedQueue::push(int, Packet *p)
{
  uint16_t sn = seqno(p);
  if (!_start_push)
    _initial_seq = 0;
  else if (_start_pull && sn < _first_seq ) {
    p->kill();
    return;
  }
  new OrderedQueueElt(&_chain, p);
}

void
OrderedQueue::dump()
{
  click_chatter("seq0 %u, seq %u", _initial_seq, _first_seq);
  OrderedQueueElt *elt = _chain;
  while(elt) {
    Packet *pp = elt->packet();
    click_chatter("elt %p (%p): %u", elt, pp, seqno(pp));
    elt = elt->next();
  }
}

Packet *
OrderedQueue::pull(int)
{
  if (_chain) {
    Packet *p = _chain->packet();
    p->set_anno_u8(7,_chain->get_anno7());
    if (!_start_pull || _skip || seqno(p)==_first_seq) {
      _chain->kill_elt();
      _first_seq = (seqno(p) + 1) % _burst;
      _start_pull = true;
      return p;
    }
  }
  return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(OrderedQueue)
