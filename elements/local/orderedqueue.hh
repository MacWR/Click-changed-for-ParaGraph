#ifndef CLICK_ORDEREDQUEUE_HH
#define CLICK_ORDEREDQUEUE_HH
#include <click/element.hh>
#include <click/packet_anno.hh>
CLICK_DECLS

/*
 * =c
 * OrderedQueue(BURST,[SKIP])
 * =s 
 * buffer packets according to their paint.anno(8)
 * =d
 * provides in order packet buffer.
 *
 * packets arriving at the input push port are inserted into a linked list,
 * sorted increasingly on the anno(8). packets with a sequence
 * number already on the list will be dropped.
 *
 * packets are pulled out of OrderedQueue. pull will return packets in order. if
 * SKIP is false, and there is a packet missing in the middle of a sequence,
 * OrderedQueue will return 0 until that packet arrives. SKIP is false by
 * default. setting SKIP to true allow puller to skip missing packets, but
 * still get packets in order.
 *
 * if a packet arrives at OrderedQueue, but it's sequence number is smaller than
 * that of the first packet on the linked list, the packet is deleted. in this
 * case, OrderedQueue assumes the packet is either a retransmit (if SKIP is
 * false) or the puller is no longer interested in it (if SKIP is true).
 *
 * the first packet arrives at OrderedQueue gets to set the initial sequence
 * number. it is expected that this packet will be either a SYN or a SYN ACK
 * packet.
 *
 * TODO
 *   prevent packets with bad seq number range from corrupting queue;
 *   should reject packets with overlaping seq number range
 */

class OrderedQueue : public Element {
private:
  static const int _capacity = 65000;

  class OrderedQueueElt {
  private:
    Packet *_packet;
    uint8_t _anno7;
    OrderedQueueElt **_chain_ptr;
    OrderedQueueElt *_next;
    OrderedQueueElt *_prev;

  public:
    OrderedQueueElt(OrderedQueueElt **chain, Packet *p);

    uint8_t get_anno7() const   { return _anno7; }
    OrderedQueueElt *next() const		{ return _next; }
    OrderedQueueElt *prev() const		{ return _prev; }
    Packet* packet() const		{ return _packet; }

    Packet* kill_elt();
  };

  OrderedQueueElt *_chain;
  uint16_t _initial_seq;
  uint16_t _first_seq;
  bool _start_pull;
  bool _start_push;

  bool _skip;
  uint16_t _burst;
  void dump();

public:

  OrderedQueue() CLICK_COLD;
  ~OrderedQueue() CLICK_COLD;

  const char *class_name() const		{ return "OrderedQueue"; }
  //const char *port_count() const		{ return PORTS_1_1; }
  const char *port_count() const		{ return "-/1"; }
  const char *processing() const		{ return PUSH_TO_PULL; }

  int initialize(ErrorHandler *) CLICK_COLD;
  void cleanup(CleanupStage) CLICK_COLD;
  int configure(Vector<String> &conf, ErrorHandler *errh) CLICK_COLD;

  void push(int, Packet *);
  Packet *pull(int);

  /* if there is a missing sequence, set seqno to
   * that sequence number. returns false if no packets
   * have arrived at the buffer. true otherwise. */
  bool first_missing_seq_no(uint16_t& seqno);

  /* if there is a missing sequence after pos, set seqno
   * to that sequence number. returns false if no packets
   * have arrived at the buffer. true otherwise. */
  bool next_missing_seq_no(uint16_t pos, uint16_t &seqno);

  //static unsigned seqlen(Packet *);
  static uint16_t seqno(Packet *);
};

inline
OrderedQueue::OrderedQueueElt::OrderedQueueElt(OrderedQueueElt **chain_ptr, Packet *p)
{
  uint16_t seqn = seqno(p);
  _chain_ptr = chain_ptr;
  _packet = p;
  _anno7 = p->anno_u8(7);

  if (*chain_ptr == 0) {
    *chain_ptr = this;
    _next = 0;
    _prev = 0;
    return;
  }
  else {
    OrderedQueueElt *list = *chain_ptr;
    OrderedQueueElt *lprev = 0L;
    do {
      Packet *pp = list->packet();
      if ( seqn < seqno(pp) ) {
	/* insert here */
	_next = list;
	_prev = list->_prev;
	_next->_prev = this;
	if (_prev)
	  _prev->_next = this;
	if (list == *chain_ptr)
          *chain_ptr = this;
	return;
      }
      else if (seqn == seqno(pp)) {
        p->kill();
	delete this;
	return;
      }
      lprev = list;
      list = list->_next;
    } while(list);
    if (!list) {
      /* add to end of list */
      _next = 0;
      _prev = lprev;
      lprev->_next = this;
      return;
    }
  }
}

inline Packet *
OrderedQueue::OrderedQueueElt::kill_elt()
{
  Packet *p = _packet;
  if (_chain_ptr && *_chain_ptr == this) {
    /* head of chain */
    if (_next)
      _next->_prev = 0;
    *_chain_ptr = _next;
  }
  else if (_prev || _next) {
    if (_prev)
      _prev->_next = _next;
    if (_next)
      _next->_prev = _prev;
  }
  _prev = 0;
  _next = 0;
  _packet = 0;
  delete this;
  return p;
}

inline bool
OrderedQueue::first_missing_seq_no(uint16_t& sn)
{
  if (!_chain && !_start_pull)
    return false;
  uint16_t expect =
    _start_pull ? _first_seq : seqno(_chain->packet());
  return next_missing_seq_no(expect, sn);
}

inline bool
OrderedQueue::next_missing_seq_no(uint16_t pos, uint16_t& sn)
{
  OrderedQueueElt *elt = _chain;
  uint16_t expect = _first_seq;
  if (elt) {
    Packet *p = elt->packet();
    expect = _start_pull ? _first_seq : seqno(p);
    while(elt) {
      Packet *p = elt->packet();
      if (seqno(p) != expect) {
	if ( expect >= pos ) {
	  sn = expect;
	  return true;
	}
	else if ( seqno(p) > pos ) {
	  sn = pos;
	  return true;
	}
      }
      expect = (seqno(p) + 1) % _burst;
      elt = elt->next();
    }
  }
  if (_start_pull || _chain) {
    if ( expect >= pos ) {
      sn = expect;
      return true;
    }
    else {
      sn = pos;
      return true;
    }
  }
  return false;
}

inline uint16_t
OrderedQueue::seqno(Packet *p)
{
  return p->anno_u16(8);
}

CLICK_ENDDECLS
#endif
