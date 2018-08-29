#ifndef CLICK_TEE2_HH
#define CLICK_TEE2_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * Tee2([N])
 *
 * PullTee2([N])
 * =s basictransfer
 * duplicates packets
 * =d
 * Tee sends a copy of each incoming packet out each output.
 *
 * PullTee's input and its first output are pull; its other outputs are push.
 * Each time the pull output pulls a packet, it
 * sends a copy out the push outputs.
 *
 * Tee and PullTee have however many outputs are used in the configuration,
 * but you can say how many outputs you expect with the optional argument
 * N.
 */

class Tee2 : public Element {

 public:

  Tee2() CLICK_COLD;

  const char *class_name() const		{ return "Tee2"; }
  const char *port_count() const		{ return "1/1-"; }
  const char *processing() const		{ return PUSH; }

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  void push(int, Packet *);

private:
  uint16_t _anno8;
  uint8_t _anno7;

};

class PullTee2 : public Element {

 public:

  PullTee2() CLICK_COLD;

  const char *class_name() const		{ return "PullTee2"; }
  const char *port_count() const		{ return "1/1-"; }
  const char *processing() const		{ return "l/lh"; }

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *pull(int);

};

CLICK_ENDDECLS
#endif
