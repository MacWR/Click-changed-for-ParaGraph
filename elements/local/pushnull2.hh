#ifndef CLICK_PUSHNULL2_HH
#define CLICK_PUSHNULL2_HH
#include <click/element.hh>
CLICK_DECLS


/*
=c
PushNull2

=s basictransfer
push-only null element

=d
Responds to each pushed packet by pushing it unchanged out its first output.

=a
Null, PullNull
*/

class PushNull2 : public Element { public:

  PushNull2() CLICK_COLD;

  const char *class_name() const	{ return "PushNull2"; }
  const char *port_count() const	{ return "-/1"; }
  const char *processing() const	{ return PUSH; }

  void push(int i, Packet *);

};


CLICK_ENDDECLS
#endif
