#ifndef CLICK_MERGE_HH
#define CLICK_MERGE_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/standard/storage.hh>
CLICK_DECLS

/*
 * =c
 * Merge(BURST,NOCOPY)
 *
 * =s transfer
 * Merge the original packets and their copies.
 * =d
 * Merge pulls the original packets by the inport 0(pull) and get their copies by the other inports(push), 
 * then merge will merge these packets into the only terminal packet. At last, merge outputs the terminal packet by ouport 0. 
 *
 *
 * Merge have however many inputs are used in the configuration,
 * but you can say how many inputs you expect with the optional argument
 * N.
 */

class PacketBuffer ;

class Merge : public Element {

public:

  Merge() CLICK_COLD;

  const char *class_name() const		{ return "Merge";}
  const char *port_count() const		{ return "2/1"; }
  const char *processing() const		{ return "Pull"; }

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
  int initialize(ErrorHandler *errh);

  WritablePacket *pull(int);
  int check_packet_buffer_is_ok(unsigned int packet_no);
  WritablePacket *merge_packets(unsigned int packet_no);
  void set_length_field(WritablePacket *p);

  WritablePacket *set_crc32(WritablePacket *p);
  WritablePacket *set_IPchecksum(WritablePacket *p_in);
  WritablePacket *set_UDPchecksum(WritablePacket *p_in);
  WritablePacket *set_TCPchecksum(WritablePacket *p_in);

private:

  int _nocopy;
  unsigned int _next;
  unsigned int _burstsize;
  int *_copies_blacklist;
  int *_packet_blacklist;
  PacketBuffer *_packet_buffer;
  
  
};

class PacketBuffer {
  
public:

  PacketBuffer();
  PacketBuffer(int copies_count);
  ~PacketBuffer();

  bool copies_is_full() {return (_next_position == _copies_count); } 
  int get_next_position() { return _next_position; }
  void reset(); 

  void set_original_packet(Packet *p);
  unsigned char *get_original_packet() { return _original_packet; }
  uint32_t get_original_packet_ipv4_header_len() { return _original_packet_ipv4_header_len; }
  unsigned int get_original_packet_transport_header_len() { return _original_packet_transport_header_len; }

  int check_operation(Packet *q);
  void set_packet_copies(Packet *q);
  bool check_and_set_packet_copies(Packet *q);

  unsigned char **get_packet_copies() { return _packet_copies; }
  uint32_t get_packet_copies_ipv4_header_len(int i) { return _packet_copies_ipv4_header_len[i]; }
  unsigned int get_packet_copies_tcp_header_len(int i) { return _packet_copies_tcp_header_len[i]; }
  unsigned int get_packet_copies_priority(int i) { return _packet_copies_priority[i]; }


private:

  int _next_position;
  int _copies_count; //=_nocopy

  unsigned char *_original_packet;
  uint32_t _original_packet_ipv4_header_len;
  unsigned int _original_packet_transport_header_len;
  
  unsigned char **_packet_copies;
  uint32_t *_packet_copies_ipv4_header_len;
  unsigned int *_packet_copies_tcp_header_len;
  unsigned int *_packet_copies_priority; //from 1 to _copies_count, default =0
  
};



CLICK_ENDDECLS
#endif
