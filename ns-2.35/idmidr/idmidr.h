/*
 *  Copyright (C) 2015  J.E. Martinez.
 *  NDS-Lab CIC IPN.
 *
 *  This file is part of IDMIDR.
 *
 *  IDMIDR is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  IDMIDR is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with IDMIDR. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef IDMIDR_H_
#define IDMIDR_H_

#include "neighborhood_list.h"

#define NOW                     Scheduler::instance().clock()
#define INVALID_ADDRESS         -987654
#define INFI_                   99
#define MAX_ACTIVE_DESTS        25
#define INVALID_SEQUENCE_NUMBER 0
#define INVALID_TIME            -16.0
#define MA_PERIOD               3.000
#define BROADCAST_JITTER        0.010 
#define COLLECTION_PERIOD	0.050
#define MIN_NR_PERIOD		0.10
#define SEQ_UPDATE		3
#define DIST_UPDATE		2
#define NO_UPDATE		1
#define DISCARD_UPDATE		0
//number of requests before changing anchor
#define ANY_TRIES		4	
//consider a node source if it's transmitted data whitin ANY_SOURCE secs before
#define ANY_SOURCE		0.50	
#define R			2
#define DESTINATION_PORT 	100
#define NO_UPSTREAM_SOURCE      0
#define MAX(a,b) (((a)>(b))?(a):(b))
#define MIN(a,b) (((a)<(b))?(a):(b))
//membership_code (Next version)
#define REGULAR_                211
#define MESH_MEMBER_            212
#define RECEIVER_               213
#define RECEIVER_MEMBER_        214
//dissemination type
#define FLOODING_               0
#define REGION_OF_INTEREST_     2
//ph type
#define MR_                     1
#define MA_                     2
#define MA_BUCKET_              3
#define NEIGHBOR_REQUEST_       4
//Requests
#define RREQ_RETRIES            3  
#define MAX_RREQ_TIMEOUT        10.0
#define TTL_THRESHOLD 		7
#define TTL_INCREMENT 		2
#define NETWORK_DIAMETER        15 

struct MaToSend{
  nsaddr_t destination_addr;
  unsigned int sequence;
  unsigned char dissemination_type;
  unsigned char distance_to_source; 
};

struct MrSent{
  nsaddr_t destination_addr;
  double time;
};

struct DestinationItem {
  nsaddr_t destination_addr;
  nsaddr_t core_id;
  unsigned int last_seq;
  float last_ma_received;
  float last_ma_generated;
  double last_nr_generated;
  nsaddr_t prefered_anchor;
  float last_data_received;
  float last_data_originated;
  float am_i_interested;
  double lastIndirectDistance;
  unsigned int distance_to_core;
  unsigned int feasible_distance;
  unsigned char membership_code;
  nsaddr_t next_hop;
  NeighborhoodList* neighborhood_list;
  GenericCache* anchor_list;
  DestinationItem* next;
  int rt_req_last_ttl;        
  double rt_req_timeout;     
  u_int8_t rt_req_cnt;      
  bool receiver;
  unsigned int r;
  DestRequested* last_request;
};

class DestinationList {
protected:
  DestinationItem* front;
public:
  DestinationList();
  ~DestinationList();
  DestinationItem* pufind(nsaddr_t);
  void puadd_from_transport(nsaddr_t);
  void add(DestinationItem*);
  void delete_neighbor(nsaddr_t);
  bool upstream_source(nsaddr_t, unsigned int);
  unsigned int get_largest_distance(nsaddr_t, unsigned int);
  void mi_update(nsaddr_t, DestinationItem*);
};

enum EventType{
  PM_NEXT_MA=71,
  NEXT_BUCKET=141,
  CHANGE_ANCHOR=151	
};

class IDMIDREvent : public Event {
public:
  IDMIDREvent();
  virtual EventType get_type() = 0;
};

class NextMa : public IDMIDREvent {
protected:
  nsaddr_t destination_addr;
public:
  NextMa(nsaddr_t);
  EventType get_type();
  nsaddr_t get_destination_address();
};

class  ChangeAnchor: public IDMIDREvent {
protected:
  DestinationItem* destination;
public:
  ChangeAnchor(DestinationItem*);
  EventType get_type();
  DestinationItem* get_destination();
};

class  NextBucket: public IDMIDREvent {
public:
  EventType get_type();
};

class IDMIDR;

/*
 * Routing Timer
 */

class IDMIDRTimer:public Handler {
protected:
  IDMIDR* agent;
public:
  IDMIDRTimer(IDMIDR*);
  virtual void handle(Event*);
};

/*
 * IDMIDR
 */

class IDMIDR : public Tap, public Agent {
  friend class IDMIDRTimer;
protected:
  nsaddr_t id;
  IDMIDRTimer* idmidr_timer;
  RNG random;
  PortClassifier* dmux; 
  Trace* logTarget;     
  Mac* mac;
  GenericCache message_cache;
  GenericCache control_cache;
  void handle_protocol_event(Event*); 
  unsigned int overhead_sequence;
  void schedule_timer(IDMIDREvent*, float);	
  DestinationList destination_list;
public:
  void pm_explicit_ack_fail(Packet* p);
  void tap(const Packet*);
protected:
  void start_receiving(nsaddr_t);
  void try_to_add_destination(DestinationItem*&, nsaddr_t);
  void pm_handle_protocol_packet(Packet*);
  void pm_handle_data_from_transport(Packet*);
  void pm_generate_mr(DestinationItem*, Packet*);
  void transmit_an_mr(DestinationItem*, nsaddr_t, char, char, int, unsigned int);
  void pm_handle_an_mr(Packet*);
  void pm_handle_a_normal_mr(Packet*);
  void pm_save_distance(nsaddr_t, unsigned int);
  bool pm_am_i_destination(DestinationItem*);
  void pm_compare_states(Packet*, MeshRequest*, DestinationItem*, nsaddr_t);
  void pm_valid_core(DestinationItem*);
  void pm_become_core(DestinationItem*);
  void pm_transmit_an_ma(DestinationItem*, unsigned char, unsigned int);
  void pm_handle_an_ma(Packet*);
  void pm_handle_a_normal_ma(nsaddr_t, MeshAnnouncement*);
  void pm_process_ma(nsaddr_t, MeshAnnouncement*, DestinationItem*);
  bool pm_state_changed(DestinationItem*, DestinationItem*);   
  void pm_send_data_packet(Packet*, DestinationItem*);
  void pm_handle_data_from_network(Packet*);
  void pm_accept_data(Packet*);
  void pm_neighbor_fail(nsaddr_t, nsaddr_t);
  void pm_handle_neighbor_request(Packet*);
  void pm_update_next_hop(DestinationItem*, bool);
  void pm_update_membership(DestinationItem*);
  void pu_send_neighbor_request(DestinationItem* , nsaddr_t);

  //MABucket

  void try_to_add_ma(nsaddr_t, unsigned int, unsigned char, unsigned int, bool);
  void add_ma(nsaddr_t, unsigned int, unsigned char, unsigned int, MaToSend*);
  void reset_bucket();
  void set_bucket_tx_time();
  void transmit_bucket();
  int bucket_size;
  void pm_handle_a_bucket(Packet*);
  MaToSend ma[MAX_ACTIVE_DESTS];
  double next_bucket_time;

public:
  IDMIDR(nsaddr_t);
  int command(int, const char*const*);
  void recv(Packet*, Handler*);
};
#endif /*IDMIDR_H_*/
