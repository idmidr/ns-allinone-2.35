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

#include <classifier-port.h>
#include <agent.h>
#include <ip.h>
#include <packet.h>
#include <timer-handler.h>
#include <address.h>
#include <rng.h>
#include <cmu-trace.h>
#include <trace.h>
#include <mac.h>
#include "generic_cache.h"
#include "destination_requested_cache.h"
#include "idmidr_pkt.h"
#include "idmidr.h"

//DESTINATION_LIST
DestinationList::DestinationList(){
  front = 0;
}

DestinationList::~DestinationList(){
  DestinationItem* temp;
  while(front!=0){
    temp=front->next;
    delete front;
    front=temp;
    }
}

DestinationItem*
DestinationList::pufind(nsaddr_t destination_addr){
  DestinationItem* temp=front;
  while (temp!=0){
    if (temp->destination_addr==destination_addr)
      return temp;
      temp=temp->next;
    }
  return 0;
}

void
DestinationList::puadd_from_transport(nsaddr_t destination_addr){
  DestinationItem* temp=new DestinationItem();
  temp->destination_addr=destination_addr;
  temp->core_id=INVALID_ADDRESS;
  temp->last_seq=INVALID_SEQUENCE_NUMBER;
  temp->last_ma_generated=INVALID_TIME;
  temp->last_nr_generated=INVALID_TIME;
  temp->last_ma_received=INVALID_TIME;
  temp->last_data_received=INVALID_TIME;
  temp->last_data_originated=INVALID_TIME;
  temp->prefered_anchor=INVALID_ADDRESS;
  temp->am_i_interested=INVALID_TIME;
  temp->lastIndirectDistance=INVALID_TIME;
  temp->distance_to_core=INFI_;
  temp->feasible_distance=INFI_;
  temp->membership_code=REGULAR_;
  temp->next_hop=INVALID_ADDRESS;
  temp->neighborhood_list=new NeighborhoodList();
  temp->rt_req_last_ttl=INFI_;
  temp->rt_req_timeout = 0.0;
  temp->rt_req_cnt = 0;
  temp->receiver=false;
  temp->r=0;
  temp->anchor_list=new GenericCache();
  temp->last_request=new DestRequested();
  temp->next=NULL;
  add(temp);
}

void
DestinationList::add(DestinationItem* group){
  if (group != NULL){
    group->next = front;
    front = group;
    }
}
		
void 
DestinationList::delete_neighbor(nsaddr_t neighbor){
  DestinationItem* temp=front;
  while (temp!=0){
    temp->neighborhood_list->remove(neighbor);
    temp=temp->next;
  }
}


bool
DestinationList::upstream_source(nsaddr_t destination_addr, unsigned int prevHopDistance){
  DestinationItem* temp=front;
  while (temp!=0){
    if(temp->last_request->find_source(destination_addr, prevHopDistance)){
      return true;
      }
    temp=temp->next;
  }
  return false;
}

void 
DestinationList::mi_update(nsaddr_t id, DestinationItem* destination){
  nsaddr_t tempAnchor=INVALID_ADDRESS;
  u_int32_t tempSeq=0;
  unsigned int tempDis=INFI_;
  nsaddr_t tempNext=INVALID_ADDRESS;
  for (NeighborItem* nlTemp = destination->neighborhood_list->front; nlTemp != 0; nlTemp = nlTemp->next){
    if((nlTemp->time_added+(2*MA_PERIOD))>=NOW){
      GenericCacheItem* alTemp=destination->anchor_list->find_source(nlTemp->core_id);
      if (nlTemp->sequence==alTemp->sequence && nlTemp->distance_to_core==alTemp->distance){  
        if (nlTemp->distance_to_core<tempDis ||
           ((nlTemp->distance_to_core==tempDis) && (tempAnchor<nlTemp->core_id)) || 
           ((nlTemp->distance_to_core==tempDis) && (tempAnchor==nlTemp->core_id) && 
					      (tempNext<nlTemp->received_from))){
            tempAnchor=nlTemp->core_id;
            tempSeq=nlTemp->sequence;
            tempDis=nlTemp->distance_to_core;
            tempNext=nlTemp->received_from;
          }
        }
      }
    }
  destination->core_id=tempAnchor;
  destination->last_seq=tempSeq;
  if (tempDis==INFI_)
    destination->distance_to_core=INFI_;
  else
    destination->distance_to_core=tempDis+1;
  destination->next_hop=tempNext;
}

unsigned int
DestinationList::get_largest_distance(nsaddr_t destination_addr, unsigned int upperBound){
  unsigned int largestDistance=0;
  unsigned int tempDistance=0;
  DestinationItem* temp=front;
  while (temp!=0){
    tempDistance=temp->last_request->get_distance(destination_addr);
    if((tempDistance<upperBound) && (tempDistance>largestDistance)){
      largestDistance=tempDistance;      
      }
    temp=temp->next;
  }
  return largestDistance;
}

//Timers
IDMIDREvent::IDMIDREvent():Event() {
}

NextMa::NextMa(nsaddr_t destination_addr) {
  this->destination_addr = destination_addr;
}

EventType
NextMa::get_type() {
  return PM_NEXT_MA;
}

nsaddr_t
NextMa::get_destination_address() {
  return destination_addr;
}

EventType
NextBucket::get_type(){
  return NEXT_BUCKET;
}

ChangeAnchor::ChangeAnchor(DestinationItem* destination){
  this->destination=destination;
}

EventType
ChangeAnchor::get_type(){
  return CHANGE_ANCHOR;
}

DestinationItem*
ChangeAnchor::get_destination(){
  return destination;
}

void
IDMIDRTimer::handle(Event* e) {
  agent->handle_protocol_event(e);
}

IDMIDRTimer::IDMIDRTimer(IDMIDR* agent) : Handler() {
  this->agent = agent;
}

//TCL Hooks
int hdr_idmidr::offset_;
static class IDMIDRHeaderClass : public PacketHeaderClass {
public:
  IDMIDRHeaderClass() : PacketHeaderClass("PacketHeader/IDMIDR",sizeof(hdr_idmidr)) {
  bind_offset(&hdr_idmidr::offset_);
  }
} class_rtProtoIDMIDR_hdr;

static class IDMIDRClass : public TclClass {
public:
  IDMIDRClass() : TclClass("Agent/IDMIDR") {}
  TclObject* create(int argc, const char*const* argv) {
  return (new IDMIDR((nsaddr_t) Address::instance().str2addr(argv[4])));
  }
} class_rtProtoIDMIDR;

//IDMIDR
IDMIDR::IDMIDR(nsaddr_t new_id) : Agent(PT_IDMIDR), 
                                  message_cache(), 
                                  control_cache() {
  id = new_id;
  logTarget = NULL;
  overhead_sequence=0;
  idmidr_timer= new IDMIDRTimer(this);
  next_bucket_time=0.0;
  for (int i=0; i<MAX_ACTIVE_DESTS; i++){
    ma[i].destination_addr=INVALID_ADDRESS;
    ma[i].sequence=0;  
    }
  bucket_size=0;
}

int
IDMIDR::command(int argc, const char*const* argv) {
  if (argc == 2) {
    if (strncasecmp(argv[1], "start", 2) == 0) {
      return TCL_OK;
      }
    }
  else if (argc == 3) {
    if (strcmp(argv[1], "log-target")  == 0 ||
        strcmp(argv[1], "tracetarget") == 0) {
      logTarget = (Trace*)TclObject::lookup(argv[2]);
      if (logTarget == NULL)
        return TCL_ERROR;
      return TCL_OK;
      }
    if (strcmp(argv[1], "port-dmux") == 0) {
      dmux = (PortClassifier*)TclObject::lookup(argv[2]);
      if (dmux == NULL)
        return TCL_ERROR;
      return TCL_OK;
      }
    if (strcmp(argv[1], "join-group") == 0) {
      start_receiving(atoi(argv[2]));
      return TCL_OK;
      }
    if (strcmp(argv[1], "install-tap") == 0) {
      mac = (Mac*) TclObject::lookup(argv[2]);
      mac->installTap(this);
      return TCL_OK;
      }
    }
  return Agent::command(argc, argv);
}

void
IDMIDR::handle_protocol_event(Event* e){
  if(e != NULL){
    IDMIDREvent* pe = (IDMIDREvent*)e;
    switch (pe->get_type()){
      case PM_NEXT_MA:{
        NextMa* event = (NextMa*)pe;
        DestinationItem* destination=destination_list.pufind(event->get_destination_address());
        if (destination==0) return;
        if((destination->last_data_received+(2*MA_PERIOD))<NOW){
          destination->core_id=INVALID_ADDRESS;
          }
	if (destination->core_id==id){
	  destination->last_seq++;
          try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                        NO_UPSTREAM_SOURCE, false);
	  schedule_timer(new NextMa(destination->destination_addr), MA_PERIOD);
	  }
        break;
        }
      case NEXT_BUCKET:{
        transmit_bucket();
        break;
	}
      case CHANGE_ANCHOR:{
        ChangeAnchor* event = (ChangeAnchor*)pe;
        DestinationItem *destination=event->get_destination();
        if (destination->next_hop!=INVALID_ADDRESS)
          return;
        destination->prefered_anchor=INVALID_ADDRESS;
        destination_list.mi_update(id, destination);
        if (destination->next_hop!=INVALID_ADDRESS){
          GenericCacheItem* temp=destination->anchor_list->find_source(destination->prefered_anchor);
          destination->last_ma_received=temp->time; 
          destination->rt_req_cnt = 0; 
          destination->rt_req_timeout = 0.0;
          try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                        NO_UPSTREAM_SOURCE, true);
          }
        break;
        }
      }
    }
}

void
IDMIDR::schedule_timer(IDMIDREvent* event, float delay) {
  Scheduler::instance().schedule(idmidr_timer, event, delay);
}

void 
IDMIDR::try_to_add_destination(DestinationItem*& destination, nsaddr_t destination_addr){
  destination=destination_list.pufind(destination_addr);
  if (destination==0){
    destination_list.puadd_from_transport(destination_addr);
    destination=destination_list.pufind(destination_addr);
    }
}

void
IDMIDR::start_receiving(nsaddr_t destination_addr){
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  destination->receiver=true;
}

void
IDMIDR::recv(Packet *p, Handler*){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  if ((HDR_CMN(p)->ptype() == PT_IDMIDR))
    pm_handle_protocol_packet(p);
  else if ((ih->saddr() == id) && (ch->num_forwards() == 0))
    pm_handle_data_from_transport(p);
  else pm_handle_data_from_network(p);
}

void
IDMIDR::pm_handle_data_from_transport(Packet *p){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  nsaddr_t destination_addr=ih->daddr();
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  if (pm_am_i_destination(destination)){
    Packet::free(p);
    return;
    }
  DestinationItem* source=0;
  try_to_add_destination(source, id);
  source->distance_to_core=0;
  destination->am_i_interested=NOW;
  destination->last_data_originated=NOW;
  bool sendNR=true;
  if((destination->last_ma_received+(2*MA_PERIOD))<NOW) sendNR=false;
  pm_update_next_hop(destination, sendNR);
  if((destination->last_ma_received+(2*MA_PERIOD))<NOW){
    pm_generate_mr(destination, p);
    }
  else{
    nsaddr_t next_hop=destination->next_hop;
    if(next_hop!=INVALID_ADDRESS){
      pm_update_membership(destination);
      message_cache.add(id, ch->uid());
      ih->ttl_ = NETWORK_DIAMETER;
      ih->anycast_dst()=destination->core_id;
      ch->size()+= IP_HDR_LEN;
      ch->size()+=8; //IDMIDR options (IP header)
      pm_send_data_packet(p,destination);
      }
    else{//routeState==DOWN
      pm_generate_mr(destination, p);
      }
    }
}

static void
idmidr_rt_failed_callback(Packet *p, void *arg) {
  ((IDMIDR*) arg)->pm_explicit_ack_fail(p);
}

void
IDMIDR::pm_send_data_packet(Packet* p, DestinationItem* destination){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  ch->direction()=hdr_cmn::DOWN;
  ch->error()=0;
  ch->prev_hop_=id;
  nsaddr_t next_hop;
  if (destination->core_id==INVALID_ADDRESS) return;
  next_hop=destination->next_hop;
  if (destination->core_id==id) next_hop=id;
  ch->next_hop()=IP_BROADCAST;
  ih->next_hop()=IP_BROADCAST;
  ch->addr_type()=NS_AF_INET;
  ih->daddr()=destination->destination_addr;
  ih->sport()=RT_PORT;
  ih->dport()=RT_PORT;
  ih->ttl()--;
  ch->next_hop()=next_hop;
  ch->xmit_failure_=idmidr_rt_failed_callback;
  ch->xmit_failure_data_=(void*)this;
  Scheduler::instance().schedule(target_, p, BROADCAST_JITTER * random.uniform(1.0));
}

void
IDMIDR::pm_handle_data_from_network(Packet *p){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  nsaddr_t destination_addr=ih->daddr();
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  nsaddr_t prevHopAddr=ch->prev_hop_;
  pm_save_distance(prevHopAddr, 1);
  if ((ih->ttl() < 1) || message_cache.find(ih->saddr(), ch->uid())){
    Packet::free(p);
    return;
    }
  message_cache.add(ih->saddr(), ch->uid());
  destination->am_i_interested=NOW;
  nsaddr_t sourceAddr=ih->saddr();
  pm_save_distance(sourceAddr, (NETWORK_DIAMETER-ih->ttl())); //We need to know the initial value of ttl. We used NETWORK_DIAMETER
  nsaddr_t lastCore=destination->core_id;
  pm_update_next_hop(destination, true);
  pm_update_membership(destination);
  bool send_data=destination->neighborhood_list->forward_data(destination->membership_code, destination->distance_to_core,
                                                              id, ch->prev_hop_, destination->last_seq, destination->last_ma_received);

  if (ih->anycast_dst()==id){ 
    destination->last_data_received=NOW;
    pm_accept_data(p->copy());
    }

  if (pm_am_i_destination(destination)){
    if (destination->core_id!=id){
      pm_valid_core(destination);
      if(destination->core_id==id){
          try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                        NO_UPSTREAM_SOURCE, true);
      }
    }
  }

  if ((ih->anycast_dst()==destination->core_id) &&
     (send_data || 
     (ch->next_hop()==id && destination->core_id!=id && destination->next_hop!=INVALID_ADDRESS))){
      pm_send_data_packet(p,destination);
      }
  else if (ch->next_hop()==id && destination->next_hop!=INVALID_ADDRESS && 
          destination->core_id!=id && (destination->last_nr_generated+(1*MIN_NR_PERIOD))<NOW &&
          ((destination->last_ma_generated+(1*MIN_NR_PERIOD))<NOW)){
    pu_send_neighbor_request(destination, ih->anycast_dst());
    Packet::free(p);
    }
  else if (ch->next_hop()==id && destination->next_hop==INVALID_ADDRESS &&
          (destination->last_nr_generated+(1*MIN_NR_PERIOD))<NOW &&
          ((destination->last_ma_generated+(1*MIN_NR_PERIOD))<NOW)){
    if (lastCore!=INVALID_ADDRESS)
      pu_send_neighbor_request(destination, lastCore);
    else if (ih->anycast_dst()!=INVALID_ADDRESS)
      pu_send_neighbor_request(destination, ih->anycast_dst());
    Packet::free(p);
    }

  else{
    Packet::free(p);
    }
}

void
IDMIDR::pm_accept_data(Packet* p) {
  hdr_ip    *ih = HDR_IP(p);
  ih->dst_.port_ = DESTINATION_PORT;
  dmux->recv(p, (Handler*)0);
}

void
IDMIDR::pm_generate_mr(DestinationItem* destination, Packet* data_packet){
  int ttl_=0;
  char dissemination_type=FLOODING_;
  if ((destination==0)
      || (destination->rt_req_timeout > NOW)){
    return;
    }

  if (destination->rt_req_cnt > RREQ_RETRIES) {
    destination->rt_req_timeout = NOW + MAX_RREQ_TIMEOUT;
    destination->rt_req_cnt = 0;
    return;
    }

  if (((destination->lastIndirectDistance+(2*MA_PERIOD))<NOW) &&
       (destination->rt_req_last_ttl != NETWORK_DIAMETER)){
    destination->rt_req_last_ttl = NETWORK_DIAMETER;
  }

    if (destination->rt_req_last_ttl < TTL_THRESHOLD)
      ttl_ = destination->rt_req_last_ttl + TTL_INCREMENT;
    else {
      ttl_ = NETWORK_DIAMETER;
      destination->rt_req_cnt += 1;
      }
  destination->rt_req_last_ttl = ttl_;
  destination->rt_req_timeout = 0.06 * (double) ttl_  ;
  if (destination->rt_req_cnt > 0)
    destination->rt_req_timeout *= destination->rt_req_cnt;
  destination->rt_req_timeout += NOW;
  if (destination->rt_req_timeout > NOW + MAX_RREQ_TIMEOUT)
    destination->rt_req_timeout = NOW + MAX_RREQ_TIMEOUT;
  ++overhead_sequence;
  if((destination->last_ma_received+(2*MA_PERIOD))>=NOW){
    dissemination_type=REGION_OF_INTEREST_;
    }
  transmit_an_mr(destination, id, dissemination_type, 0, ttl_, overhead_sequence);
}

void 
IDMIDR::transmit_an_mr(DestinationItem* destination, nsaddr_t sourceAddr, char dissemination_type,
                      char distance_to_source, int ttl_, unsigned int sequenceNumber){
  MeshRequest mr;
  Packet *p=Packet::alloc(sizeof(mr));
  hdr_cmn *ch=HDR_CMN(p);
  hdr_ip *ih=HDR_IP(p);
  hdr_idmidr *ph=HDR_IDMIDR(p);
  mr.dissemination_type=dissemination_type;
  ih->saddr()=sourceAddr;
  ih->daddr()=destination->destination_addr;
  mr.sequence=sequenceNumber;
  mr.distance_to_source=distance_to_source;
  ch->direction()=hdr_cmn::DOWN;
  ch->error()=0;
  ch->prev_hop_=id;
  ch->next_hop()=IP_BROADCAST;
  ch->addr_type()=NS_AF_INET;
  ih->sport()=RT_PORT;
  ih->dport()=RT_PORT;
  ih->ttl()=ttl_;
  ph->type=MR_;
  ch->ptype()=PT_IDMIDR;
  ch->size()=IP_HDR_LEN+8; //mr size
  control_cache.add(ih->saddr(), mr.sequence);
  *((MeshRequest*)((PacketData*)p->userdata())->data()) = mr;
  Scheduler::instance().schedule(target_, p, BROADCAST_JITTER * random.uniform(1.0));
}

void
IDMIDR::pm_handle_protocol_packet(Packet* p){
  hdr_idmidr *ph=HDR_IDMIDR(p);
  if (ph->type==MR_)
    pm_handle_a_normal_mr(p);
  else if (ph->type==MA_)
    pm_handle_an_ma(p);
  else if (ph->type==MA_BUCKET_) 
    pm_handle_a_bucket(p);
  else //(ph->type==NEIGHBOR_REQUEST)
    pm_handle_neighbor_request(p);
}

void
IDMIDR::pm_handle_an_ma(Packet* p){
  MeshAnnouncement ma;
  ma=*((MeshAnnouncement*)((PacketData*)p->userdata())->data());
  hdr_cmn *ch=HDR_CMN(p);
  nsaddr_t prevHopAddr=ch->prev_hop_;
  pm_handle_a_normal_ma(prevHopAddr, &ma);
  Packet::free(p);
}

void 
IDMIDR::pm_handle_a_normal_ma(nsaddr_t prevHopAddr, MeshAnnouncement* ma){
  nsaddr_t destination_addr=ma->destination_addr;
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  pm_save_distance(prevHopAddr, 1);
  if (!(ma->core_id==id)){
    pm_process_ma(prevHopAddr, ma, destination);
    } 
}

void 
IDMIDR::pm_process_ma(nsaddr_t prevHopAddr, MeshAnnouncement* ma, DestinationItem* destination){
  bool changes=false;
  DestinationItem previous_state=*destination;
  if (!destination->receiver){
    Update tempUpdate;
    destination->anchor_list->update_source(ma->core_id, ma->sequence, ma->distance_to_core, tempUpdate);
    if (tempUpdate.type)
      destination->neighborhood_list->mi_add(ma->core_id, ma->next_hop, ma->sequence, ma->distance_to_core,
                                             prevHopAddr, tempUpdate.time);
    if (tempUpdate.type==SEQ_UPDATE){
      pm_save_distance(ma->core_id, (ma->distance_to_core+1));
        destination->last_ma_received=NOW; 
        pm_save_distance(destination->destination_addr, (ma->distance_to_core+1));
        destination->rt_req_cnt = 0;
        destination->rt_req_timeout = 0.0; 
      if (ma->core_id==prevHopAddr)
        destination->am_i_interested=NOW;    
      }
    destination_list.mi_update(id, destination);
    changes=pm_state_changed(&previous_state, destination);
    }
  unsigned int myDistanceToSource=0;
  if (changes && ma->distance_to_source){
    if(destination_list.upstream_source(destination->destination_addr, ma->distance_to_source)){
      myDistanceToSource=destination_list.get_largest_distance(destination->destination_addr, ma->distance_to_source);
      }
  } 
  if (changes && 
     ((ma->dissemination_type==FLOODING_) ||
     ((destination->am_i_interested + MA_PERIOD) >= NOW) ||
     (ma->distance_to_source && myDistanceToSource))){
   try_to_add_ma(destination->destination_addr, destination->last_seq, ma->dissemination_type,
                          myDistanceToSource, false);
   }
}

bool
IDMIDR::pm_state_changed(DestinationItem* previous_state, DestinationItem* current_state){
  if (current_state->next_hop==INVALID_ADDRESS) return false;
  if (previous_state->core_id!=current_state->core_id) return true;
  if (previous_state->feasible_distance!=current_state->feasible_distance) return true;
  if (previous_state->last_seq!=current_state->last_seq) return true;
  if (previous_state->distance_to_core!=current_state->distance_to_core) return true;
  if (previous_state->next_hop!=current_state->next_hop) return true;
  if (previous_state->membership_code!=current_state->membership_code) return true;
  return false;
}

void
IDMIDR::pm_handle_an_mr(Packet* p){
  MeshRequest mr;
  mr=*((MeshRequest*)((PacketData*)p->userdata())->data());
  if (mr.dissemination_type==FLOODING_)
    pm_handle_a_normal_mr(p);
  
  else{ //REGION_OF_INTEREST_
    hdr_ip  *ih = HDR_IP(p);
    nsaddr_t destination_addr=ih->daddr();
    DestinationItem* destination=0;
    try_to_add_destination(destination, destination_addr);
    if((destination->am_i_interested + MA_PERIOD) >= NOW){
      pm_handle_a_normal_mr(p);
      }
    else{
      Packet::free(p);
      }
    }
}

void 
IDMIDR::pm_handle_a_normal_mr(Packet* p){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  MeshRequest mr;
  mr=*((MeshRequest*)((PacketData*)p->userdata())->data());
  nsaddr_t prevHopAddr=ch->prev_hop_;
  pm_save_distance(prevHopAddr, 1);
  if( (control_cache.find(ih->saddr(), mr.sequence)) || ih->ttl()<=0 || ih->saddr()==id){
    Packet::free(p);
    return;
    }
  control_cache.add(ih->saddr(), mr.sequence);
  ih->ttl()--;
  nsaddr_t destination_addr=ih->daddr();
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  nsaddr_t sourceAddr=ih->saddr();
  DestinationItem* source=0;
  try_to_add_destination(source, sourceAddr);
  source->last_request->try_to_add_mr_sent(destination_addr, mr.distance_to_source+1);
  pm_save_distance(sourceAddr, mr.distance_to_source+1);
  unsigned int reverseDistance=destination_list.get_largest_distance(destination_addr, INFI_);
  if(pm_am_i_destination(destination)){
    if(destination->core_id==id){
      destination->last_seq++;
      try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                    reverseDistance, false);
      }
    else{
      pm_valid_core(destination);
      if(destination->core_id==id){
        try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                      reverseDistance, true);
      }
      else{
	pm_compare_states(p, &mr, destination, sourceAddr);
        }
      }
      
    destination->am_i_interested=NOW;
  }
  
  else{//(!pm_am_i_receiver(destination))
    pm_compare_states(p, &mr, destination, sourceAddr);
  }
 Packet::free(p);
}

void 
IDMIDR::pm_transmit_an_ma(DestinationItem* destination, unsigned char dissemination_type, unsigned int distance_to_source){
  MeshAnnouncement ma;
  Packet* p=Packet::alloc(sizeof(ma));
  hdr_cmn *ch=HDR_CMN(p);
  hdr_ip *ih=HDR_IP(p);
  hdr_idmidr *ph=HDR_IDMIDR(p);

  ma.core_id=destination->core_id; if(ma.core_id==INVALID_ADDRESS) return;
  if (ma.core_id==id){
    ma.next_hop=id;
    ma.mm=RECEIVER_MEMBER_;
    destination->last_ma_received=NOW;
    }
  else{
    ma.next_hop=destination->next_hop;
    if (ma.next_hop==INVALID_ADDRESS){
      Packet::free(p);
      return;
      }
    ma.mm=destination->membership_code;
    }
  ch->uid()=0;
  ma.sequence=destination->last_seq;
  ma.distance_to_core=destination->distance_to_core;
  ma.dissemination_type=dissemination_type;
  ch->ptype()=PT_IDMIDR;
  ch->direction()=hdr_cmn::DOWN;
  ch->size()=IP_HDR_LEN+24; //ma size
  ch->error()=0;
  ch->prev_hop_=id;
  ch->next_hop()=IP_BROADCAST;
  ch->addr_type()=NS_AF_INET;
  ih->saddr()=id;
  ih->ttl()=2;
  ma.distance_to_source=NO_UPSTREAM_SOURCE;
  if (distance_to_source){
    ma.distance_to_source=distance_to_source;
    }

  ih->daddr()=IP_BROADCAST;
  ma.destination_addr=destination->destination_addr;
  ih->sport()=RT_PORT;
  ih->dport()=RT_PORT;
  ph->type=MA_;

  *((MeshAnnouncement*)((PacketData*)p->userdata())->data()) = ma;
  Scheduler::instance().schedule(target_, p, BROADCAST_JITTER *random.uniform(1.0));
}

void 
IDMIDR::pm_valid_core(DestinationItem* destination){
  pm_become_core(destination);
}

void
IDMIDR::pm_become_core(DestinationItem* destination){
  destination->core_id=id;
  destination->distance_to_core=0;
  destination->feasible_distance=0;
  destination->next_hop=id;
  destination->last_seq++;
  delete destination->neighborhood_list;
  destination->neighborhood_list = new NeighborhoodList();
  schedule_timer(new NextMa(destination->destination_addr), MA_PERIOD);
}

void
IDMIDR::pm_compare_states(Packet* p, MeshRequest* mr, DestinationItem* destination, nsaddr_t sourceAddr){
  hdr_ip  *ih = HDR_IP(p);
  pm_update_next_hop(destination, false);
  pm_update_membership(destination);
  nsaddr_t next_hop=destination->next_hop;
  if((next_hop!=INVALID_ADDRESS) && (mr->dissemination_type==FLOODING_)){
  unsigned int reverseDistance=destination_list.get_largest_distance(destination->destination_addr, INFI_);
  try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                reverseDistance, false);
  }
  else{ 
    if (ih->ttl()<=0){
      return;
    }
    if ((mr->dissemination_type==FLOODING_) ||
       ((mr->dissemination_type==REGION_OF_INTEREST_) && ((destination->am_i_interested + MA_PERIOD) >= NOW))){
      transmit_an_mr(destination, sourceAddr, mr->dissemination_type, (mr->distance_to_source)+1, ih->ttl(), mr->sequence);
      }
  }
}

bool
IDMIDR::pm_am_i_destination(DestinationItem* destination){
  if (destination->receiver)
    return true;
  return false;
}

void
IDMIDR::pm_save_distance(nsaddr_t sourceAddr, unsigned int distance){
  DestinationItem* source=0;
  try_to_add_destination(source, sourceAddr);
  source->rt_req_last_ttl=distance;
  source->lastIndirectDistance=NOW;
}

void 
IDMIDR::pm_handle_neighbor_request(Packet* p){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  NeighborRequest nr;
  nr=*((NeighborRequest*)((PacketData*)p->userdata())->data());
  nsaddr_t destination_addr=ih->daddr();
  nsaddr_t next_hopAddr=ch->prev_hop_;
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  nsaddr_t prevHopAddr=ch->prev_hop_;
  pm_save_distance(prevHopAddr, 1);

  if (destination->receiver){
    if((nr.anchor==id) &&
      ((destination->am_i_interested+(MA_PERIOD))>=NOW) && ((destination->last_ma_generated+MIN_NR_PERIOD)<NOW)){
      try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                    NO_UPSTREAM_SOURCE, false);
      }
    else 
    Packet::free(p);
    return;
    }

  nsaddr_t lastNextHop=destination->next_hop;
  unsigned char lastDistance=destination->distance_to_core;
  unsigned char lastMembershipCode=destination->membership_code;
  nsaddr_t lastCore=destination->core_id;
  
  if (destination->neighborhood_list->same_anchor(prevHopAddr, nr.anchor)){
    destination->neighborhood_list->remove(next_hopAddr);
    }
  destination_list.mi_update(id, destination);

  if (lastNextHop==INVALID_ADDRESS){
    Packet::free(p);
    return;
    }

  if (destination->next_hop==INVALID_ADDRESS){
    pu_send_neighbor_request(destination, lastCore);
    }

  else if((lastCore!=destination->core_id || lastNextHop!=destination->next_hop ||
         lastDistance!=destination->distance_to_core || lastMembershipCode!=destination->membership_code) ||
           (((destination->last_seq > nr.last_seq)|| 
           ((destination->last_seq == nr.last_seq) && destination->distance_to_core<=nr.last_feasible_dist)) &&
                               (destination->core_id==nr.anchor) && 
                               ((destination->last_ma_generated+MIN_NR_PERIOD)<NOW))){
    try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                           NO_UPSTREAM_SOURCE, false);
    }
Packet::free(p);
}

void
IDMIDR::pm_neighbor_fail(nsaddr_t destination_addr, nsaddr_t next_hopAddr){
  DestinationItem* destination=0;
  try_to_add_destination(destination, destination_addr);
  if (next_hopAddr!=destination->next_hop)
    return;
  nsaddr_t lastNextHop=next_hopAddr;
  nsaddr_t lastCore=destination->core_id;
  
  destination_list.delete_neighbor(next_hopAddr);
  destination_list.mi_update(id, destination);

  if (destination->next_hop==INVALID_ADDRESS){
    if((destination->last_nr_generated+MIN_NR_PERIOD)<NOW)
      pu_send_neighbor_request(destination, lastCore);
    }
  else if (lastNextHop!=destination->next_hop){
    try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
               NO_UPSTREAM_SOURCE, false);
    }
}

void
IDMIDR::pm_update_membership(DestinationItem* destination){ //Next version
}

void
IDMIDR::pm_update_next_hop(DestinationItem* destination, bool pathNode){
  if (destination->core_id==id) return;
  if (destination->receiver) return;
  bool changes=false;
  DestinationItem previous_state=*destination;
  destination_list.mi_update(id, destination);
  changes=pm_state_changed(&previous_state, destination);
  if (destination->next_hop!=INVALID_ADDRESS && changes){
    try_to_add_ma(destination->destination_addr, destination->last_seq, REGION_OF_INTEREST_,
                  NO_UPSTREAM_SOURCE, false);
    } 
  else if (previous_state.next_hop!=INVALID_ADDRESS && destination->next_hop==INVALID_ADDRESS &&
           pathNode){
    pu_send_neighbor_request(destination, previous_state.core_id); 
    }
}

void
IDMIDR::pu_send_neighbor_request(DestinationItem* destination, nsaddr_t anchor){
  NeighborRequest nr;
  Packet* p=Packet::alloc(sizeof(nr));
  hdr_cmn *ch=HDR_CMN(p);
  hdr_ip *ih=HDR_IP(p);
  hdr_idmidr *ph=HDR_IDMIDR(p);
  double new_req_time;
  ph->type=NEIGHBOR_REQUEST_;
  ch->uid()=0;
  nr.anchor=anchor;
  GenericCacheItem* alTemp=destination->anchor_list->find_source(anchor);
  nr.last_seq=alTemp->sequence;
  nr.last_feasible_dist=alTemp->distance;
  destination->last_nr_generated=NOW;
  ch->ptype()=PT_IDMIDR;
  ch->direction()=hdr_cmn::DOWN;
  ch->size()=IP_HDR_LEN+12; //neighbor request size
  ch->error()=0;
  ch->prev_hop_=id;
  ch->next_hop()=IP_BROADCAST;
  ch->addr_type()=NS_AF_INET;
  ih->saddr()=id;
  ih->ttl()=2;
  ih->daddr()=destination->destination_addr;
  ih->sport()=RT_PORT;
  ih->dport()=RT_PORT;
  new_req_time=MAX((NOW+MIN_NR_PERIOD),(destination->rt_req_timeout));
  destination->rt_req_timeout=new_req_time;
  *((NeighborRequest*)((PacketData*)p->userdata())->data()) = nr;
  Scheduler::instance().schedule(target_, p, (BROADCAST_JITTER *random.uniform(1.0)));
}

void
IDMIDR::pm_explicit_ack_fail(Packet* p){
  hdr_cmn *ch = HDR_CMN(p);
  hdr_ip  *ih = HDR_IP(p);
  pm_neighbor_fail(ih->daddr(), ch->next_hop());
}

//Overhearing

void
IDMIDR::tap(const Packet* p){
  hdr_cmn *ch=HDR_CMN(p);
  hdr_ip *ih=HDR_IP(p);
  //We must overhear all data packets. For our simulations we only used CBR, so ch->ptype()==PT_CBR is enough.
  if (ch->ptype()==PT_CBR && ch->next_hop()!=id){
    nsaddr_t destination_addr=ih->daddr();
    DestinationItem* destination=0;
    try_to_add_destination(destination, destination_addr);
    nsaddr_t prevHopAddr=ch->prev_hop_;
    pm_save_distance(prevHopAddr, 1);
    if ((ih->ttl() < 1) || message_cache.find(ih->saddr(), ch->uid())){
      return;
      }
    message_cache.add(ih->saddr(), ch->uid());
    destination->am_i_interested=NOW;
    nsaddr_t sourceAddr=ih->saddr();
    pm_save_distance(sourceAddr, (NETWORK_DIAMETER-ih->ttl()));
  }
}

//maBuckets

void
IDMIDR::pm_handle_a_bucket(Packet* p){
  hdr_cmn *ch=HDR_CMN(p);
  int bSize=ch->uid();
  nsaddr_t prevHopAddr=ch->prev_hop_;
  MeshAnnouncement bucket[bSize];
  memcpy((void*)&bucket,(void*)((PacketData*)p->userdata())->data(), sizeof(MeshAnnouncement) * bSize);
  for (int i=0; i<bSize; i++){
    if (bucket[i].destination_addr!=INVALID_ADDRESS){
      pm_handle_a_normal_ma(prevHopAddr, (bucket+i));
      }
    }
  Packet::free(p);
}

void
IDMIDR::reset_bucket(){
  next_bucket_time=0.0;
  for (int i=0; i<bucket_size; i++){
      ma[i].destination_addr=INVALID_ADDRESS;
      ma[i].sequence=0;
    }
  bucket_size=0;
}

void
IDMIDR::set_bucket_tx_time(){
  if(next_bucket_time<NOW){
    next_bucket_time=NOW+COLLECTION_PERIOD;
    schedule_timer(new NextBucket(), COLLECTION_PERIOD);
    }
}

void
IDMIDR::try_to_add_ma(nsaddr_t destination_addr, unsigned int sequence,
                     unsigned char dissemination_type, unsigned int distance_to_source,
                     bool force){
  bool added=false;
  for (int i=0; i<MAX_ACTIVE_DESTS; i++){
    if (ma[i].destination_addr==INVALID_ADDRESS){
      add_ma(destination_addr, sequence, dissemination_type, distance_to_source, (ma+i));
      added=true;
      bucket_size++;
      DestinationItem* destination=0;
      try_to_add_destination(destination, destination_addr);
      destination->last_ma_generated=NOW;
      break;
      }
    else if (ma[i].destination_addr==destination_addr && force){
      add_ma(destination_addr, sequence, dissemination_type, distance_to_source, (ma+i));
      break;
      }
    else if (ma[i].destination_addr==destination_addr && ma[i].sequence<sequence){
      add_ma(destination_addr, sequence, dissemination_type, distance_to_source, (ma+i));
      break;
      }
    else if (ma[i].destination_addr==destination_addr && 
             ma[i].sequence==sequence && 
             ma[i].dissemination_type!=FLOODING_ &&
             dissemination_type!=FLOODING_ &&
             ma[i].distance_to_source<distance_to_source){
      ma[i].distance_to_source=distance_to_source;
      break;
      }
    else if (ma[i].destination_addr==destination_addr)
      break; 
    }
  if (added)
    set_bucket_tx_time();
}

void
IDMIDR::add_ma(nsaddr_t destination_addr, unsigned int sequence,
                unsigned char dissemination_type, unsigned int distance_to_source,
                MaToSend* spot){
  spot->destination_addr=destination_addr;
  spot->sequence=sequence;
  spot->dissemination_type=dissemination_type;
  spot->distance_to_source=distance_to_source;
}

void 
IDMIDR::transmit_bucket(){
  if (bucket_size==0){
    return;
    }
  if (bucket_size==1){
    DestinationItem* temp=destination_list.pufind(ma[0].destination_addr);
    if (temp==0) return;
    pm_transmit_an_ma(temp, ma[0].dissemination_type, ma[0].distance_to_source);
    }
  else{
    MeshAnnouncement bucket[bucket_size];
    Packet *p = Packet::alloc(sizeof(bucket));
    hdr_cmn *ch=HDR_CMN(p);
    hdr_ip *ih=HDR_IP(p);
    hdr_idmidr *ph=HDR_IDMIDR(p);
    ih->saddr()=id;
    ih->ttl()=2;
    ih->daddr()=IP_BROADCAST;
    ih->sport()=RT_PORT;
    ih->dport()=RT_PORT;
    ch->uid()=bucket_size; //size of bucket
    ch->ptype()=PT_IDMIDR;
    ch->direction()=hdr_cmn::DOWN;
    ch->size()=IP_HDR_LEN+(22*bucket_size)+4;
    ch->error()=0;
    ch->prev_hop_=id;
    ch->next_hop()=IP_BROADCAST;
    ch->addr_type()=NS_AF_INET;
    ph->type=MA_BUCKET_;
    for (int i=0; i<bucket_size; i++){
      bucket[i].destination_addr=INVALID_ADDRESS;
      DestinationItem* temp=destination_list.pufind(ma[i].destination_addr);
      if (temp==0 ||
          temp->core_id==INVALID_ADDRESS ||
          (temp->core_id!=id && temp->next_hop==INVALID_ADDRESS))
        continue;
      bucket[i].core_id=temp->core_id; 
      if (temp->core_id==id){
        bucket[i].next_hop=id;
        bucket[i].mm=RECEIVER_MEMBER_;
        temp->last_ma_received=NOW;
        }
      else{
        bucket[i].next_hop=temp->next_hop;
        bucket[i].mm=temp->membership_code;
        }
      bucket[i].sequence=temp->last_seq;
      bucket[i].distance_to_core=temp->distance_to_core;
      bucket[i].dissemination_type=ma[i].dissemination_type;
      bucket[i].distance_to_source=ma[i].distance_to_source;
      bucket[i].destination_addr=temp->destination_addr;
      }
    memcpy((void*)(((PacketData*)p->userdata())->data()),(void*)&bucket, sizeof(bucket));
    Scheduler::instance().schedule(target_, p, BROADCAST_JITTER * (random.uniform(1.0)));
    }
  reset_bucket();
}
