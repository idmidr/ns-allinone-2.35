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

#include <timer-handler.h>

#include "neighborhood_list.h"

#define INVALID_ADDRESS         -987654
#define INFI_                   99
#define MA_PERIOD               3.000
#define NOW                     Scheduler::instance().clock()
#define MESH_MEMBER_            212
#define RECEIVER_MEMBER_        214

NeighborhoodList::NeighborhoodList(){
  front =0;
}

NeighborhoodList::~NeighborhoodList(){
  NeighborItem* temp;
  while (front!=0) {
    temp=front->next;
    delete front;
    front=temp;
    }
}

void 
NeighborhoodList::mi_add(nsaddr_t core_id, nsaddr_t next_hop, unsigned int sequence,
                         unsigned int distance_to_core, nsaddr_t received_from, double time_added){
  NeighborItem* temp=new NeighborItem();
  temp->core_id=core_id;
  temp->next_hop=next_hop;
  temp->sequence=sequence;
  temp->distance_to_core=distance_to_core;
  temp->received_from=received_from;
  temp->time_added=time_added;
  remove(temp->received_from);
  temp->next = front;
  front=temp;
}

void
NeighborhoodList::remove(nsaddr_t neighbor){
  if (front != 0){
    NeighborItem* temp = front;
    if (front->received_from ==neighbor) {
      front = front->next;
      delete temp;
      return;
      }
    while (temp->next!=0) {
      if (temp->next->received_from == neighbor) {
        NeighborItem* to_be_freed = temp->next;
	temp->next = temp->next->next;
	delete to_be_freed;
	return;
	}
      temp = temp->next;
      }
    }
}


unsigned int
NeighborhoodList::get_distance(){
  if (front!=0  && (front->time_added+(2*MA_PERIOD))>=NOW)
    return (front->distance_to_core)+1;
  return INFI_;
}

bool 
NeighborhoodList::forward_data(unsigned char membership_code, unsigned char distance_to_core, nsaddr_t id,
                               nsaddr_t received_from, u_int32_t currentSeq, double currentSeqTime){
  if (membership_code==MESH_MEMBER_ || membership_code==RECEIVER_MEMBER_) //Next version
    return true;
  for (NeighborItem* temp = front; temp != 0; temp = temp->next){
    if (temp->received_from==received_from && 
        temp->sequence==currentSeq &&
        ((currentSeqTime+(2*MA_PERIOD))>=NOW) &&
        temp->distance_to_core>distance_to_core && 
        temp->next_hop<=id){
      return true;
      }
    }
  return false;
}

bool
NeighborhoodList::same_anchor(nsaddr_t neighbor, nsaddr_t anchor) {
  for (NeighborItem* temp = front; temp != 0; temp = temp->next){
    if ((temp->received_from==neighbor) && 
       (temp->core_id==anchor))
      return true;
      }	
  return false;
}
