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

#include "destination_requested_cache.h"

#define INVALID_ADDRESS         -987654
#define INFI_                   99
#define MA_PERIOD               3.000
#define NOW                     Scheduler::instance().clock()
#define INVALID_TIME            -16.0

void
DestRequested::add_mr_sent(DestRequestedItem *mr, nsaddr_t destination_addr,
                           unsigned int distance){
  mr->destination_addr=destination_addr;
  mr->distance=distance;
  mr->time=NOW;
}

void
DestRequested::update_mr_sent(DestRequestedItem *mr, unsigned int distance){
  mr->distance=distance;
  mr->time=NOW;
}

void
DestRequested::try_to_add_mr_sent(nsaddr_t destination_addr, unsigned int distance){
  int i=0;
  bool added=false;
  DestRequestedItem* availableSpot=0;
  for (i=0; i<SMAX_FLOWS; i++){
    if (destination[i].destination_addr==INVALID_ADDRESS){
      add_mr_sent((destination+i), destination_addr, distance);
      added=true;
      break;
      }
    else if (destination[i].destination_addr==destination_addr){
      update_mr_sent(destination+i, distance);
      added=true;
      break;
      }
    else{
      if (((destination[i].time+(0.5*MA_PERIOD))<NOW) && !(availableSpot)){
        availableSpot=(destination+i); 
        }
      }
    }
    if ((!added) && (availableSpot)){
      add_mr_sent((availableSpot), destination_addr, distance);
      }
}

bool
DestRequested::find_source(nsaddr_t destination_addr, unsigned int prevHopDistance){
  for (int i=0; i<SMAX_FLOWS; i++){
    if (destination[i].destination_addr==INVALID_ADDRESS)
      break;
    if (destination[i].destination_addr==destination_addr &&
       ((destination[i].time+(0.5*MA_PERIOD))>=NOW) && 
       (destination[i].distance<prevHopDistance)){
      return true;
      }
    }
  return false;
}
 
unsigned int
DestRequested::get_distance(nsaddr_t destination_addr){
  for (int i=0; i<SMAX_FLOWS; i++){
    if (destination[i].destination_addr==INVALID_ADDRESS)
      break;
    if (destination[i].destination_addr==destination_addr &&
       ((destination[i].time+(0.5*MA_PERIOD))>=NOW)){
      return destination[i].distance;
      }
    }
  return 0;
}

DestRequested::DestRequested(){
  for (int i=0; i<SMAX_FLOWS; i++){
    destination[i].destination_addr=INVALID_ADDRESS;
    destination[i].distance=INFI_;
    destination[i].time=INVALID_TIME;
    }
}
