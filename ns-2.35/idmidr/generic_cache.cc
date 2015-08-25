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

#include "generic_cache.h"

#define SEQ_UPDATE	3
#define DIST_UPDATE	2
#define NO_UPDATE	1
#define DISCARD_UPDATE	0
#define NOW             Scheduler::instance().clock()

GenericCache::GenericCache() {
  front = NULL;
  rear  = NULL;
}

GenericCache::~GenericCache() {
  GenericCacheItem* temp;
  while (front != NULL) {
    temp = front->next;
    delete front;
    front = temp;
    }
}

bool
GenericCache::find(nsaddr_t source, u_int32_t sequence) {
  for (GenericCacheItem* temp = front; temp != NULL; temp = temp->next)
    if ((temp->source == source) && (temp->sequence == sequence))
      return true;
    return false;
}

GenericCacheItem*
GenericCache::find_source(nsaddr_t source) {
  for (GenericCacheItem* temp = front; temp != NULL; temp = temp->next)
    if (temp->source == source)
      return temp;
    return 0;
}

void
GenericCache::add(nsaddr_t source, u_int32_t sequence, unsigned int distance) {
  if (front == NULL) {
    rear  = new GenericCacheItem();
    front = rear;
    }
  else {
    rear->next = new GenericCacheItem();
    rear = rear->next;
    }
  rear->source   = source;
  rear->sequence = sequence;
  rear->distance = distance;
  rear->time     = NOW;
  rear->next     = NULL;
}

void
GenericCache::update_source(nsaddr_t source, u_int32_t sequence, unsigned int distance,
                            Update& tempUpdate){
  GenericCacheItem *tempCacheItem=find_source(source);
  if (!tempCacheItem){
    add(source, sequence, distance);
    tempUpdate.type=SEQ_UPDATE;
    tempUpdate.time=NOW;
    }
  else if (tempCacheItem->sequence < sequence){
    tempCacheItem->sequence=sequence;
    tempCacheItem->distance=distance;
    tempCacheItem->time=NOW;
    tempUpdate.type=SEQ_UPDATE;
    tempUpdate.time=NOW;
    }
  else if ((tempCacheItem->sequence == sequence) &&
          (tempCacheItem->distance > distance)){
    tempCacheItem->distance=distance;
    tempUpdate.type=DIST_UPDATE;
    tempUpdate.time=tempCacheItem->time;
    }
  else if ((tempCacheItem->sequence == sequence) &&
          (tempCacheItem->distance <= distance)){
    tempUpdate.type=NO_UPDATE;
    tempUpdate.time=tempCacheItem->time;
    }
  else if (tempCacheItem->sequence > sequence){
    tempUpdate.type=DISCARD_UPDATE;
    }
}

void
GenericCache::remove_front() {
  if (front != NULL) {
    GenericCacheItem* temp = front;
    front = front->next;
    delete temp;
    if (front == NULL)
      rear = NULL;
    }
}
