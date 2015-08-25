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

#ifndef GENERIC_CACHE_H
#define GENERIC_CACHE_H

#include "../config.h"

struct GenericCacheItem {
  nsaddr_t source;
  u_int32_t sequence;
  unsigned int distance;
  double time;
  GenericCacheItem* next;
};

struct Update{
  unsigned char type;
  double time;
};

class GenericCache {
protected:
  GenericCacheItem* front;
  GenericCacheItem* rear;
public:
  GenericCache();
  ~GenericCache();
  bool find(nsaddr_t, u_int32_t);
  GenericCacheItem* find_source(nsaddr_t); 
  void add(nsaddr_t, u_int32_t, unsigned int distance=0);
  void update_source(nsaddr_t, u_int32_t, unsigned int, Update&);
  void remove_front();
};

#endif /*GENERIC_CACHE_H*/
