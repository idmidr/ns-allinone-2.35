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

#ifndef NEIGHBORHOOD_LIST_H
#define NEIGHBORHOOD_LIST_H

#include "../config.h"

struct NeighborItem {
  nsaddr_t core_id;
  nsaddr_t next_hop;
  u_int32_t sequence;
  unsigned char membership_code;
  unsigned int distance_to_core;
  float time_added;
  nsaddr_t received_from;
  NeighborItem* next;
};

class DestinationList;

class NeighborhoodList {
  friend class DestinationList;
protected:
  NeighborItem* front;
public:
  NeighborhoodList();
  ~NeighborhoodList();
  void mi_add(nsaddr_t, nsaddr_t, unsigned int, unsigned int, nsaddr_t, double);
  bool same_anchor(nsaddr_t, nsaddr_t);
  void remove(nsaddr_t);
  unsigned int get_distance();
  unsigned char get_membership_code(bool, unsigned char, nsaddr_t, nsaddr_t, u_int32_t, double);
  bool forward_data(unsigned char, unsigned char, nsaddr_t, nsaddr_t,
                    u_int32_t, double);
  bool nearer_neighbors(unsigned char);
};

#endif /*NEIGHBORHOOD_LIST_H*/
