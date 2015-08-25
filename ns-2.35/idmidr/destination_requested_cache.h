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

#ifndef DEST_REQUESTED_H
#define DEST_REQUESTED_H

#include "../config.h"

//Max concurrent flows per source
#define SMAX_FLOWS		5 

struct DestRequestedItem{
  nsaddr_t destination_addr;
  unsigned int distance;
  double time;
};
 
class DestRequested{
public:  
  DestRequestedItem destination[SMAX_FLOWS];
  DestRequested();
  void add_mr_sent(DestRequestedItem*, nsaddr_t, unsigned int);
  void update_mr_sent(DestRequestedItem*, unsigned int);
  void try_to_add_mr_sent(nsaddr_t, unsigned int);
  bool find_source(nsaddr_t, unsigned int);
  unsigned int get_distance(nsaddr_t);
};

#endif /*DEST_REQUESTED_H*/
