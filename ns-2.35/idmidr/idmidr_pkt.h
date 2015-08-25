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

#ifndef IDMIDR_PKT_H_
#define IDMIDR_PKT_H_

#define HDR_IDMIDR(p) hdr_idmidr::access(p)
#define IDMIDR_HDR_LEN 4

/*
 * IDMIDR Header Description
 */

struct hdr_idmidr{
  static int offset_;  // Offset of the IDMIDR packet header
  unsigned char type;
  inline static int& offset() {return offset_;}
  inline static hdr_idmidr* access(const Packet* p) {
  return (hdr_idmidr*)p->access(offset_);
  }
};

struct MeshRequest{
  unsigned int sequence;
  unsigned char dissemination_type;
  unsigned char distance_to_source;
};

struct NeighborRequest{
  unsigned int last_seq;
  nsaddr_t anchor;
  unsigned char last_feasible_dist;
};

struct MeshAnnouncement{
  nsaddr_t destination_addr;
  nsaddr_t core_id;
  nsaddr_t next_hop;
  unsigned int sequence;
  unsigned char distance_to_core;
  unsigned char distance_to_source;
  unsigned char dissemination_type;
  unsigned char mm;
};

#endif /*IDMIDR_PKT_H_*/
