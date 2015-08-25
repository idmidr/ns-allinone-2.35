/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved. 

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

*/

//#include <ip.h>

#include <aodv/aodv.h>
#include <aodv/aodv_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define CURRENT_TIME    Scheduler::instance().clock()

//#define DEBUG
//#define ERROR

#ifdef DEBUG
static int route_request = 0;
#endif

/*
  TCL Hooks
*/


int hdr_aodv::offset_;
static class AODVHeaderClass : public PacketHeaderClass {
public:
        AODVHeaderClass() : PacketHeaderClass("PacketHeader/AODV",
                                              sizeof(hdr_all_aodv)) {
	  bind_offset(&hdr_aodv::offset_);
	} 
} class_rtProtoAODV_hdr;

static class AODVclass : public TclClass {
public:
        AODVclass() : TclClass("Agent/AODV") {}
        TclObject* create(int argc, const char*const* argv) {
          assert(argc == 5);
          //return (new AODV((nsaddr_t) atoi(argv[4])));
	  return (new AODV((nsaddr_t) Address::instance().str2addr(argv[4])));
        }
} class_rtProtoAODV;


int
AODV::command(int argc, const char*const* argv) {
  if(argc == 2) {
  Tcl& tcl = Tcl::instance();
    
    if(strncasecmp(argv[1], "id", 2) == 0) {
      tcl.resultf("%d", index);
      return TCL_OK;
    }
    
    if(strncasecmp(argv[1], "start", 2) == 0) {
      btimer.handle((Event*) 0);

#ifndef AODV_LINK_LAYER_DETECTION
      htimer.handle((Event*) 0);
      ntimer.handle((Event*) 0);
#endif // LINK LAYER DETECTION

      rtimer.handle((Event*) 0);
      return TCL_OK;
     }               
  }
  else if(argc == 3) {
    if(strcmp(argv[1], "index") == 0) {
      index = atoi(argv[2]);
      return TCL_OK;
    }

    else if(strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
      logtarget = (Trace*) TclObject::lookup(argv[2]);
      if(logtarget == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if(strcmp(argv[1], "drop-target") == 0) {
    int stat = rqueue.command(argc,argv);
      if (stat != TCL_OK) return stat;
      return Agent::command(argc, argv);
    }
    else if(strcmp(argv[1], "if-queue") == 0) {
    ifqueue = (PriQueue*) TclObject::lookup(argv[2]);
      
      if(ifqueue == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if (strcmp(argv[1], "port-dmux") == 0) {
    	dmux_ = (PortClassifier *)TclObject::lookup(argv[2]);
	if (dmux_ == 0) {
		fprintf (stderr, "%s: %s lookup of %s failed\n", __FILE__,
		argv[1], argv[2]);
		return TCL_ERROR;
	}
	return TCL_OK;
    }
    if (strcmp(argv[1], "join-group") == 0) {
       start_receiving(atoi(argv[2]));
       return TCL_OK;
    }
  }
  return Agent::command(argc, argv);

}

NewAnchorEvent::NewAnchorEvent(nsaddr_t dst, nsaddr_t anydst){
  uni_dst=dst;
  any_dst=anydst;

}

nsaddr_t
NewAnchorEvent::get_uni_dst(){
  return uni_dst;

}

nsaddr_t
NewAnchorEvent::get_any_dst(){
  return any_dst;

}

/* 
   Constructor
*/

AODV::AODV(nsaddr_t id) : Agent(PT_AODV),
			  btimer(this), htimer(this), ntimer(this), 
			  rtimer(this), lrtimer(this), natimer(this), rqueue() {
  index = id;
  seqno = 2;
  bid = 1;

  LIST_INIT(&nbhead); //neighbor cache
  LIST_INIT(&bihead); //broadcast cache

  logtarget = 0;
  ifqueue = 0;

  for(int i=0; i < MAX_ANYCAST_GROUPS; i++) {
    anycast_address[i] = UNKOWN_ANYCAST;
    }
  current_groups=0;

}

/*
  Timers
*/

void
BroadcastTimer::handle(Event*) {
  agent->id_purge();
  Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);

}

void
HelloTimer::handle(Event*) {
   agent->sendHello();
   double interval = MinHelloInterval + 
                 ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
   assert(interval >= 0);
   Scheduler::instance().schedule(this, &intr, interval);

}

void
NeighborTimer::handle(Event*) {
  agent->nb_purge();
  Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);

}

void
RouteCacheTimer::handle(Event*) {
  agent->rt_purge();
#define FREQUENCY 0.5 // sec
  Scheduler::instance().schedule(this, &intr, FREQUENCY);

}

void
LocalRepairTimer::handle(Event* p)  {  // SRD: 5/4/99
aodv_rt_entry *rt;
struct hdr_ip *ih = HDR_IP( (Packet *)p);
   /* you get here after the timeout in a local repair attempt */
   /*	fprintf(stderr, "%s\n", __FUNCTION__); */

    rt = agent->rtable.rt_lookup(ih->daddr());
	
    if (rt && rt->rt_flags != RTF_UP) {
    // route is yet to be repaired
    // I will be conservative and bring down the route
    // and send route errors upstream.
    /* The following assert fails, not sure why */
    /* assert (rt->rt_flags == RTF_IN_REPAIR); */
		
      //rt->rt_seqno++;
      agent->rt_down(rt);
      // send RERR
#ifdef DEBUG
      fprintf(stderr,"Dst - %d, failed local repair\n", rt->rt_dst);
#endif      
    }
    Packet::free((Packet *)p);

}


void 
NewAnchorTimer::handle(Event* a){
NewAnchorEvent* event=(NewAnchorEvent*)a;
 agent->change_anchor(event->get_uni_dst(), event->get_any_dst());

}

/*
   Broadcast ID Management  Functions
*/


void
AODV::id_insert(nsaddr_t id, u_int32_t bid) {
BroadcastID *b = new BroadcastID(id, bid);

 assert(b);
 b->expire = CURRENT_TIME + BCAST_ID_SAVE;
 LIST_INSERT_HEAD(&bihead, b, link);

}


/* SRD */
bool
AODV::id_lookup(nsaddr_t id, u_int32_t bid) {
BroadcastID *b = bihead.lh_first;
 
 // Search the list for a match of source and bid
 for( ; b; b = b->link.le_next) {
   if ((b->src == id) && (b->id == bid))
     return true;     
 }
 return false;

}


void
AODV::id_purge() {
BroadcastID *b = bihead.lh_first;
BroadcastID *bn;
double now = CURRENT_TIME;

 for(; b; b = bn) {
   bn = b->link.le_next;
   if(b->expire <= now) {
     LIST_REMOVE(b,link);
     delete b;
     }
  }

}


/*
  Helper Functions
*/


double
AODV::PerHopTime(aodv_rt_entry *rt) {
int num_non_zero = 0, i;
double total_latency = 0.0;

 if (!rt)
   return ((double) NODE_TRAVERSAL_TIME );
	
 for (i=0; i < MAX_HISTORY; i++) {
   if (rt->rt_disc_latency[i] > 0.0) {
      num_non_zero++;
      total_latency += rt->rt_disc_latency[i];
   }
 }
 if (num_non_zero > 0)
   return(total_latency / (double) num_non_zero);
 else
   return((double) NODE_TRAVERSAL_TIME);

}


/*
  Link Failure Management Functions
*/

static void
aodv_rt_failed_callback(Packet *p, void *arg) {
  ((AODV*) arg)->rt_ll_failed(p);

}


/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
AODV::rt_ll_failed(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv_rt_entry *rt;
nsaddr_t broken_nbr = ch->next_hop_;

#ifndef AODV_LINK_LAYER_DETECTION
 drop(p, DROP_RTR_MAC_CALLBACK);
#else 

 /*
  * Non-data packets and Broadcast Packets can be dropped.
  */
  if(! DATA_PACKET(ch->ptype()) ||
     (u_int32_t) ih->daddr() == IP_BROADCAST) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_broke(p);
	if((rt = rtable.rt_lookup(ih->daddr())) == 0) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_del(ch->next_hop_);

#ifdef AODV_LOCAL_REPAIR
  /* if the broken link is closer to the dest than source, 
     attempt a local repair. Otherwise, bring down the route. */

  if (ch->num_forwards() > rt->rt_hops) {
    //rt->rt_flags=temp_flags;
    local_rt_repair(rt, p); // local repair
    // retrieve all the packets in the ifq using this link,
    // queue the packets for which local repair is done, 
    return;
  }
  else	
#endif // LOCAL REPAIR	
  {
    //rt->rt_flags=temp_flags;
    drop(p, DROP_RTR_MAC_CALLBACK);
    // Do the same thing for other packets in the interface queue using the
    // broken link -Mahesh
while((p = ifqueue->filter(broken_nbr))) {
     drop(p, DROP_RTR_MAC_CALLBACK);
    }	
    nb_delete(broken_nbr);
  }
#endif // LINK LAYER DETECTION

}


void
AODV::handle_link_failure(nsaddr_t id) {
aodv_rt_entry *rt, *rtn;
Packet *rerr = Packet::alloc();
struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);

 re->DestCount = 0;
 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next; 
   if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id) ) {
     assert (rt->rt_flags == RTF_UP);
     assert((rt->rt_seqno%2) == 0);
     rt->rt_seqno++;
     re->unreachable_dst[re->DestCount] = rt->rt_dst;
     re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
		     index, re->unreachable_dst[re->DestCount],
		     re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
     re->DestCount += 1;
     rt_down(rt);
   }
   // remove the lost neighbor from all the precursor lists
   rt->pc_delete(id);
 }   

 if (re->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr, false);
 }
 else {
   Packet::free(rerr);
 }

}


void
AODV::local_rt_repair(aodv_rt_entry *rt, Packet *p) {
struct hdr_ip *ih = HDR_IP(p);

#ifdef DEBUG
  fprintf(stderr,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst); 
#endif  
  // Buffer the packet 
  rqueue.enque(p);

  // mark the route as under repair 
  rt->rt_flags = RTF_IN_REPAIR;

  aodv_rt_entry *rta;       //anycast
  rta = rtable.rt_lookup(ih->anycast_dst());
  if(rta == 0){
    rta = rtable.rt_add(ih->anycast_dst());
    }

  sendRequest(rt->rt_dst, ih->anycast_dst());

  // set up a timer interrupt
  Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);

}


void
AODV::rt_update(aodv_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
	       	nsaddr_t nexthop, double expire_time) {

  rt->rt_seqno = seqnum;
  rt->rt_hops = metric;
  rt->rt_flags = RTF_UP;
  rt->rt_nexthop = nexthop;
  rt->rt_expire = expire_time;

}


void
AODV::rt_down(aodv_rt_entry *rt) {
  /*
   *  Make sure that you don't "down" a route more than once.
   */

  if(rt->rt_flags == RTF_DOWN) {
    return;
  }
   
  // assert (rt->rt_seqno%2); // is the seqno odd?
  rt->rt_last_hop_count = rt->rt_hops;
  rt->rt_hops = INFINITY2;
  rt->rt_flags = RTF_DOWN;
  nsaddr_t last_next_hop=rt->rt_nexthop;
  rt->rt_nexthop = 0;
  rt->rt_expire = 0;

  for(aodv_rt_entry* rt_temp = rtable.head(); rt_temp; rt_temp=rt_temp->rt_link.le_next){
    if(rt_temp->rt_prefered_anchor==rt->rt_dst && rt->rt_dst!=rt_temp->rt_dst){
      rt_temp->rt_last_hop_count = rt->rt_last_hop_count;
      }
    }

  int i=0;
  while (rt->anycast_address[i]!=UNKOWN_ANYCAST){
    rt->anycast_address[i++]=UNKOWN_ANYCAST;
    }
 
  for(aodv_rt_entry* rt_temp = rtable.head(); rt_temp; rt_temp=rt_temp->rt_link.le_next){
    if(rt_temp->rt_prefered_anchor==rt->rt_dst && rt->rt_dst!=rt_temp->rt_dst){
      if (rt_temp->last_data_generated+ANY_SOURCE<CURRENT_TIME){
        rt_temp->rt_prefered_anchor=NO_ANCHOR;
        }
      aodv_rt_entry* rt_tempa;
      if (rt_temp->last_data_generated+ANY_SOURCE<CURRENT_TIME){
        rt_tempa=try_to_find_anchor(rt_temp->rt_dst, last_next_hop);
        }
      else{
        rt_tempa=0;
        }
      if (rt_tempa){
        rt_temp->rt_prefered_anchor=rt_tempa->rt_dst;
        rt_temp->rt_req_cnt = rt_tempa->rt_req_cnt;
        rt_temp->rt_req_timeout = rt_tempa->rt_req_timeout;
        rt_temp->rt_req_last_ttl = rt_tempa->rt_req_last_ttl;
        rt_temp->rt_last_hop_count = rt_tempa->rt_last_hop_count;

        if (rt_temp->last_data_generated+ANY_SOURCE>=CURRENT_TIME){
          update_last_history(rt_tempa, rt_temp);
          rqueue.updateAnchor(rt_temp->rt_dst, rt_tempa->rt_dst, index);
          double delay = 0.0;
          Packet *buf_pkt;
          while((buf_pkt = rqueue.deque(rt_tempa->rt_dst))) {
            if(rt_tempa->rt_hops != INFINITY2) {
              assert (rt_tempa->rt_flags == RTF_UP);
              forward(rt_tempa, buf_pkt, delay);
              delay += ARP_DELAY;
              }
            }
          }
        } 
      } 
    } 
     
} /* rt_down function */


/*
  Route Handling Functions
*/


void
AODV::rt_resolve(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv_rt_entry *rt=0;

 /*
  *  Set the transmit failure callback.  That
  *  won't change.
  */
 ch->xmit_failure_ = aodv_rt_failed_callback;
 ch->xmit_failure_data_ = (void*) this;
 
 if(ih->saddr() == index){

   if ((ih->daddr()>=ANYCAST_ADDRESS) && (am_i_anycast_dest(ih->daddr()))){
     dmux_->recv(p,0);
     return; 
     }

   ih->anycast_dst()=ih->daddr();  //anycast_options
   nsaddr_t anycast_id = ih->daddr();
   aodv_rt_entry *rta;
   rta = rtable.rt_lookup(anycast_id); 
   if(rta == 0){
     rta = rtable.rt_add(anycast_id); 
     }
   rta->last_data_generated=CURRENT_TIME;
   nsaddr_t unicast_id = rta->rt_prefered_anchor;
   if(unicast_id!=NO_ANCHOR){
     rt = rtable.rt_lookup(unicast_id);
     if(rt == 0){
       rt = rtable.rt_add(unicast_id);
       }
     }

    if(rt && rt->rt_flags == RTF_UP){
      assert(rt->rt_hops != INFINITY2);
      ih->daddr()=unicast_id;
      forward(rt, p, NO_DELAY);
      }
   else{
     if (rt) 
 	 ih->daddr()=rt->rt_dst;
     rqueue.enque(p);
     if (rt == 0)
       sendRequest(rta->rt_dst, rta->rt_dst);
     else{
       sendRequest(rt->rt_dst, rta->rt_dst);
       }
     }
   } //if(ih->saddr() == index)

 else{

   rt = rtable.rt_lookup(ih->daddr());
   if(rt == 0){
     rt = rtable.rt_add(ih->daddr());
     }

   if(rt->rt_flags == RTF_UP){
     assert(rt->rt_hops != INFINITY2);
     forward(rt, p, NO_DELAY);
     }

   else if (rt->rt_flags == RTF_IN_REPAIR) {
     rqueue.enque(p);
     }

   else {
     Packet *rerr = Packet::alloc();
     struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);
     /* 
     * For now, drop the packet and send error upstream.
     * Now the route errors are broadcast to upstream
     * neighbors - Mahesh 09/11/99
     */	
 
     assert (rt->rt_flags == RTF_DOWN);
     re->DestCount = 0; 
     re->unreachable_dst[re->DestCount] = rt->rt_dst;
     re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
     re->DestCount += 1;
#ifdef DEBUG
     fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
     sendError(rerr, false);

     drop(p, DROP_RTR_NO_ROUTE);
     }
   } //else (ih->saddr() == index)  

}


void
AODV::rt_purge() {
aodv_rt_entry *rt, *rtn;
double now = CURRENT_TIME;
double delay = 0.0;
Packet *p;

 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next;
   if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
   // if a valid route has expired, purge all packets from 
   // send buffer and invalidate the route.                    
	assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
       fprintf(stderr, "%s: calling drop()\n",
                       __FUNCTION__);
#endif // DEBUG
       drop(p, DROP_RTR_NO_ROUTE);
     }
     rt->rt_seqno++;
     assert (rt->rt_seqno%2);
     rt_down(rt);
   }
   else if (rt->rt_flags == RTF_UP) {
   // If the route is not expired,
   // and there are packets in the sendbuffer waiting,
   // forward them. This should not be needed, but this extra 
   // check does no harm.
     assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
       forward (rt, p, delay);
       delay += ARP_DELAY;
     }
   } 
   else if (rqueue.find(rt->rt_dst)){
   // If the route is down and 
   // if there is a packet for this destination waiting in
   // the sendbuffer, then send out route request. sendRequest
   // will check whether it is time to really send out request
   // or not.
   // This may not be crucial to do it here, as each generated 
   // packet will do a sendRequest anyway.
     d_dst temp;
     rqueue.find_anycast_dst(temp, rt->rt_dst);
     for (int i=0; i<temp.n; i++){
       sendRequest(temp.unicast_dst[i], temp.anycast_dst[i]);
       }
      }
   }

}


/*
  Packet Reception Routines
*/


void
AODV::recv(Packet *p, Handler*) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(initialized());
 //assert(p->incoming == 0);
 // XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

 if(ch->ptype() == PT_AODV) {
   ih->ttl_ -= 1;
   recvAODV(p);
   return;
 }

 /*
  *  Must be a packet I'm originating...
  */
if((ih->saddr() == index) && (ch->num_forwards() == 0)) {
 /*
  * Add the IP Header.  
  * TCP adds the IP header too, so to avoid setting it twice, we check if
  * this packet is not a TCP or ACK segment.
  */
  if (ch->ptype() != PT_TCP && ch->ptype() != PT_ACK) {
    ch->size() += IP_HDR_LEN;
  }
   // Added by Parag Dadhania && John Novatnack to handle broadcasting
  if ( (u_int32_t)ih->daddr() != IP_BROADCAST) {
    ih->ttl_ = NETWORK_DIAMETER;
  }
}
 /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
else if(ih->saddr() == index) {
   drop(p, DROP_RTR_ROUTE_LOOP);
   return;
 }
 /*
  *  Packet I'm forwarding...
  */
 else {
 /*
  *  Check the TTL.  If it is zero, then discard.
  */
   if(--ih->ttl_ == 0) {
     drop(p, DROP_RTR_TTL);
     return;
   }
 }
// Added by Parag Dadhania && John Novatnack to handle broadcasting
 if ( (u_int32_t)ih->daddr() != IP_BROADCAST){
  rt_resolve(p);

  }
 else
   forward((aodv_rt_entry*) 0, p, NO_DELAY); 

}


void
AODV::recvAODV(Packet *p) {
 struct hdr_aodv *ah = HDR_AODV(p);

 assert(HDR_IP (p)->sport() == RT_PORT);
 assert(HDR_IP (p)->dport() == RT_PORT);

 /*
  * Incoming Packets.
  */
 switch(ah->ah_type) {

 case AODVTYPE_RREQ:
   recvRequest(p);
   break;

 case AODVTYPE_RREP:
   recvReply(p);
   break;

 case AODVTYPE_RERR:
   recvError(p);
   break;

 case AODVTYPE_HELLO:
   recvHello(p);
   break;
        
 default:
   fprintf(stderr, "Invalid AODV type (%x)\n", ah->ah_type);
   exit(1);
 }

}


void
AODV::recvRequest(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
aodv_rt_entry *rt, *rt_temp=0;

  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this request.
   */

  if(rq->rq_src == index) {
#ifdef DEBUG
    fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  } 

 if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
   //fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG
 
   Packet::free(p);
   return;
 }

 /*
  * Cache the broadcast ID
  */
 id_insert(rq->rq_src, rq->rq_bcast_id);

 /* 
  * We are either going to forward the REQUEST or generate a
  * REPLY. Before we do anything, we make sure that the REVERSE
  * route is in the route table.
  */
 aodv_rt_entry *rt0; // rt0 is the reverse route 
   
 rt0 = rtable.rt_lookup(rq->rq_src);
 if(rt0 == 0) { /* if not in the route table */
 // create an entry for the reverse route.
   rt0 = rtable.rt_add(rq->rq_src);
   }
 rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));
 rt0->rt_prefered_anchor=rt0->rt_dst;
 if ( (rq->rq_src_seqno > rt0->rt_seqno ) ||
    ((rq->rq_src_seqno == rt0->rt_seqno) && 
    (rq->rq_hop_count < rt0->rt_hops)) ) {
   // If we have a fresher seq no. or lesser #hops for the 
   // same seq no., update the rt entry. Else don't bother.
   rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
   max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)) );
   if (rt0->rt_req_timeout > 0.0) {
     // Reset the soft state and 
     // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
     // This is because route is used in the forward direction,
     // but only sources get benefited by this change
       rt0->rt_req_cnt = 0;
       rt0->rt_req_timeout = 0.0; 
       rt0->rt_req_last_ttl = rq->rq_hop_count;
       rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
     }

     /* Find out whether any buffered packet can benefit from the 
      * reverse route.
      * May need some change in the following code - Mahesh 09/11/99
      */
     assert (rt0->rt_flags == RTF_UP);
     Packet *buffered_pkt;
     while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
       if (rt0 && (rt0->rt_flags == RTF_UP)) {
	assert(rt0->rt_hops != INFINITY2);
         forward(rt0, buffered_pkt, NO_DELAY);
       }
     }
   } 
   // End for putting reverse route in rt table


 /*
  * We have taken care of the reverse route stuff.
  * Now see whether we can send a route reply. 
  */

 rt = rtable.rt_lookup(rq->rq_dst); 

 // First check if I am the destination ..
 nsaddr_t anycast_dst = rq->rq_anycast_dst;  //anycast
 if(rq->rq_dst == index || am_i_anycast_dest(anycast_dst)) { 

#ifdef DEBUG
   fprintf(stderr, "%d - %s: destination sending reply\n",
                   index, __FUNCTION__);
#endif // DEBUG
               
   // Just to be safe, I use the max. Somebody may have
   // incremented the dst seqno.
   seqno = max(seqno, rq->rq_dst_seqno)+1;
   if (seqno%2) seqno++;
   sendReply(rq->rq_src,           // IP Destination
             1,                    // Hop Count
             index,                // Dest IP Address
             seqno,                // Dest Sequence Num
             MY_ROUTE_TIMEOUT,     // Lifetime
             rq->rq_timestamp,    // timestamp
 	     anycast_dst);		//anycast
   Packet::free(p);
 }

 // I am not the destination, but I may have a fresh enough route.

 else if (rt && (rt->rt_hops != INFINITY2) && 
	  	(rt->rt_seqno >= rq->rq_dst_seqno) && (rq->rq_dst<ANYCAST_ADDRESS)) {

   assert(rq->rq_dst == rt->rt_dst);
   sendReply(rq->rq_src,
             rt->rt_hops + 1,
             rq->rq_dst,
             rt->rt_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
             rq->rq_timestamp,
             anycast_dst);
   rt->pc_insert(rt0->rt_nexthop); 
   rt0->pc_insert(rt->rt_nexthop); 

#ifdef RREQ_GRAT_RREP  

   sendReply(rq->rq_dst,
             rq->rq_hop_count,
             rq->rq_src,
             rq->rq_src_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp,
             anycast_dst); 
#endif
   
// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT
   
// DONE: Included gratuitous replies to be sent as per IETF aodv draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv-packet.h --- Anant Utgikar, 09/16/02.
    
    Packet::free(p);
 }


 else if (rq->rq_dst==rq->rq_anycast_dst && (rq->rq_dst>=ANYCAST_ADDRESS) &&(rt_temp=try_to_find_anchor(rq->rq_anycast_dst, UNKOWN_ANYCAST))){
   assert(rq->rq_dst == rt_temp->rt_dst);
   sendReply(rq->rq_src, 
             rt_temp->rt_hops + 1,
             rt_temp->rt_dst,
             rt_temp->rt_seqno,
             (u_int32_t) (rt_temp->rt_expire - CURRENT_TIME),
             rq->rq_timestamp,
             anycast_dst);
   rt_temp->pc_insert(rt0->rt_nexthop); 
   rt0->pc_insert(rt_temp->rt_nexthop);
   Packet::free(p);

 }

 /*
  * Can't reply. So forward the  Route Request
  */
 else {
   ih->saddr() = index;
   ih->daddr() = IP_BROADCAST;
   rq->rq_hop_count += 1;
   // Maximum sequence number seen en route
   if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
   forward((aodv_rt_entry*) 0, p, DELAY);
 }

}


void
AODV::recvReply(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
aodv_rt_entry *rt, *rta;
char suppress_reply = 0;
double delay = 0.0;
	
#ifdef DEBUG
 fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG

 /*
  *  Got a reply. So reset the "soft state" maintained for 
  *  route requests in the request table. We don't really have
  *  have a separate request table. It is just a part of the
  *  routing table itself. 
  */
 // Note that rp_dst is the dest of the data packets, not the
 // the dest of the reply, which is the src of the data packets.

 rt = rtable.rt_lookup(rp->rp_dst); 
        
 /*
  *  If I don't have a rt entry to this host... adding
  */
 if(rt == 0) {
   rt = rtable.rt_add(rp->rp_dst);
 }

 if(rt->rt_prefered_anchor==NO_ANCHOR){
   rt->rt_prefered_anchor=rp->rp_dst;
   }

 rta  = rtable.rt_lookup(rp->rp_anycast_dst);
 if(rta == 0) {
   rta = rtable.rt_add(rp->rp_anycast_dst);
 }

 rt->try_to_add_membership(rp->rp_anycast_dst);

 /*
  * Add a forward route table entry... here I am following 
  * Perkins-Royer AODV paper almost literally - SRD 5/99
  */

 if ( (rt->rt_seqno < rp->rp_dst_seqno) ||   // newer route 
      ((rt->rt_seqno == rp->rp_dst_seqno) &&  
       (rt->rt_hops > rp->rp_hop_count)) ) { // shorter or better route

  // Update the rt entry 
  rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
		rp->rp_src, CURRENT_TIME + rp->rp_lifetime);

 if (rta->rt_prefered_anchor==NO_ANCHOR ||
    ((rta->last_data_generated+ANY_SOURCE<CURRENT_TIME) && rta->rt_prefered_anchor!=rp->rp_dst &&  better_anchor(rta->rt_prefered_anchor, rp->rp_dst)))
   {
   rta->rt_prefered_anchor=rp->rp_dst; //anycast
   if (rta->last_data_generated+ANY_SOURCE>=CURRENT_TIME || ih->daddr() == index){
     update_last_history(rt, rta);
     }    

   if (rta->last_data_generated+ANY_SOURCE>=CURRENT_TIME ){
     rqueue.updateAnchor(rp->rp_anycast_dst, rp->rp_dst, index);
     }
   rta->rt_last_hop_count=rt->rt_last_hop_count;
   }

 if (rta->rt_prefered_anchor!=rp->rp_dst){
   rta=rt;
   }

  // reset the soft state
 rt->rt_req_cnt = 0;
 rt->rt_req_timeout = 0.0;
 rta->rt_req_cnt = 0;
 rta->rt_req_timeout = 0.0;
 
 rt->rt_req_last_ttl = rp->rp_hop_count;
 rta->rt_req_last_ttl = rp->rp_hop_count;

 if (ih->daddr() == index) { // If I am the original source
  // Update the route discovery latency statistics
  // rp->rp_timestamp is the time of request origination
   rt->rt_disc_latency[(unsigned char)rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
                                         / (double) rp->rp_hop_count;

   rta->rt_disc_latency[(unsigned char)rta->hist_indx]=rt->rt_disc_latency[(unsigned char)rt->hist_indx];
   // increment indx for next time
   rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
   rta->hist_indx=rt->hist_indx;
   }

  /*
   * Send all packets queued in the sendbuffer destined for
   * this destination. 
   * XXX - observe the "second" use of p.
   */
  Packet *buf_pkt;
  while((buf_pkt = rqueue.deque(rt->rt_dst))) {
    if(rt->rt_hops != INFINITY2) {
       assert (rt->rt_flags == RTF_UP);
    // Delay them a little to help ARP. Otherwise ARP 
    // may drop packets. -SRD 5/23/99
      forward(rt, buf_pkt, delay);
      delay += ARP_DELAY;
      }
    }
 }
 else {
  suppress_reply = 1;
 }

 /*
  * If reply is for me, discard it.
  */

 if(ih->daddr() == index || suppress_reply) {
   Packet::free(p);
   }
 /*
  * Otherwise, forward the Route Reply.
  */
 else {
   // Find the rt entry
   aodv_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
   // If the rt is up, forward
   if(rt0 && (rt0->rt_hops != INFINITY2)) {
     assert (rt0->rt_flags == RTF_UP);
     rp->rp_hop_count += 1;
     rp->rp_src = index;
     forward(rt0, p, NO_DELAY);
     // Insert the nexthop towards the RREQ source to 
     // the precursor list of the RREQ destination
     rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
     
     }
   else {
   // I don't know how to forward .. drop the reply. 
#ifdef DEBUG
     fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
     drop(p, DROP_RTR_NO_ROUTE);
     }
   }

}


void
AODV::recvError(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
aodv_rt_entry *rt;
u_int8_t i;
Packet *rerr = Packet::alloc();
struct hdr_aodv_error *nre = HDR_AODV_ERROR(rerr);

 nre->DestCount = 0;

 for (i=0; i<re->DestCount; i++) {
 // For each unreachable destination
   rt = rtable.rt_lookup(re->unreachable_dst[i]);
   if ( rt && (rt->rt_hops != INFINITY2) &&
	(rt->rt_nexthop == ih->saddr()) &&
     	(rt->rt_seqno <= re->unreachable_dst_seqno[i]) ) {
	assert(rt->rt_flags == RTF_UP);
	assert((rt->rt_seqno%2) == 0); // is the seqno even?
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__,CURRENT_TIME,
		     index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
		     re->unreachable_dst[i],re->unreachable_dst_seqno[i],
	             ih->saddr());
#endif // DEBUG
     	rt->rt_seqno = re->unreachable_dst_seqno[i];
     	rt_down(rt);
   // Not sure whether this is the right thing to do
   Packet *pkt;
	while((pkt = ifqueue->filter(ih->saddr()))) {
        	drop(pkt, DROP_RTR_MAC_CALLBACK);
     	}

     // if precursor list non-empty add to RERR and delete the precursor list
     	if (!rt->pc_empty()) {
     		nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
     		nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
     		nre->DestCount += 1;
		rt->pc_delete();
     	}
   }
 } 

 if (nre->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr);
 }
 else {
   Packet::free(rerr);
 }

 Packet::free(p);

}


/*
   Packet Transmission Routines
*/


void
AODV::forward(aodv_rt_entry *rt, Packet *p, double delay) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 if(ih->ttl_ == 0) {

#ifdef DEBUG
  fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG
 
  drop(p, DROP_RTR_TTL);
  return;
 }

 if ( (( ch->ptype() != PT_AODV && ch->direction() == hdr_cmn::UP ) &&
	((u_int32_t)ih->daddr() == IP_BROADCAST))
		|| (ih->daddr() == here_.addr_)) {
	dmux_->recv(p,0);
	return;
 }

 if (rt) {
   assert(rt->rt_flags == RTF_UP);
   rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
 
   aodv_rt_entry *rta = rtable.rt_lookup(ih->anycast_dst());
   if(rta == 0){
      rta = rtable.rt_add(ih->anycast_dst());
      }
   if(ch->ptype() != PT_AODV){
     if (ih->daddr()==rta->rt_prefered_anchor){
	rta->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
        }
    
     if (ih->anycast_dst()!=ih->daddr() && ih->saddr()==index)
       ch->size() += sizeof(nsaddr_t); //anycast options
     }

   ch->next_hop_ = rt->rt_nexthop;
   ch->addr_type() = NS_AF_INET;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }
 else { // if it is a broadcast packet
   // assert(ch->ptype() == PT_AODV); // maybe a diff pkt type like gaf

   assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
   ch->addr_type() = NS_AF_NONE;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }

if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
 // If it is a broadcast packet
   assert(rt == 0);
   if (ch->ptype() == PT_AODV) {
     /*
      *  Jitter the sending of AODV broadcast packets by 10ms
      */
     Scheduler::instance().schedule(target_, p,
      				   0.01 * Random::uniform());
   } else {
     Scheduler::instance().schedule(target_, p, 0.);  // No jitter
   }
 }
 else { // Not a broadcast packet
   if(delay > 0.0) {
     Scheduler::instance().schedule(target_, p, delay);
   }
   else {
   // Not a broadcast packet, no delay, send immediately
     Scheduler::instance().schedule(target_, p, 0.);
   }
 }

}


void
AODV::sendRequest(nsaddr_t dst, nsaddr_t anycast_dst) {
// Allocate a RREQ packet 
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
aodv_rt_entry *rt = rtable.rt_lookup(dst);
 assert(rt);

aodv_rt_entry *rt_temp = rtable.rt_lookup(dst);
rt_temp = rtable.rt_lookup(anycast_dst);
  if(rt_temp == 0){
      rt_temp = rtable.rt_add(anycast_dst);
      }
assert(rt_temp);


  if (rt_temp->rt_prefered_anchor!=rt->rt_dst){
    rt_temp=rt;
    }

 /*
  *  Rate limit sending of Route Requests. We are very conservative
  *  about sending out route requests. 
  */

 if (rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   Packet::free((Packet *)p);
   return;
 }


 if (rt_temp->rt_req_timeout > CURRENT_TIME) {
   Packet::free((Packet *)p);
   return;
 }

 // rt_req_cnt is the no. of times we did network-wide broadcast
 // RREQ_RETRIES is the maximum number we will allow before 
 // going to a long timeout.

 if (rt_temp->rt_req_cnt > RREQ_RETRIES) {
   rt_temp->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;  
   rt_temp->rt_req_cnt = 0;
   rt->rt_req_timeout=rt_temp->rt_req_timeout;
   rt->rt_req_cnt=rt_temp->rt_req_cnt; 

 Packet *buf_pkt;
     while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
       drop(buf_pkt, DROP_RTR_NO_ROUTE);
     }
   Packet::free((Packet *)p);
   return;
 }


#ifdef DEBUG
   fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d\n",
                    ++route_request, index, rt->rt_dst);
#endif // DEBUG

 // Determine the TTL to be used this time. 
 // Dynamic TTL evaluation - SRD

 rt->rt_req_last_ttl = max(rt->rt_req_last_ttl,rt->rt_last_hop_count);
 rt_temp->rt_req_last_ttl=rt->rt_req_last_ttl;  
 if (0 == rt->rt_req_last_ttl) {
 // first time query broadcast
   ih->ttl_ = TTL_START;
 }
 else {
 // Expanding ring search.
   if (rt->rt_req_last_ttl < TTL_THRESHOLD)
     ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
   else {
   // network-wide broadcast
     ih->ttl_ = NETWORK_DIAMETER;
     rt_temp->rt_req_cnt += 1;
     rt->rt_req_cnt=rt_temp->rt_req_cnt; 
   }
 }

 // remember the TTL used  for the next time
 rt->rt_req_last_ttl = ih->ttl_;
 rt_temp->rt_req_last_ttl=rt->rt_req_last_ttl; 

 // PerHopTime is the roundtrip time per hop for route requests.
 // The factor 2.0 is just to be safe .. SRD 5/22/99
 // Also note that we are making timeouts to be larger if we have 
 // done network wide broadcast before. 

 rt_temp->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt);  
 rt->rt_req_timeout=rt_temp->rt_req_timeout;
 if (rt_temp->rt_req_cnt > 0){
   rt_temp->rt_req_timeout *= rt_temp->rt_req_cnt;  
   rt->rt_req_timeout=rt_temp->rt_req_timeout;
							 }
 rt_temp->rt_req_timeout += CURRENT_TIME;
 rt->rt_req_timeout=rt_temp->rt_req_timeout; 

 // Don't let the timeout to be too large, however .. SRD 6/8/99
 if (rt_temp->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT){
   rt_temp->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;   
   rt->rt_req_timeout=rt_temp->rt_req_timeout;
   }
 rt->rt_expire = 0;

#ifdef DEBUG
 fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
	         ++route_request, 
		 index, rt->rt_dst, 
		 rt_temp->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG
	

 // Fill out the RREQ packet 
 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rq->size();

 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;

 // Fill up some more fields. 
 rq->rq_type = AODVTYPE_RREQ;
 rq->rq_hop_count = 1;
 rq->rq_bcast_id = bid++;
 rq->rq_dst = dst;
 rq->rq_anycast_dst = anycast_dst; //anycast
 ih->anycast_dst()=anycast_dst;
 
 if(rq->rq_anycast_dst>=ANYCAST_ADDRESS){
   ch->size() += sizeof(nsaddr_t);
   }

 rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
 rq->rq_src = index;
 seqno += 2;
 assert ((seqno%2) == 0);
 rq->rq_src_seqno = seqno;
 rq->rq_timestamp = CURRENT_TIME;

 if (dst!=anycast_dst &&  (rt_temp->last_data_generated+ANY_SOURCE>=CURRENT_TIME)){
   if (rt_temp->rt_req_cnt>=ANY_TRIES){
     Scheduler::instance().schedule(&natimer, new NewAnchorEvent(dst, anycast_dst), 0.6);
     }
  }

 Scheduler::instance().schedule(target_, p, 0.);

}


void
AODV::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
                u_int32_t rpseq, u_int32_t lifetime, double timestamp, nsaddr_t anycast_dst) {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
aodv_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
fprintf(stderr, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
 assert(rt);

 rp->rp_type = AODVTYPE_RREP;
 //rp->rp_flags = 0x00;
 rp->rp_hop_count = hop_count;
 rp->rp_dst = rpdst;
 rp->rp_dst_seqno = rpseq;
 rp->rp_src = index;
 rp->rp_lifetime = lifetime;
 rp->rp_timestamp = timestamp;
 rp->rp_anycast_dst = anycast_dst;	//anycast
 ih->anycast_dst()=anycast_dst; 
 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rp->size();
 if(rpdst!=anycast_dst)
  ch->size() += sizeof(nsaddr_t);
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_INET;
 ch->next_hop_ = rt->rt_nexthop;
 ch->prev_hop_ = index;          // AODV hack
 ch->direction() = hdr_cmn::DOWN;

 ih->saddr() = index;
 ih->daddr() = ipdst;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = NETWORK_DIAMETER;

 Scheduler::instance().schedule(target_, p, 0.);

}


void
AODV::sendError(Packet *p, bool jitter) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
    
#ifdef ERROR
fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 re->re_type = AODVTYPE_RERR;
 //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
 // DestCount and list of unreachable destinations are already filled

 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + re->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->next_hop_ = 0;
 ch->prev_hop_ = index;          // AODV hack
 ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 // Do we need any jitter? Yes
 if (jitter)
 	Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());
 else
 	Scheduler::instance().schedule(target_, p, 0.0);

}


/*
   Neighbor Management Functions
*/


void
AODV::sendHello() {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rh = HDR_AODV_REPLY(p);

#ifdef DEBUG
fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 rh->rp_type = AODVTYPE_HELLO;
 //rh->rp_flags = 0x00;
 rh->rp_hop_count = 1;
 rh->rp_dst = index;
 rh->rp_dst_seqno = seqno;
 rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rh->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 Scheduler::instance().schedule(target_, p, 0.0);

}


void
AODV::recvHello(Packet *p) {
//struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
AODV_Neighbor *nb;

 nb = nb_lookup(rp->rp_dst);
 if(nb == 0) {
   nb_insert(rp->rp_dst);
 }
 else {
   nb->nb_expire = CURRENT_TIME +
                   (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 }

 Packet::free(p);

}


void
AODV::nb_insert(nsaddr_t id) {
AODV_Neighbor *nb = new AODV_Neighbor(id);

 assert(nb);
 nb->nb_expire = CURRENT_TIME +
                (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 LIST_INSERT_HEAD(&nbhead, nb, nb_link);
 seqno += 2;             // set of neighbors changed
 assert ((seqno%2) == 0);

}


AODV_Neighbor*
AODV::nb_lookup(nsaddr_t id) {
AODV_Neighbor *nb = nbhead.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) break;
 }
 return nb;

}


/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */

void
AODV::nb_delete(nsaddr_t id) {
AODV_Neighbor *nb = nbhead.lh_first;

 log_link_del(id);
 seqno += 2;     // Set of neighbors changed
 assert ((seqno%2) == 0);

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) {
     LIST_REMOVE(nb,nb_link);
     delete nb;
     break;
   }
 }

 handle_link_failure(id);

}


/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
 

void
AODV::nb_purge() {
AODV_Neighbor *nb = nbhead.lh_first;
AODV_Neighbor *nbn;
 double now = CURRENT_TIME;
   for(; nb; nb = nbn) {
     nbn = nb->nb_link.le_next;
     if(nb->nb_expire <= now) {
       nb_delete(nb->nb_addr);
       }
     }
  
}


//ANYCAST
void
AODV::start_receiving(nsaddr_t destinationAddr){
 add_anycast_membership(destinationAddr);
 //What should I do if I have queued packets for destinationAddr?

}


void 
AODV::add_anycast_membership(nsaddr_t destinationAddr){
 anycast_address[current_groups++]=destinationAddr;
}


bool
AODV::am_i_anycast_dest(nsaddr_t destinationAddr){
 for(int i=0; i<current_groups; i++){
   if (anycast_address[i]==destinationAddr)
     return true;  
   }
 return false;

}


aodv_rt_entry*
AODV::best_anchor(aodv_rt_entry* a, aodv_rt_entry* b, nsaddr_t anycast_dst, nsaddr_t next_hop){
 if ((!a)&&(!b)){
   return 0;
   }
 else if((!a) && b){
   bool b_in=b->try_to_find_anchor(anycast_dst, next_hop);
   if (b_in)
     return b;
   else
     return 0;
   }
 else if(a && (!b)){
   bool a_in=a->try_to_find_anchor(anycast_dst, next_hop);
   if (a_in)
     return a;
   else
     return 0;
   }
 else if (a && b){
   bool b_in=b->try_to_find_anchor(anycast_dst, next_hop);
   bool a_in=a->try_to_find_anchor(anycast_dst, next_hop);
   if ((!a_in) && (!b_in)){
     return 0;
     }
   else if (a_in && (!b_in)){
     return a;
     }
   else if ((!a_in) && b_in){
     return b;
     }
   else if (a->rt_hops < b->rt_hops){
     return a;
     }
   else{
     return b;
     }
   }
 else return 0;

}


aodv_rt_entry*
AODV::try_to_find_anchor(nsaddr_t anycast_dst, nsaddr_t next_hop){
aodv_rt_entry *rt_tempa, *rt_tempb;
 rt_tempa=rtable.head();
 if(rt_tempa->rt_link.le_next==0){
   if (rt_tempa->try_to_find_anchor(anycast_dst, next_hop) ){
     return rt_tempa;
     }
   else{
     return 0;
     }
   }
 for(rt_tempb=rt_tempa->rt_link.le_next; rt_tempb; rt_tempb=rt_tempb->rt_link.le_next){
    rt_tempa=best_anchor(rt_tempa, rt_tempb, anycast_dst, next_hop);
    } 
 return rt_tempa;

}


bool
AODV::better_anchor(nsaddr_t a, nsaddr_t b){
 if(a==NO_ANCHOR){
   return true;
   }

 aodv_rt_entry *rta, *rtb; 
 rta = rtable.rt_lookup(a);
 rtb = rtable.rt_lookup(b);

 if (rta->rt_flags != RTF_UP){
   return true;
   }
 else if (rta->rt_hops > rtb->rt_hops){
   return true;
   }
 return false;

}


void
AODV::update_last_history(aodv_rt_entry *rta, aodv_rt_entry *rtb) {
 for (int i=0; i < MAX_HISTORY; i++) {
   rtb->rt_disc_latency[i]=rta->rt_disc_latency[i];  
   }
 rtb->hist_indx=rta->hist_indx; 

}


void 
AODV::change_anchor(nsaddr_t uni, nsaddr_t any){
aodv_rt_entry* rt_temp = rtable.rt_lookup(any);
 if(rt_temp == 0){
     rt_temp = rtable.rt_add(any);
     }
 assert(rt_temp);
 aodv_rt_entry* rt_tempa=rtable.rt_lookup(uni);
 if (rt_tempa==0) return;

 if (rt_tempa->rt_flags == RTF_UP) {
   return;
 }
 rt_tempa=try_to_find_anchor(any, UNKOWN_ANYCAST);

 if (rt_tempa){
   rt_temp->rt_prefered_anchor=rt_tempa->rt_dst;
   rt_temp->rt_req_cnt = rt_tempa->rt_req_cnt;
   rt_temp->rt_req_timeout = rt_tempa->rt_req_timeout;
   rt_temp->rt_req_last_ttl = rt_tempa->rt_req_last_ttl;
   rt_temp->rt_last_hop_count = rt_tempa->rt_last_hop_count;

   update_last_history(rt_tempa, rt_temp);
   rqueue.updateAnchor(rt_temp->rt_dst, rt_tempa->rt_dst, index);
   double delay = 0.0;
   Packet *buf_pkt;
   while((buf_pkt = rqueue.deque(rt_tempa->rt_dst))) {
     if(rt_tempa->rt_hops != INFINITY2) {
       assert (rt_tempa->rt_flags == RTF_UP);
       forward(rt_tempa, buf_pkt, delay);
       delay += ARP_DELAY;
       }
     }
   } 

}
