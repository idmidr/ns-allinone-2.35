Mac/802_11 set SlotTime_          0.000020      ;# 20us
Mac/802_11 set SIFS_              0.000010      ;# 10us
Mac/802_11 set PreambleLength_    144           ;# 144 bit
Mac/802_11 set PLCPHeaderLength_  48            ;# 48 bits
Mac/802_11 set PLCPDataRate_      1.0e6         ;# 1Mbps
Mac/802_11 set dataRate_          2.0e6         ;# 11Mbps
Mac/802_11 set basicRate_         1.0e6         ;# 1Mbps

set val(chan)         Channel/WirelessChannel  ;# channel type
set val(prop)         Propagation/TwoRayGround ;# radio-propagation model
set val(ant)          Antenna/OmniAntenna      ;# antenna type
set val(ll)           LL                       ;# link layer type
set val(ifq)          Queue/DropTail/PriQueue  ;# interface queue type
set val(ifqlen)       256                      ;# max packet in ifq
set val(netif)        Phy/WirelessPhy          ;# network interface type
set val(mac)          Mac/802_11               ;# MAC type
set val(rp)           IDMIDR	               ;# ad-hoc routing protocol 
set nodes             100                      ;# number of mobilenodes
set X		      1400		       ;# simulation area
set Y		      1400		       ;# simulation area
set opt(stop)	      120		       ;# simulation time
set val(traf)         "traffic"                ;# traffic file 
set val(esc)          "movement"               ;# movement file
set val(nullo)        "null_agent"             ;# null agent
set val(seed)         567634                   ;# RNG seed
set val(tra)          output.tr                ;# output trace file name
set val(visual)       visual.nam               ;# nam file name

set ns_	[new Simulator]
global defaultRNG
$defaultRNG seed $val(seed)

set tracefd [open $val(tra) w]
$ns_ trace-all $tracefd

set tracenam [open visualconren.nam w]
$ns_ namtrace-all-wireless $tracenam $X $Y

set topo [new Topography]
$topo load_flatgrid $X $Y

set god_ [create-god $nodes]

# Configure nodes
        $ns_ node-config -adhocRouting $val(rp) \
                         -llType $val(ll) \
                         -macType $val(mac) \
                         -ifqType $val(ifq) \
                         -ifqLen $val(ifqlen) \
                         -antType $val(ant) \
                         -propType $val(prop) \
                         -phyType $val(netif) \
                         -topoInstance $topo \
                         -channelType $val(chan) \
                         -agentTrace ON \
                         -routerTrace OFF \
                         -macTrace ON \
                         -movementTrace OFF

for {set i 0} {$i < $nodes} {incr i} {
   set node_($i) [$ns_ node]
   $node_($i) random-motion 0;
}

source $val(esc)
source $val(traf)
source $val(nullo)

#idmmidr join-group
Node instproc join-group { group } { 
    $self instvar ragent_
    set group [expr $group]
    $ragent_ join-group $group
}

for {set i 0} {$i < $nodes} {incr i} {
   $ns_ at $opt(stop) "$node_($i) reset";
}

$ns_ at $opt(stop) "$ns_ halt"
puts "Starting Simulation ..."
$ns_ run
puts "NS EXITING..."
 
