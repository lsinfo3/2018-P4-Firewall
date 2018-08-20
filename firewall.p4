//===============================
// Defines
//===============================

#define ETHERTYPE_IPV4 0x0800
#define IP_PROT_TCP 0x06
#define IP_PROT_UDP 17

//===============================
// Headers
//===============================

header_type eth_hdr {
    fields {
        dst : 48;
        src : 48;
        etype : 16;
    }
}
 
header_type ipv4_hdr {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_hdr {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_hdr {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}


header eth_hdr eth;
header ipv4_hdr ipv4; 
header tcp_hdr tcp;
header udp_hdr udp;

//===============================
// Parser Chain
//===============================

parser start {
    return eth_parse;
}

parser eth_parse {
    extract(eth);
    return select(latest.etype) {
        ETHERTYPE_IPV4 : ipv4_parse;
        default: ingress;
    }
}
 
parser ipv4_parse {
    extract(ipv4);
    return select(ipv4.protocol) {
        IP_PROT_TCP : tcp_parse;
        IP_PROT_UDP : udp_parse;
        default : ingress;
    }
} 
 
parser tcp_parse {
    extract(tcp);
    return ingress;
}
  
parser udp_parse {
    extract(udp);
    return ingress;
}
 

//===============================
// Actions
//===============================

action drop_act() {
    drop();
}
 
action fwd_act(prt) {
    modify_field(standard_metadata.egress_spec, prt);
}


//===============================
// Table Definition
//===============================
 
table fo_tbl {
    reads {
        ipv4.srcAddr : ternary;        
        tcp.srcPort : ternary;
        ipv4.dstAddr : ternary;
        tcp.dstPort : ternary;       
        eth.etype : exact;
    }
    actions {
        drop_act;
        fwd_act;
    }
}
 
control ingress {
    apply(fo_tbl);
}
