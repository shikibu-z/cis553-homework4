// Name: Junyong Zhao
// PennKey: junyong

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 255

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

header distance_vec_t {
    bit<32>     src;
    bit<16>     length;
    bit<2016>   data;
}

struct headers_t {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    arp_t           arp;
    distance_vec_t  distance_vec;
}

struct local_variables_t {
    bit<1>  forMe;
    bit<32> nhop;
}

struct routing_digest_t {
    bit<32>     src;
    bit<16>     length;
    bit<2016>   data;
    bit<48>     src_mac;
    bit<9>      src_port; 
}

struct arp_digest_t {
    // TODO
    bit<48> sha;
    bit<32> spa;
    bit<48> dst_mac;
    bit<9>  src_port;

}

/*************************************************************************
***********************  P A R S E   P A C K E T *************************
*************************************************************************/

parser cis553Parser(packet_in packet,
                    out headers_t hdr,
                    inout local_variables_t metadata,
                    inout standard_metadata_t standard_metadata) {
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_routing;
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            0x0553: parse_routing;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_routing {
        packet.extract(hdr.distance_vec);
        transition accept;
    }
}

/*************************************************************************
***********************  I N G R E S S  **********************************
*************************************************************************/

control cis553Ingress(inout headers_t hdr,
                      inout local_variables_t metadata,
                      inout standard_metadata_t standard_metadata) {
    action aiForMe() {
        metadata.forMe = 1;
    }

    action aDrop() {
        mark_to_drop(standard_metadata);
    }

    action orouting(bit<48> src_mac, bit<48> dst_mac, bit<9> egress_port) {
        hdr.ethernet.setValid();
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.etherType = 0x0553;
        standard_metadata.egress_spec = egress_port;
    }

    action lpmatch(bit<32> next_hop) {
        metadata.nhop = next_hop;
    }

    action setnhop() {
        metadata.nhop = hdr.ipv4.dstAddr;
    }

    action aiforward(bit<48> src_mac, bit<48> dst_mac, bit<9> egress_port) {
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = dst_mac;
        standard_metadata.egress_spec = egress_port;
    }

    action sendarp(bit<48> src_mac, bit<48> dst_mac, bit<32> src_ip, bit<9> egress_port) {
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = dst_mac;
        hdr.ethernet.etherType = 0x0806;
        hdr.arp.setValid();
        hdr.arp.htype = 1;
        hdr.arp.hlen = 6;
        hdr.arp.ptype = 0x0800;
        hdr.arp.plen = 4;
        hdr.arp.oper = 1;
        hdr.arp.sha = src_mac;
        hdr.arp.spa = src_ip;
        hdr.arp.tpa = metadata.nhop;
        hdr.ipv4.setInvalid();
        standard_metadata.egress_spec = egress_port;
    }

    action iarpreq(bit<48> src_mac) {
        hdr.arp.oper = 2;
        hdr.arp.tha = hdr.arp.sha;
        bit<32> temp = hdr.arp.tpa;
        hdr.arp.tpa = hdr.arp.spa;
        hdr.arp.sha = src_mac;
        hdr.arp.spa = temp;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = src_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action arpdigest() {
        arp_digest_t arp_digest = {
            hdr.arp.sha,
            hdr.arp.spa,
            hdr.ethernet.dstAddr,
            standard_metadata.ingress_port
        };
        digest(0, arp_digest);
    }

    action routdigest() {
        routing_digest_t routing_digest = {
            hdr.distance_vec.src,
            hdr.distance_vec.length,
            hdr.distance_vec.data,
            hdr.ethernet.srcAddr,
            standard_metadata.ingress_port
        };
        digest(0, routing_digest);
    }

    table tiHandleIncomingEthernet {
        key = {
            hdr.ethernet.dstAddr : exact;
            standard_metadata.ingress_port : exact;
        }
        actions = {
            aiForMe;
            aDrop;
        }
    }

    table tiHandleOutgoingRouting {
        key = {
            hdr.distance_vec.src : exact;
        }
        actions = {
            orouting;
            aDrop;
        }
    }

    table tiHandleIpv4 {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            lpmatch;
            setnhop;
            aDrop;
        }
    }

    table tiHandleOutgoingEthernet {
        key = {
            metadata.nhop : lpm; 
        }
        actions = {
            aiforward;
            sendarp;
        }
    }

    table tiHandleIncomingArpReqest {
        key = {
            hdr.arp.tpa : exact;
        }
        actions = {
            iarpreq;
        }
    }

    table tiHandleIncomingArpResponse {
        actions = {
            arpdigest;
        }
    }

    table tiHandleIncomingRouting {
        actions = {
            routdigest;
        }
    }

    apply {
        if (hdr.ethernet.isValid()) {
            tiHandleIncomingEthernet.apply();
        } else {
            tiHandleOutgoingRouting.apply();
        }
        if (metadata.forMe == 0) {
        } else if (hdr.ipv4.isValid()) {
            tiHandleIpv4.apply();
            tiHandleOutgoingEthernet.apply();
        } else if (hdr.arp.isValid() && hdr.arp.oper == 1) {
            tiHandleIncomingArpReqest.apply();
        } else if (hdr.arp.isValid() && hdr.arp.oper == 2) {
            tiHandleIncomingArpResponse.apply();
        } else if (hdr.distance_vec.isValid()) {
            tiHandleIncomingRouting.apply();
        } else {
            aDrop();
        }
    }
}

/*************************************************************************
***********************  E G R E S S  ************************************
*************************************************************************/

control cis553Egress(inout headers_t hdr,
                     inout local_variables_t metadata,
                     inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control cis553VerifyChecksum(inout headers_t hdr,
                             inout local_variables_t metadata) {
     apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control cis553ComputeChecksum(inout headers_t hdr,
                              inout local_variables_t metadata) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control cis553Deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.distance_vec);
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(cis553Parser(),
         cis553VerifyChecksum(),
         cis553Ingress(),
         cis553Egress(),
         cis553ComputeChecksum(),
         cis553Deparser()) main;
