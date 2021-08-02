#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "../headers.p4"
#include "../util.p4"


#if __TARGET_TOFINO__ == 2
header tna_timestamps_h {
    bit<16> pad_1;
    bit<48> ingress_mac;
    bit<16> pad_2;
    bit<48> ingress_global;
    bit<32> enqueue;
    bit<32> dequeue_delta;
    bit<16> pad_5;
    bit<48> egress_global;
    bit<16> pad_6;
    bit<48> egress_tx;
}
#else
header tna_timestamps_h {
    bit<16> pad_1;
    bit<48> ingress_mac;
    bit<16> pad_2;
    bit<48> ingress_global;
    bit<14> pad_3;
    bit<18> enqueue;
    bit<14> pad_4;
    bit<18> dequeue_delta;
    bit<16> pad_5;
    bit<48> egress_global;
    bit<16> pad_6;
    bit<48> egress_tx;
}
#endif

const bit<8> RESUB_TYPE_A = 255;
const bit<8> RESUB_TYPE_B = 0;
const bit<8> RESUB_TYPE_C = 1;

header resubmit_type_a {
    bit<8>  type;
    bit<8>  f1;
    bit<16> f2;
    bit<32> f3;
#if __TARGET_TOFINO__ != 1
    bit<64> additional;
#endif
}
header resubmit_type_b {
    bit<8>  type;
    bit<8>  f1;
    bit<48> padding;
#if __TARGET_TOFINO__ != 1
    bit<64> additional;
#endif
}
header resubmit_type_c {
    bit<8>  type;
    bit<16> f1;
    bit<16> f2;
    bit<16> f3;
    bit<8> padding;
#if __TARGET_TOFINO__ != 1
    bit<64> additional;
#endif
}

struct metadata_t {
    bit<8>          resub_type;
    resubmit_type_a a;
    resubmit_type_b b;
    resubmit_type_c c;
    // result_h result_hdr;
    //tna_timestamps_h tna_timestamps_hdr;
    //ptp_metadata_t tx_ptp_md_hdr;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    //TofinoIngressParser() tofino_parser;

    //state start {
    //    tofino_parser.apply(pkt, ig_md, ig_intr_md);
    //    transition parse_ethernet;
    //}

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        ig_md.resub_type = pkt.lookahead<bit<8>>()[7:0];
        transition select(ig_md.resub_type) {
            RESUB_TYPE_A : parse_resub_a;
            RESUB_TYPE_B : parse_resub_b;
            RESUB_TYPE_C : parse_resub_c;
            default : reject;
        }
    }

    state parse_resub_a {
        pkt.extract(ig_md.a);
        transition parse_resub_end;
    }
    state parse_resub_b {
        pkt.extract(ig_md.b);
        transition parse_resub_end;
    }
    state parse_resub_c {
        pkt.extract(ig_md.c);
        transition parse_resub_end;
    }

    state parse_resub_end {
    #if __TARGET_TOFINO__ != 1
        /* On Tofino-2 and later there are an additional 64 bits of padding
         * after the resubmit data but before the packet headers.  This is also
         * present for non-resubmit packets but the "port_metadata_unpack" call
         * will handle skipping over this padding for non-resubmit packets. */
        pkt.advance(64);
    #endif
        transition parse_ethernet;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    //state parse_tna_timestamp {
    //    pkt.extract(ig_md.tna_timestamps_hdr);
    //    transition accept;
    //}
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply {
        pkt.emit(hdr);
        //pkt.emit(ig_md.tna_timestamps_hdr);
    }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : reject;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    //state parse_tna_timestamp {
    //    pkt.extract(eg_md.tna_timestamps_hdr);
    //    transition accept;
    //}
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(packet_out pkt,
                              inout header_t hdr,
                              in metadata_t eg_md,
                              in egress_intrinsic_metadata_for_deparser_t 
                                eg_intr_dprsr_md
                              ) {

    apply {
        pkt.emit(hdr);
        //pkt.emit(eg_md.result_hdr);
        //pkt.emit(eg_md.tna_timestamps_hdr);
    }
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    //action set_egress_port() {
    //    ig_intr_tm_md.ucast_egress_port = OUTPUT_PORT;
    //}
    //
    //table output_port {
    //    actions = {
    //        set_egress_port;
    //    }
    //    size = 1024;
    //    default_action = set_egress_port;
    //}

    apply {

        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        //ig_tm_md.bypass_egress = 1w1;

        //output_port.apply();
    }
}

// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    Resubmit() resubmit;

    action ipv4_mtu_check(bit<16> mtu) {
        hdr.report.result = mtu |-| hdr.ipv4.total_len;

    }

    action mtu_miss() {
        hdr.report.result = 16w0xffff;
    }

    table mtu {
        key = {
            hdr.ipv4.isValid() : exact;
        }

        actions = {
            ipv4_mtu_check;
            mtu_miss;
        }

        const default_action = mtu_miss;
        size = 1024;
    }

    apply {
        hdr.report.setValid();
        hdr.udp.hdr_length = hdr.udp.hdr_length + 2;

        mtu.apply();

        if (hdr.report.result == 16w0) {
            eg_md.b.type = RESUB_TYPE_B;
            eg_md.b.f1 = 8w1;
#if __TARGET_TOFINO__ != 1
            eg_md.b.additional = 64w0;
#endif
            resubmit.emit(eg_md.b);
        }
    }
}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
