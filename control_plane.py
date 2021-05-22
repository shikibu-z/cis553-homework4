# Name: Junyong Zhao
# PennKey: junyong

import argparse
from collections import OrderedDict
import json
import os
import struct
import sys
import threading
from time import sleep

sys.path.append("utils")
import bmv2
import helper
from convert import *


def SendDistanceVector(router, p4info_helper, myIPs, distanceVector, dvLock):
    while True:
        for ip in myIPs:
            dvLock.acquire()
            payload = p4info_helper.buildRoutingPayload(ip, distanceVector)
            dvLock.release()
            router.SendPacketOut(payload)
        sleep(10)


def RunControlPlane(router, config, p4info_helper):
    distanceVector = []
    dvLock = threading.Lock()
    myIPs = []
    rtable = {}
    infty = 16

    for i in config:
        ip = getBaseIPv4(i["ip"], i["prefix_len"])
        distanceVector.append([ip, i["prefix_len"], 0])
        myIPs.append(i["ip"])
        rtable[(ip, i["prefix_len"])] = [i["ip"], 0]

        table_entry = p4info_helper.buildTableEntry(
            table_name="cis553Ingress.tiHandleIncomingEthernet",
            match_fields={
                "hdr.ethernet.dstAddr": "FF:FF:FF:FF:FF:FF",
                "standard_metadata.ingress_port": i["port"]
            },
            action_name="cis553Ingress.aiForMe"
        )
        router.WriteTableEntry(table_entry)
        table_entry = p4info_helper.buildTableEntry(
            table_name="cis553Ingress.tiHandleIncomingEthernet",
            match_fields={
                "hdr.ethernet.dstAddr": i["mac"],
                "standard_metadata.ingress_port": i["port"]
            },
            action_name="cis553Ingress.aiForMe"
        )
        router.WriteTableEntry(table_entry)
        table_entry = p4info_helper.buildTableEntry(
            table_name="cis553Ingress.tiHandleOutgoingRouting",
            match_fields={
                "hdr.distance_vec.src": i["ip"]
            },
            action_name="cis553Ingress.orouting",
            action_params={
                "src_mac": i["mac"],
                "dst_mac": "FF:FF:FF:FF:FF:FF",
                "egress_port": i["port"]
            }
        )
        router.WriteTableEntry(table_entry)
        table_entry = p4info_helper.buildTableEntry(
            table_name="cis553Ingress.tiHandleIpv4",
            match_fields={
                "hdr.ipv4.dstAddr": [getBaseIPv4(i["ip"], i["prefix_len"]), i["prefix_len"]]
            },
            action_name="cis553Ingress.setnhop")
        router.WriteTableEntry(table_entry)
        table_entry = p4info_helper.buildTableEntry(
            table_name="cis553Ingress.tiHandleOutgoingEthernet",
            match_fields={
                "metadata.nhop": [getBaseIPv4(i["ip"], i["prefix_len"]), i["prefix_len"]]
            },
            action_name="cis553Ingress.sendarp",
            action_params={
                "src_mac": i["mac"],
                "dst_mac": "FF:FF:FF:FF:FF:FF",
                "src_ip": i["ip"],
                "egress_port": i["port"]
            }
        )
        router.WriteTableEntry(table_entry)
        table_entry = p4info_helper.buildTableEntry(
            table_name="cis553Ingress.tiHandleIncomingArpReqest",
            match_fields={
                "hdr.arp.tpa": i["ip"]
            },
            action_name="cis553Ingress.iarpreq",
            action_params={
                "src_mac": i["mac"]
            }
        )
        router.WriteTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name="cis553Ingress.tiHandleIncomingArpResponse",
        default_action=True,
        action_name="cis553Ingress.arpdigest")
    router.UpdateTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name="cis553Ingress.tiHandleIncomingRouting",
        default_action=True,
        action_name="cis553Ingress.routdigest")
    router.UpdateTableEntry(table_entry)

    rout_digest = p4info_helper.buildDigestConfig("routing_digest_t")
    arp_digest = p4info_helper.buildDigestConfig("arp_digest_t")

    update_thread = threading.Thread(
        target=SendDistanceVector,
        args=(
            router, p4info_helper, myIPs, distanceVector, dvLock
        )
    )
    update_thread.start()

    while 1:
        response = router.GetDigest([rout_digest, arp_digest])
        if response.name == "arp_digest_t":
            sha = decodeMac(
                response.digest.data[0].struct.members[0].bitstring)
            spa = decodeIPv4(
                response.digest.data[0].struct.members[1].bitstring)
            dst_mac = decodeMac(
                response.digest.data[0].struct.members[2].bitstring)
            ingress_port = decodeNum(
                response.digest.data[0].struct.members[3].bitstring)
            table_entry = p4info_helper.buildTableEntry(
                table_name="cis553Ingress.tiHandleOutgoingEthernet",
                match_fields={
                    "metadata.nhop": [getBaseIPv4(spa, 32), 32]
                },
                action_name="cis553Ingress.aiforward",
                action_params={
                    "src_mac": dst_mac,
                    "dst_mac": sha,
                    "egress_port": ingress_port
                }
            )
            router.WriteTableEntry(table_entry)

        elif response.name == "routing_digest_t":
            src_ip = decodeIPv4(
                response.digest.data[0].struct.members[0].bitstring)
            src_len = decodeNum(
                response.digest.data[0].struct.members[1].bitstring)
            data = response.digest.data[0].struct.members[2].bitstring
            src_mac = decodeMac(
                response.digest.data[0].struct.members[3].bitstring)
            ingress_port = decodeNum(
                response.digest.data[0].struct.members[4].bitstring)
            for i in range(src_len):
                prefix, length, cost = struct.unpack_from(
                    '!IBB', data, i*6)
                prefix = decodeIPv4(struct.pack('!I', prefix))
                new_cost = cost + 1
                if new_cost > infty:
                    new_cost = infty
                if (prefix, length) in rtable:
                    if new_cost < rtable[(prefix, length)][1]:
                        table_entry = p4info_helper.buildTableEntry(
                            table_name="cis553Ingress.tiHandleIpv4",
                            match_fields={
                                "hdr.ipv4.dstAddr": [prefix, length]
                            },
                            action_name="cis553Ingress.lpmatch",
                            action_params={
                                "next_hop": src_ip
                            }
                        )
                        router.UpdateTableEntry(table_entry)
                    elif new_cost == rtable[(prefix, length)][1]:
                        continue
                    elif src_ip == rtable[(prefix, length)][0]:
                        table_entry = p4info_helper.buildTableEntry(
                            table_name="cis553Ingress.tiHandleIpv4",
                            match_fields={
                                "hdr.ipv4.dstAddr": [prefix, length]
                            },
                            action_name="cis553Ingress.lpmatch",
                            action_params={
                                "next_hop": src_ip
                            }
                        )
                        router.UpdateTableEntry(table_entry)
                    else:
                        continue
                    dvLock.acquire()
                    rtable[(prefix, length)] = [src_ip, new_cost]
                    for j in distanceVector:
                        if j[0] == prefix and j[1] == length:
                            j[2] = new_cost
                    dvLock.release()
                    for ip in myIPs:
                        dvLock.acquire()
                        payload = p4info_helper.buildRoutingPayload(
                            ip, distanceVector)
                        dvLock.release()
                        router.SendPacketOut(payload)
                else:
                    table_entry = p4info_helper.buildTableEntry(
                        table_name="cis553Ingress.tiHandleIpv4",
                        match_fields={
                            "hdr.ipv4.dstAddr": [prefix, length]
                        },
                        action_name="cis553Ingress.lpmatch",
                        action_params={
                            "next_hop": src_ip
                        }
                    )
                    router.WriteTableEntry(table_entry)
                    dvLock.acquire()
                    rtable[(prefix, length)] = [src_ip, new_cost]
                    distanceVector.append([prefix, length, new_cost])
                    dvLock.release()
                    for ip in myIPs:
                        dvLock.acquire()
                        payload = p4info_helper.buildRoutingPayload(
                            ip, distanceVector)
                        dvLock.release()
                        router.SendPacketOut(payload)

    router.shutdown()


def ConfigureNetwork(p4info_file="build/data_plane.p4info",
                     bmv2_json="build/data_plane.json",
                     topology_json="topology2.json"):
    p4info_helper = helper.P4InfoHelper(p4info_file)
    with open(topology_json, 'r') as f:
        routers = json.load(f, object_pairs_hook=OrderedDict)['routers']

    threads = []
    port = 50051
    id_num = 0

    for name, config in routers.items():
        config = byteify(config)

        print "Connecting to P4Runtime server on {}...".format(name)
        r = bmv2.Bmv2SwitchConnection(name, "127.0.0.1:" + str(port), id_num)
        r.MasterArbitrationUpdate()
        r.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                      bmv2_json_file_path=bmv2_json)
        t = threading.Thread(target=RunControlPlane,
                             args=(r, config, p4info_helper))
        t.start()
        threads.append(t)

        port += 1
        id_num += 1

    for t in threads:
        t.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CIS553 P4Runtime Controller')

    parser.add_argument("-c", '--p4info-file',
                        help="path to P4Runtime protobuf description (text)",
                        type=str, action="store",
                        default="build/data_plane.p4info")
    parser.add_argument("-b", '--bmv2-json',
                        help="path to BMv2 switch description (json)",
                        type=str, action="store",
                        default="build/data_plane.json")
    parser.add_argument("-t", '--topology-json',
                        help="path to the topology configuration (json)",
                        type=str, action="store",
                        default="configs/topology.json")

    args = parser.parse_args()

    if not os.path.exists(args.p4info_file):
        parser.error("File %s does not exist!" % args.p4info_file)
    if not os.path.exists(args.bmv2_json):
        parser.error("File %s does not exist!" % args.bmv2_json)
    if not os.path.exists(args.topology_json):
        parser.error("File %s does not exist!" % args.topology_json)

    ConfigureNetwork(args.p4info_file, args.bmv2_json, args.topology_json)
