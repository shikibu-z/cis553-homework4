# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from Queue import Queue
from abc import abstractmethod
from datetime import datetime

import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.tmp import p4config_pb2


MSG_LOG_MAX_LEN = 1024

# List of all active connections
connections = []

def ShutdownAllSwitchConnections():
    for c in connections:
        c.shutdown()

class SwitchConnection(object):
    """
    An object that can be used to configure a programmable data plane.  Many of
    the functions expect well-formatted protobuf messages.  helper.py can build
    them for you.

    Most of these functions include a dry_run option that will print out the
    protobuf object instead of sending it to the data plane so that you can
    verify its format.


    Important Methods
    -----------------

    AddMulticastGroup(multicast_group_entry, dry_run=False)
        Adds a MulticastGroupEntry to the data plane.  See helper.py for how to
        build this entry.

    GetDigest(digest_config, dry_run=False)
        Requests the next digest in the stream.  Registers the digest with the
        control plane if necessary. Each call to this function will block until
        it returns a single digest object.

        You can check the protobufs / P4Runtime docs for the format of the
        returned object, or you can print it out yourself.

    WriteTableEntry(table_entry, dry_run=False)
        Adds a TableEntry to a data plane table.  See helper.py for how to build
        this entry.  Should only be called if the match_fields does not already
        exist in the table.

    UpdateTableEntry(table_entry, dry_run=False)
        Same as WriteTableEntry, but to replace existing entries with the same
        match_fields configuration.

    ReadTableEntries(table_id=None, dry_run=False)
        Used to fetch all the table entries that have been added to the data
        plane.  You can get the table_id of a table using helper.py's
        get_tables_id(table_name) function.

    SendPacketOut(payload, dry_run=False)
        Sends a message with contents defined by payload to the data plane.
    """

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        self.proto_dump_file = proto_dump_file

        self.digests_configured = dict()
        connections.append(self)

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def MasterArbitrationUpdate(self, dry_run=False, **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1

        if dry_run:
            print "P4Runtime MasterArbitrationUpdate: ", request
        else:
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                return item # just one

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print "P4Runtime SetForwardingPipelineConfig:", request
        else:
            self.client_stub.SetForwardingPipelineConfig(request)

    def ConfigureDigest(self, digest_config, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1

        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.digest_entry.CopyFrom(digest_config)

        if dry_run:
            print "P4Runtime ConfigureDigest:", request
        else:
            self.client_stub.Write(request)

    def AddMulticastGroup(self, multicast_group_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.high = 0
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.multicast_group_entry.CopyFrom(multicast_group_entry)
        if dry_run:
            print "P4Runtime AddMulticastGroup:", request
        else:
            self.client_stub.Write(request)

    def GetDigest(self, digest_configs, dry_run=False):
        for config in digest_configs:
            entry = config['entry']
            if entry.digest_id not in self.digests_configured:
                self.digests_configured[entry.digest_id] = config['name']
                self.ConfigureDigest(entry, dry_run)

        # listen for a single request
        response = None
        for item in self.stream_msg_resp:
            response = item
            break

        # now ACK it so we get more
        ack = p4runtime_pb2.StreamMessageRequest()
        ack.digest_ack.digest_id = response.digest.digest_id
        ack.digest_ack.list_id = response.digest.list_id
        self.requests_stream.put(ack)

        # fill in the name from the config
        name = self.digests_configured[response.digest.digest_id]
        return DigestReturn(name, response.digest)

    def WriteTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print "P4Runtime Write:", request
        else:
            self.client_stub.Write(request)

    def UpdateTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print "P4Runtime Update:", request
        else:
            self.client_stub.Write(request)

    def ReadTableEntries(self, table_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            print "P4Runtime Read:", request
        else:
            for response in self.client_stub.Read(request):
                yield response

    def SendPacketOut(self, payload, dry_run=False):
        req = p4runtime_pb2.StreamMessageRequest()
        req.packet.payload = payload

        if dry_run:
            print "Sending PacketOut:", req
        else:
            self.requests_stream.put(req)


class DigestReturn(object):
    def __init__(self, name, digest):
        self.name = name
        self.digest = digest

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return 'name: %s\n%s' % (self.name, self.digest)


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)