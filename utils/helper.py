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
import re
import struct

import google.protobuf.text_format
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2

from convert import encode, encodeIPv4, encodeNum


class P4InfoHelper(object):
    """
    A class used to generate things like table entries and digest configs that
    can be subsequently be used for switch.py's WriteTableEntry, etc. functions.
    It's nice to have a helper here because those functions expect a specific
    protobuf format and the use of the unique ids from data_plane.p4info.

    See the linked protobuf definition in the README for the precise format.

    Important Methods
    -----------------

    buildTableEntry(table_name, match_fields=None, default_action=False,
                    action_name=None, action_params=None, priority=None)
        Build a TableEntry message that represents either a default action
        (no match fields) or a match-action pair.  Should match a table, match
        keys, and action definition in the data plane.

        match_fields and action_params take Python dictionaries that map from
        field/parameter name to value.  If there are multiple match fields or
        multiple parameters to the action function, you can just add to the
        dictionary.

        Note that different types of matches (exact, lpm, etc.) expect different
        formats for match field.  get_match_field_pb() shows how each match
        field is parsed.  The P4 spec has more information on what they mean to
        the data plane program.

    buildMulticastEntry(mcast_group_id, member_ports)
        Build a MulticastGroupEntry object.  Assumes that there's some action in
        the data plane that sets the packet's multicast group like:

        standard_metadata.mcast_grp = 2;

        A call to this function with mcast_group_id = 2, and member_ports = 
        [1,2,3] will configure the switch to replicate that packet to ports 1,
        2, and 3. Useful for both multicasting and broadcasting.

    buildDigestConfig(digest_name)
        Build a DigestEntry message that can be used with switch.py's GetDigest
        function.  Should correspond with an action in the data plane that looks
        like the following, where digest_name is "ethlearn_digest_t"

        digest_t d = {hdr.ethernet.srcAddr, standard_metadata.ingress_port};
        digest(0, d);

    buildRoutingPayload(my_ip, distance_vector)
        Build a byte string from a distance vector.  The expected format of the
        distance vector is [[prefix, length, cost], [prefix, length, cost] ...].
        There is currently a limit of 42 elements in the vector.
    """

    def __init__(self, p4_info_filepath):
        p4info = p4info_pb2.P4Info()
        # Load the p4info file into a skeleton P4Info object
        with open(p4_info_filepath) as p4info_f:
            google.protobuf.text_format.Merge(p4info_f.read(), p4info)
        self.p4info = p4info

    def get(self, entity_type, name=None, id=None):
        if name is not None and id is not None:
            raise AssertionError("name or id must be None")

        for o in getattr(self.p4info, entity_type):
            pre = o.preamble
            if name:
                if (pre.name == name or pre.alias == name):
                    return o
            else:
                if pre.id == id:
                    return o

        if name:
            raise AttributeError("Could not find %r of type %s" \
                        % (name, entity_type))
        else:
            raise AttributeError("Could not find id %r of type %s" \
                        % (id, entity_type))

    def get_id(self, entity_type, name):
        return self.get(entity_type, name=name).preamble.id

    def get_name(self, entity_type, id):
        return self.get(entity_type, id=id).preamble.name

    def __getattr__(self, attr):
        # Synthesize convenience functions for name to id lookups for top-level
        # entities, e.g., get_tables_id(name) or get_actions_id(name)
        m = re.search("^get_(\w+)_id$", attr)
        if m:
            primitive = m.group(1)
            return lambda name: self.get_id(primitive, name)

        # Synthesize convenience functions for id to name lookups
        # e.g. get_tables_name(id) or get_actions_name(id)
        m = re.search("^get_(\w+)_name$", attr)
        if m:
            primitive = m.group(1)
            return lambda id: self.get_name(primitive, id)

        raise AttributeError("%r object has no attribute %r" \
                    % (self.__class__, attr))

    def get_match_field(self, table_name, name=None, id=None):
        """
        Returns the p4info interface specification of a table match field.
        One of name or id should be set.
        """
        for t in self.p4info.tables:
            pre = t.preamble
            if pre.name == table_name:
                for mf in t.match_fields:
                    if name is not None:
                        if mf.name == name:
                            return mf
                    elif id is not None:
                        if mf.id == id:
                            return mf
        raise AttributeError("%r has no attribute %r" \
                    % (table_name, name if name is not None else id))

    def get_match_field_pb(self, table_name, match_field_name, value):
        """
        Converts a match field value to something readable by the switch.
        For each match type, the user provides:
        EXACT:
            <value>
        LPM:
            [<string (ip address)>, <prefix length>]
        TERNARY:
            [<value>, <bit mask>]
        RANGE:
            [<low value>, <high value>]
        """
        p4info_match = self.get_match_field(table_name, match_field_name)
        bitwidth = p4info_match.bitwidth
        p4runtime_match = p4runtime_pb2.FieldMatch()
        p4runtime_match.field_id = p4info_match.id
        match_type = p4info_match.match_type
        if match_type == p4info_pb2.MatchField.EXACT:
            exact = p4runtime_match.exact
            exact.value = encode(value, bitwidth)
        elif match_type == p4info_pb2.MatchField.LPM:
            lpm = p4runtime_match.lpm
            lpm.value = encode(value[0], bitwidth)
            lpm.prefix_len = value[1]
        elif match_type == p4info_pb2.MatchField.TERNARY:
            lpm = p4runtime_match.ternary
            lpm.value = encode(value[0], bitwidth)
            lpm.mask = encode(value[1], bitwidth)
        elif match_type == p4info_pb2.MatchField.RANGE:
            lpm = p4runtime_match.range
            lpm.low = encode(value[0], bitwidth)
            lpm.high = encode(value[1], bitwidth)
        else:
            raise Exception("Unsupported match type with type %r" % match_type)
        return p4runtime_match

    def get_action_param(self, action_name, name=None, id=None):
        """
        Returns the p4info interface specification of an action parameter.
        One of name or id should be set.
        """
        for a in self.p4info.actions:
            pre = a.preamble
            if pre.name == action_name:
                for p in a.params:
                    if name is not None:
                        if p.name == name:
                            return p
                    elif id is not None:
                        if p.id == id:
                            return p
        raise AttributeError("action %r has no param %r, (has: %r)" \
                    % (action_name, name if name is not None else id, a.params))

    def get_action_param_pb(self, action_name, param_name, value):
        """
        Converts an action parameter value to something readable by the switch.
        The user provides a single value that will be passed to the action
        function when the associated table entry is matched.
        """
        p4info_param = self.get_action_param(action_name, param_name)
        p4runtime_param = p4runtime_pb2.Action.Param()
        p4runtime_param.param_id = p4info_param.id
        p4runtime_param.value = encode(value, p4info_param.bitwidth)
        return p4runtime_param

    def buildTableEntry(self,
                        table_name,
                        match_fields=None,
                        default_action=False,
                        action_name=None,
                        action_params=None,
                        priority=None):
        """
        See documentation at beginning of document.
        """
        table_entry = p4runtime_pb2.TableEntry()
        table_entry.table_id = self.get_tables_id(table_name)

        if priority is not None:
            table_entry.priority = priority

        if match_fields:
            table_entry.match.extend([
                self.get_match_field_pb(table_name, match_field_name, value)
                for match_field_name, value in match_fields.iteritems()
            ])

        if default_action:
            table_entry.is_default_action = True

        if action_name:
            action = table_entry.action.action
            action.action_id = self.get_actions_id(action_name)
            if action_params:
                action.params.extend([
                    self.get_action_param_pb(action_name, field_name, value)
                    for field_name, value in action_params.iteritems()
                ])
        return table_entry

    def buildMulticastEntry(self, mcast_group_id, member_ports):
        """
        See documentation at beginning of document.
        """
        multicast_entry = p4runtime_pb2.MulticastGroupEntry()

        multicast_entry.multicast_group_id = mcast_group_id

        for i in member_ports:
            replica = p4runtime_pb2.Replica()
            replica.egress_port = i
            replica.instance = 1
            multicast_entry.replicas.extend([replica])

        return multicast_entry

    def buildDigestConfig(self, digest_name):
        """
        See documentation at beginning of document.
        """
        digest_entry = p4runtime_pb2.DigestEntry()
        digest_entry.digest_id = self.get_digests_id(digest_name)
        digest_entry.config.max_timeout_ns = 0
        digest_entry.config.max_list_size = 1
        digest_entry.config.ack_timeout_ns = 1000000

        return {'name': digest_name, 'entry': digest_entry}

    def buildRoutingPayload(self, my_ip, distance_vector):
        """
        See documentation at beginning of document.

        This function uses struct.pack/unpack in order to make sure that the
        bytes are packed correctly.  Other function pack/unpack automatically
        with protobufs.  With this function, we're building the routing payload
        ourselves.
        """

        payload = bytearray(258)  # 6 (header) + 42 * 6 (prefix + length + cost)
        payload[0:4] = encodeIPv4(my_ip)
        payload[4:6] = encodeNum(len(distance_vector), 16)
        #my_ip_int = struct.unpack('!I', encodeIPv4(my_ip))[0]
        #struct.pack_into('!IH', payload, 0, my_ip_int, len(distance_vector))

        for i in range(len(distance_vector)):
            prefix, length, cost = distance_vector[i]
            prefix = struct.unpack('!I', encodeIPv4(prefix))[0]
            struct.pack_into('!IBB', payload, 6 + i * 6, prefix, length, cost)

        return bytes(payload)
