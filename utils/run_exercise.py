#!/usr/bin/env python2
# Copyright 2013-present Barefoot Networks, Inc.
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
# Adapted by Robert MacDavid (macdavid@cs.princeton.edu) from scripts found in
# the p4app repository (https://github.com/p4lang/p4app)
#
# We encourage you to dissect this script to better understand the BMv2/Mininet
# environment used by the P4 tutorial.
#
from collections import OrderedDict
import os, sys, json, subprocess, re, argparse
from os import path
from time import sleep

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.term import makeTerm


from p4runtime_switch import P4RuntimeSwitch

def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4 Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4Switch

class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
        A custom class is used because the exercises make a few topology
        assumptions, mostly about the IP and MAC addresses.
    """
    def __init__(self, hosts, switches, links, log_dir, **opts):
        Topo.__init__(self, **opts)

        for h in hosts:
            host_config = hosts[h]
            host_prefix = host_config['prefix_len']
            host_ip = host_config['ip'] + "/" + str(host_prefix)
            host_mac = host_config['mac']
            self.addHost(h, ip=host_ip, mac=host_mac)

        for sw in switches:
            self.addSwitch(sw, log_file="%s/%s.log" %(log_dir, sw))

        for link in links:
            if link['node1'][0] == 'h':
                host_name = link['node1']
                host_mac = hosts[host_name]['mac']
                sw_name = link['node2'][:link['node2'].index(':')]
                sw_port = int(link['node2'][link['node2'].index(':')+1:])
                self.addLink(host_name, sw_name,
                             port1=1, port2=sw_port,
                             delay=link['latency'], bw=link['bandwidth'],
                             addr1=host_mac, addr2=host_mac)
            elif link['node2'][0] == 'h':
                host_name = link['node2']
                host_mac = hosts[host_name]['mac']
                sw_name = link['node1'][:link['node1'].index(':')]
                sw_port = int(link['node1'][link['node1'].index(':')+1:])
                self.addLink(host_name, sw_name,
                             port1=1, port2=sw_port,
                             delay=link['latency'], bw=link['bandwidth'],
                             addr1=host_mac, addr2=host_mac)
            else:
                node1_name = link['node1'][:link['node1'].index(':')]
                node1_port = int(link['node1'][link['node2'].index(':')+1:])
                node2_name = link['node2'][:link['node2'].index(':')]
                node2_port = int(link['node2'][link['node2'].index(':')+1:])
                self.addLink(node1_name, node2_name,
                             port1=node1_port, port2=node2_port,
                             delay=link['latency'], bw=link['bandwidth'])


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : list<string>       // list of mininet host names
            switches : dict<string, dict> // mininet host names and their associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def formatLatency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, topo_file, log_dir, pcap_dir,
                       switch_json, bmv2_exe='simple_switch', quiet=False):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json file which describes the exercise's
                                         mininet topology.
                log_dir  : string     // Path to a directory for storing exercise logs
                pcap_dir : string     // Ditto, but for mininet switch pcap files
                switch_json : string  // Path to a compiled p4 json for bmv2
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.quiet = quiet
        self.logger('Reading topology file.')
        self.topo_file = topo_file
        with open(self.topo_file, 'r') as f:
            topo = json.load(f, object_pairs_hook=OrderedDict)
        self.hosts = topo['hosts']
        self.switches = topo['routers']
        self.links = self.parse_links(topo['links'])

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe


    def run_exercise(self, no_term):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Not sure how to do the sleeps better

        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        self.program_switches()
        sleep(1)

        with open(self.log_dir + "/cp.log", "w") as control_log_file:
            # Run the control plane
            control_path = path.dirname(path.dirname(path.abspath(__file__))) \
                           + "/control_plane.py"
            cp = subprocess.Popen(["python", control_path,
                                   "-t", self.topo_file],
                                  stdout=control_log_file)
            sleep(1)

            # check if it actually worked. This check doesn't catch everything.
            # Only immediate errors.
            cp.poll()
            if cp.returncode and cp.returncode != 0:
                self.net.stop()
                raise RuntimeError("Could not start up control plane")

            self.do_net_cli(no_term)
            # stop right after the CLI is exited
            self.net.stop()


    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            if s > t:
                s,t = t,s

            link_dict = {'node1':s,
                        'node2':t,
                        'latency':'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.formatLatency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 'r', 'Hosts should be connected to routers, not ' + str(link_dict['node2'])
            links.append(link_dict)
        return links


    def create_network(self):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        self.topo = ExerciseTopo(self.hosts, self.switches.keys(), self.links, self.log_dir)

        switchClass = configureP4Switch(
                sw_path=self.bmv2_exe,
                json_path=self.switch_json,
                log_console=True,
                verbose=True,
                pcap_dump=self.pcap_dir)

        self.net = Mininet(topo = self.topo,
                      link = TCLink,
                      host = P4Host,
                      switch = switchClass,
                      controller = None)


    def program_switches(self):
        """ If any command files were provided for the switches,
            this method will start up the CLI on each switch and use the
            contents of the command files as input.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        cli = 'simple_switch_CLI'
        for sw_name, sw_dict in self.switches.iteritems():
            if 'cli_input' not in sw_dict: continue
            # get the port for this particular switch's thrift server
            sw_obj = self.net.get(sw_name)
            thrift_port = sw_obj.thrift_port

            cli_input_commands = sw_dict['cli_input']
            self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))
            with open(cli_input_commands, 'r') as fin:
                cli_outfile = '%s/%s_cli_output.log'%(self.log_dir, sw_name)
                with open(cli_outfile, 'w') as fout:
                    subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                     stdin=fin, stdout=fout)

    def program_hosts(self):
        """ Adds static ARP entries and default routes to each mininet host.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for host_name in self.topo.hosts():
            h = self.net.get(host_name)
            h_iface = h.intfs.values()[0]
            host_gw = self.hosts[host_name]["gateway"]

            # Ensure each host's interface name is unique, or else mininet
            # cannot shutdown gracefully
            h.defaultIntf().rename('%s-eth0' % host_name)

            # static arp entries and default routes
            # link = h_iface.link
            # sw_iface = link.intf1 if link.intf1 != h_iface else link.intf2
            # h.cmd('arp -i %s -s %s %s' % (h_iface.name, host_gw, sw_iface.mac))

            h.cmd('ethtool --offload %s rx off tx off' % h_iface.name)
            #h.cmd('ip route add %s dev %s' % (host_gw, h_iface.name))
            h.setDefaultRoute("via %s dev %s" % (host_gw, h_iface.name))

            h.cmd('sudo tcpdump -n -i %s --immediate-mode -U -Q in -w %s/%s_in.pcap &' % (h_iface.name, self.pcap_dir, host_name))
            h.cmd('sudo tcpdump -n -i %s --immediate-mode -U -Q out -w %s/%s_out.pcap &' % (h_iface.name, self.pcap_dir, host_name))

    def do_net_cli(self, no_term):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        # if self.switch_json:
        #     print('To inspect or change the switch configuration, connect to')
        #     print('its CLI from your host operating system using this command:')
        #     print('  simple_switch_CLI --thrift-port <switch thrift port>')
        #     print('')
        print('To view a router log, run this command from your host OS:')
        print('  tail -f %s/<routername>.log' %  self.log_dir)
        print('')
        print('To view the router pcaps, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')
        print('To view the host pcaps, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r h2_in.pcap')
        print('')

        if not no_term:
            for node in self.net.hosts:
                self.net.terms += makeTerm(node, term = "xterm")

        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-n', '--no_term', help='Do not run xterm',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch')
    return parser.parse_args()


if __name__ == '__main__':
    from mininet.log import setLogLevel
    setLogLevel("info")

    args = get_args()
    exercise = ExerciseRunner(args.topo, args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet)

    exercise.run_exercise(args.no_term)

