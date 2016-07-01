from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.dpid import str_to_dpid
from ryu.controller import dpset
from ryu.topology.api import get_switch, get_link
from ryu.topology import event, switches 
from ryu.lib import hub
import networkx as nx
import time



class LinkDelay(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset' : dpset.DPSet}

    def __init__(self, *args, **kwargs):
        super(LinkDelay, self).__init__(*args, **kwargs)
        self.sendEchotime=0.0
        self.receiveReplytime=0.0
        self.topology_api_app = self
        self.net=nx.DiGraph()
	self.switches = []
	time.sleep(2)
	self.monitor_thread = hub.spawn(self.send_echo_request)
        #self.send_echo_request(str_to_dpid('0000000000000003'),"123")

    @set_ev_cls(ofp_event.EventOFPEchoReply,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_reply_handler(self, ev):
        self.receiveReplytime=time.time()
    	print '*****detect the echoreply message'
    	#print ev.msg
        print '+++++++++the echo time is++++++++ '
        print "%f"%(self.receiveReplytime-self.sendEchotime)
        #self.logger.debug('OFPEchoReply received: data=%s',utils.hex_array(ev.msg.data))

    def send_echo_request(self):
	while True:
		hub.sleep(2)
		datapath = self.switches[0]
		data = "123"
            	ofp = datapath.ofproto
            	ofp_parser = datapath.ofproto_parser

            	req = ofp_parser.OFPEchoRequest(datapath, data)
            	datapath.send_msg(req)
		self.sendEchotime = time.time()
		hub.sleep(3)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        #time.sleep(0.5)
        switch_list = get_switch(self.topology_api_app, None)
        self.switches=[switch.dp for switch in switch_list]
        #self.send_echo_request(switches[0],"wyx")
        #self.sendEchotime=time.time()

    '''@set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        time.sleep(0.5)
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
         
        links_list = get_link(self.topology_api_app, None)
        #print links_list
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        #print links
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()
	attribute=self.net.get_edge_data(1,2)
	#print attribute['port']'''
