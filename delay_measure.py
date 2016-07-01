from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.controller.handler import set_ev_cls
from ryu.base import app_manager
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import vlan
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.ofproto.ofproto_parser import MsgBase, msg_str_attr
from ryu.lib import mac
import netaddr
import array
import time
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from ryu.topology import api
import networkx as nx
from ryu.lib import hub

path = [1,2,3]

class PacketTest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        }
    def __init__(self, *args, **kwargs):
   	super(PacketTest,self).__init__(*args,**kwargs)
        self.sw = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.dpset=kwargs['dpset']
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0
        self.path_List = []
        self.flows_List = []
        self.add_flow_time=[]
        self.receveTestTime=0.0
        self.sendTestTime=0.0
        self.add_flow_path=[1,2,3]
	#self.test_delay_path=[1,2,3]
	self.limit=1
	self.flow_limit=1
	time.sleep(1)
	self.monitor_thread = hub.spawn(self.testdelay)
        
    def testdelay(self):
	#hub.sleep(3)
	#self.get_topology_data()
	'''if(self.flow_limit==1):
        	self.add_path_flow(self.add_flow_path)
		self.flow_limit += 1'''
	#hub.sleep(3)
	while True:
		test_delay_path=[1,2,3]
        	dp= self.dpset.get(test_delay_path[0])
        	p = self.build_udp()
        	link = self.net.get_edge_data(test_delay_path[0],test_delay_path[1])
		if link:
			port_no = link['port']
        		self.send_openflow_packet(dp, p.data,port_no)
			print 'success'
			hub.sleep(3)
		hub.sleep(3)
        
    def build_udp(self):
        #dst = '1' * 6
	dst = '00:00:00:00:00:01'
        src = '00:00:00:00:00:02' 
        ethertype = ether.ETH_TYPE_8021Q
        e = ethernet.ethernet(dst, src, ethertype)
        v = vlan.vlan(1, 1, 3, ether.ETH_TYPE_IP)

        ip = ipv4.ipv4(4, 5, 0, 0, 0, 0, 0, 255, 17, 33, '192.168.1.1', '192.168.1.11')
        u = udp.udp(12, 34, 0)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(v)
        p.add_protocol(ip)
        p.add_protocol(u)
	#data content
        p.add_protocol("123456789")
        p.serialize()
        return p

    def send_openflow_packet(self, dp, packet, port_no,
                             inport=ofproto_v1_3.OFPP_CONTROLLER):

        actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
	out=dp.ofproto_parser.OFPPacketOut(datapath=dp,buffer_id=dp.ofproto.OFP_NO_BUFFER,in_port=dp.ofproto.OFPP_CONTROLLER,actions=actions,data=packet)
	dp.send_msg(out)
	self.sendTestTime=time.time()
	print "the send time is %f and the send datapath is %d"%(self.sendTestTime,dp.id)
        #dp.send_packet_out(in_port=inport, actions=actions, data=packet)


    #add flow
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, idle_timeout=0, hard_timeout=0,
                                    priority=priority, match=match,
                                    instructions=inst, flags=flags)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=0, hard_timeout=0,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
	print '%%%%%%%%%%%'


    #get topology
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self,ev):
        time.sleep(0.01)
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        print "**********List of links"
        print self.net.edges()
	'''while(self.limit>0):
		self.testdelay(self.test_delay_path)
		self.limit-=1'''
		#hub.sleep(3)

    def add_path_flow(self,path):
	i=0
        pathlen=len(path)
        while i<pathlen-1:
            datapath = self.dpset.get(path[i])
	    ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            dpid = path[i]
            link = self.net.get_edge_data(path[i],path[i+1])
	    if link:
	    	out_port = link['port']
            	match = parser.OFPMatch(ipv4_src='192.168.1.1')
            	actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            	self.add_flow(datapath, 1, match, actions)
		#print "add a flow"
		#print "match is"
		#print match
	    else:
		print 'no link'
	    i=i+1

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
	pkt = packet.Packet(msg.data)
	nw=pkt.get_protocol(ipv4.ipv4)
	pkt_arp = pkt.get_protocol(arp.arp)
	#if pkt_arp:
		#print 'paket is arp'
	if(nw):
        	ip_src = nw.src
		print datapath.id
		print '///////////'
		print ip_src
        	if(ip_src=='192.168.1.1'):
            		print'+++++++receive the test packet from %d '% datapath.id
            		#print msg.data
            		self.receveTestTime=time.time()
			print 'the receive time is %f'%self.receveTestTime
            		print'**********caculate the delay time is ******'
            		delaytime=self.receveTestTime-self.sendTestTime
			f=open('/home/john/Data/delay.txt','a')
			f.write(str(delaytime)+'\n')
			f.close()
            		print delaytime
