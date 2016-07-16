#The main contents are as follows:

##1. Network troubleshooting based on OpenFlow: 
  Troubleshooting network plays vital role in many network applications and protocols. The current troubleshooting mainly analysis the results of performance measurement, which is coarse-grained for fault diagnosis. In this paper, a network measurement and link troubleshooting method based on OpenFlow protocol is proposed so that faults can be diagnosed effectively. This method utilize the centralized controller to collect information from every node among the network, analyze the information for topology management, link packet loss, link bandwidth, link delay and packet trajectory to diagnose the network, and finally experiments show that the proposed method effectively diagnose and locate the link fault.

##2. Fast Link Failure Recovery Based on OpenFlow: 
  As part of network security, network disaster and recovery has been a focus, and traditional network lacks of automatic failure detection and recovery tool. Since the traditional network’s control plane tightly coupled with data plane, making the network into a distributed system. When a network link fails, the network can not be fast fault location and recovery. However, SDN breaks the traditional closed network. To rapidly locate and recover link failure in SDN, a link failure recovery mechanism based on OpenFlow is proposed. the mechanism realize  topology management, loop free, route management, failure detection and recovery in SDN controller. Simulation results prove that the mechanism can accurately detect and recover the link failure.

##3. Detecting Packet Trajectory on NetMagic Platform: 
  NetMagic is FPGA-based SDN switching device, which overcomes the limitations of the equipment NetFPGA form, programmability, performance and other aspects. It is easy to modify software and hardware, design case fully, etc. This paper present the detection of network topology and packet trajectory in the network consists of NetMagics. We use probe packet to reproduce the trajectory of arbitrary production packet only by adding three rules per NetMagic to record path his-tory in on-board RAM. The core idea is that we install a hash function in both controller and NetMagic to process the header of probe packets, which considerably reduce the usage of RAM space and facilitate the collection of trajectory data. The evaluation shows that our implementation works properly under high concurrency of tracing tasks by adjusting the parameter of hash function.

This is the SDN Network Fault Diagnosis project developed Yu Jun@SoutheastUniversity.

If you find any issues or bugs, please contact me with e-mail: yujun_daxia@163.com
