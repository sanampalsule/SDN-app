package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.l3routing.IL3Routing;
import edu.wisc.cs.sdn.apps.util.ArpServer;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to L3Routing application
    private IL3Routing l3RoutingApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.l3RoutingApp = context.getServiceImpl(IL3Routing.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        
        /*********************************************************************/
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
    public void switchAdded(long switchId) {
        IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
        log.info(String.format("Switch s%d added", switchId));
        
        // Install default rule to send all packets to the next table (L3 routing)
        OFMatch match = new OFMatch();
        match.setWildcards(OFMatch.OFPFW_ALL);
        OFInstructionGotoTable gotoTable = new OFInstructionGotoTable((byte) 1);
        ArrayList<OFInstruction> instructionList = new ArrayList<OFInstruction>();
        instructionList.add(gotoTable);
        SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY, match, instructionList, (short) 0, (short) 0);
        
        // Install rules to handle TCP SYN and ARP requests for each virtual IP
        for (LoadBalancerInstance instance : this.instances.values()) {
            // Rule for TCP SYN to virtual IPs
            match = new OFMatch();
            match.setDataLayerType(Ethernet.TYPE_IPv4);
            match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
            match.setTcpFlags(TCP_FLAG_SYN);
            match.setNetworkDestination(instance.getVirtualIP());
            match.setWildcards(OFMatch.OFPFW_ALL ^ OFMatch.OFPFW_DL_TYPE ^ OFMatch.OFPFW_NW_PROTO ^ OFMatch.OFPFW_NW_DST_ALL ^ OFMatch.OFPFW_TP_DST);

            OFActionOutput outputToController = new OFActionOutput(IOFSwitch.Port.IN_PORT);
            ArrayList<OFAction> actionList = new ArrayList<OFAction>();
            actionList.add(outputToController);
            OFInstructionApplyActions applyActions = new OFInstructionApplyActions(actionList);
            instructionList.clear();
            instructionList.add(applyActions);
            SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY + 1, match, instructionList, IDLE_TIMEOUT, (short) 0);

            // Rule for ARP requests to virtual IPs
            match = new OFMatch();
            match.setDataLayerType(Ethernet.TYPE_ARP);
            match.setNetworkDestination(instance.getVirtualIP());
            match.setWildcards(OFMatch.OFPFW_ALL ^ OFMatch.OFPFW_DL_TYPE ^ OFMatch.OFPFW_NW_DST_ALL);
            
            actionList.clear();
            actionList.add(outputToController);
            applyActions = new OFInstructionApplyActions(actionList);
            instructionList.clear();
            instructionList.add(applyActions);
            SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY + 1, match, instructionList, (short) 0, (short) 0);
        }
    }

    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        OFPacketIn pktIn = (OFPacketIn)msg;
        Ethernet eth = new Ethernet();
        eth.deserialize(pktIn.getPacketData(), 0, pktIn.getTotalLength());
        if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
            IPv4 ipv4 = (IPv4) eth.getPayload();
            if (ipv4.getProtocol() == IPv4.PROTOCOL_TCP) {
                TCP tcp = (TCP) ipv4.getPayload();
                if (tcp.getFlags() == TCP_FLAG_SYN) {
                    int vip = ipv4.getDestinationAddress();
                    LoadBalancerInstance instance = this.instances.get(vip);
                    if (instance != null) {
                        // Implement host selection logic, e.g., round robin
                        String hostIP = instance.getHosts().get(0); // Simplified for example
                        int hostIpAddr = IPv4.toIPv4Address(hostIP);
                        MACAddress hostMacAddr = getHostMACAddress(hostIpAddr);

                        // Install connection-specific rule for TCP SYN
                        match = new OFMatch();
                        match.setDataLayerType(Ethernet.TYPE_IPv4);
                        match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
                        match.setNetworkSource(ipv4.getSourceAddress());
                        match.setNetworkDestination(vip);
                        match.setTransportSource(tcp.getSourcePort());
                        match.setTransportDestination(tcp.getDestinationPort());
                        match.setWildcards(OFMatch.OFPFW_ALL ^ OFMatch.OFPFW_DL_TYPE ^ OFMatch.OFPFW_NW_PROTO ^ OFMatch.OFPFW_NW_SRC_ALL ^ OFMatch.OFPFW_NW_DST_ALL ^ OFMatch.OFPFW_TP_SRC ^ OFMatch.OFPFW_TP_DST);

                        actionList.clear();
                        OFActionSetField setFieldIp = new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIpAddr);
                        OFActionSetField setFieldMac = new OFActionSetField(OFOXMFieldType.ETH_DST, hostMacAddr.toBytes());
                        actionList.add(setFieldIp);
                        actionList.add(setFieldMac);
                        actionList.add(new OFActionOutput(IOFSwitch.Port.NORMAL));
                        applyActions = new OFInstructionApplyActions(actionList);
                        instructionList.clear();
                        instructionList.add(applyActions);
                        SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 2), match, instructionList, IDLE_TIMEOUT, (short) 0);
                        return Command.STOP;
                    }
                } else {
                    // Send a TCP RST packet if the TCP packet is not a SYN
                    sendTcpReset(sw, pktIn, ipv4, tcp);
                    return Command.STOP;
                }
            } else if (ipv4.getProtocol() == IPv4.PROTOCOL_ARP) {
                ARP arp = (ARP) ipv4.getPayload();
                if (arp.getOpCode() == ARP.OP_REQUEST) {
                    int targetProtocolAddress = IPv4.toIPv4Address(arp.getTargetProtocolAddress());
                    if (this.instances.containsKey(targetProtocolAddress)) {
                        sendArpReply(sw, pktIn, arp, this.instances.get(targetProtocolAddress));
                        return Command.STOP;
                    }
                }
            }
        }
        return Command.CONTINUE;
    }

    private void sendTcpReset(IOFSwitch sw, OFPacketIn pktIn, IPv4 ipv4, TCP tcp) {
        Ethernet ethReply = new Ethernet();
        ethReply.setSourceMACAddress(ipv4.getDestinationAddress());
        ethReply.setDestinationMACAddress(ipv4.getSourceAddress());
        ethReply.setEtherType(Ethernet.TYPE_IPv4);

        IPv4 ipv4Reply = new IPv4();
        ipv4Reply.setSourceAddress(ipv4.getDestinationAddress());
        ipv4Reply.setDestinationAddress(ipv4.getSourceAddress());
        ipv4Reply.setProtocol(IPv4.PROTOCOL_TCP);

        TCP tcpReply = new TCP();
        tcpReply.setSourcePort(tcp.getDestinationPort());
        tcpReply.setDestinationPort(tcp.getSourcePort());
        tcpReply.setFlags(TCP_FLAG_RST);

        ipv4Reply.setPayload(tcpReply);
        ethReply.setPayload(ipv4Reply);

        byte[] serializedData = ethReply.serialize();
        OFPacketIn reply = new OFPacketIn();
        reply.setPacketData(serializedData);
        SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethReply);
    }

    private void sendArpReply(IOFSwitch sw, OFPacketIn pktIn, ARP arp, LoadBalancerInstance instance) {
        ARP arpReply = new ARP();
        arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
        arpReply.setHardwareAddressLength((byte) 6);
        arpReply.setProtocolAddressLength((byte) 4);
        arpReply.setOpCode(ARP.OP_REPLY);
        arpReply.setSenderHardwareAddress(instance.getVirtualMAC().toBytes());
        arpReply.setSenderProtocolAddress(arp.getTargetProtocolAddress());
        arpReply.setTargetHardwareAddress(arp.getSenderHardwareAddress());
        arpReply.setTargetProtocolAddress(arp.getSenderProtocolAddress());

        Ethernet ethReply = new Ethernet();
        ethReply.setEtherType(Ethernet.TYPE_ARP);
        ethReply.setSourceMACAddress(instance.getVirtualMAC().toBytes());
        ethReply.setDestinationMACAddress(arp.getSenderHardwareAddress());
        ethReply.setPayload(arpReply);

        SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethReply);
    }

    private MACAddress getHostMACAddress(int hostIPAddress) {
        Iterator<? extends IDevice> devices = this.deviceProv.queryDevices(null, null, hostIPAddress, null, null);
        if (devices.hasNext()) {
            return MACAddress.valueOf(devices.next().getMACAddress());
        }
        return null;
    }

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}
