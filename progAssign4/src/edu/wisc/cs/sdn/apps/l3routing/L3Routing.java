package edu.wisc.cs.sdn.apps.l3routing;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.sdnplatform.sync.internal.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener
{
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

    // Current paths for each switches as the destination.
	private Map<Long, Map<Long, Link>> nxtHopForDst;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
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
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Initialize variables or perform startup tasks, if necessary */
		updateAllSwitches();
		for (Host h: getHosts()) {
		    updateRule(h, UpdateRuleChoice.ADD_HOST);
        }
		/*********************************************************************/
	}
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

	/**
	 * Get update of the paths
	 */
	private void updateAllSwitches() {
		nxtHopForDst = new HashMap<Long, Map<Long, Link>>();
		for (Long sw: getSwitches().keySet()) {
			nxtHopForDst.put(sw, BellmanFord(sw));
		}
	}

	/**
	 * Run the Bellman Ford algorithm.
	 */
	private HashMap<Long, Link> BellmanFord(long t) {
		List<Long> path = new ArrayList<Long>();
		HashSet<Long> vis = new HashSet<Long>();
		HashMap<Long, Integer> dist = new HashMap<Long, Integer>();
		HashMap<Long, Link> nxtHop = new HashMap<Long, Link>();
		LinkedList<Long> queue = new LinkedList<Long>();

		Collection<Link> links = getLinks();
		Collection<Long> switches = getSwitches().keySet();

		int INF = 10000000;

		for (long u: switches) {
			if (u == t) dist.put(u, 0);
			else dist.put(u, INF);
		}

		queue.add(t);
		vis.add(t);

		while (!queue.isEmpty()) {
			long u = queue.pop();
			int du = dist.get(u);
			vis.remove(u);
			for (Link l: links) if (l.getDst() == u) {
				 long v = l.getSrc();
				 int dv = dist.get(v);
				 if (dv > du + 1) {
				 	dist.remove(v);
				 	dist.put(v, du + 1);
				 	nxtHop.remove(v);
				 	nxtHop.put(v, l);
				 	if (!vis.contains(v)) {
				 		vis.add(v);
				 		queue.add(v);
					}
				 }
			}
		}

		return nxtHop;
	}

	/**
	 * Get the path from source host to the destination host.
	 */
	private Pair<List<Long>, Integer> getPath(Map<Long, Long> nxtHop, Host src, Host dst) {
		List<Long> ans = new ArrayList<Long>();
		long s = src.getSwitch().getId(), t = dst.getSwitch().getId();
		long p = s;
		int len = -1;
		do {
			++len;
			ans.add(p);
			p = nxtHop.get(p);
		} while (p != t);
		return new Pair<List<Long>, Integer>(ans, len);
	}

	/**
	 * Search the port from s to t
	 */

	private int getPortFromS2T(long s, long t) {
		Collection<Link> links = getLinks();
		for (Link l: links) {
			if (l.getSrc() == s && l.getDst() == t) return l.getSrcPort();
		}
		return -1;
	}

	/**
	 * Update the rules of switches.
	 */
	private enum UpdateRuleChoice {
		ADD_HOST, DEL_HOST, MOV_HOST;
	}
	private void updateRule(Host dst, UpdateRuleChoice choice) {
		long t = dst.getSwitch().getId();
		for (Map.Entry<Long, IOFSwitch> entry: getSwitches().entrySet()) {
			IOFSwitch swEntity = entry.getValue();
			long sw = entry.getKey();
			Link link = nxtHopForDst.get(t).get(sw);
			OFMatch ofMatch = new OFMatch();
			ofMatch.setField(OFOXMFieldType.ETH_TYPE, OFMatch.ETH_TYPE_IPV4);
			ofMatch.setNetworkDestination(dst.getIPv4Address());

			if (choice == UpdateRuleChoice.DEL_HOST || choice == UpdateRuleChoice.MOV_HOST)
				SwitchCommands.removeRules(swEntity, table, ofMatch);
			if (dst.isAttachedToSwitch() && (choice == UpdateRuleChoice.MOV_HOST || choice == UpdateRuleChoice.ADD_HOST)) {
				OFInstructionApplyActions inst = new OFInstructionApplyActions();
				List<OFAction> actions = new LinkedList<OFAction>();
				actions.add(new OFActionOutput(getPortFromS2T(sw, link.getDst())));
				inst.setActions(actions);
				List<OFInstruction> instructions = new ArrayList<OFInstruction>();

				SwitchCommands.installRule(swEntity, table, SwitchCommands.DEFAULT_PRIORITY, ofMatch, instructions);
			}
		}


	}

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */

	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			updateRule(host, UpdateRuleChoice.ADD_HOST);
			/*****************************************************************/
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{ return; }
		this.knownHosts.remove(host);
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		updateRule(host, UpdateRuleChoice.DEL_HOST);
		/*********************************************************************/
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		updateRule(host, UpdateRuleChoice.MOV_HOST);
		/*********************************************************************/
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param switchId for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		updateAllSwitches();
		for (Host host: getHosts()) {
			updateRule(host, UpdateRuleChoice.MOV_HOST);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param switchId for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		updateAllSwitches();
		for (Host host: getHosts()) {
			updateRule(host, UpdateRuleChoice.MOV_HOST);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> s%s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		updateAllSwitches();
		for (Host host: getHosts()) {
			updateRule(host, UpdateRuleChoice.MOV_HOST);
		}
		/*********************************************************************/
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param switchId for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param switchId for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param switchId for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
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
        floodlightService.add(ILinkDiscoveryService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}
}
