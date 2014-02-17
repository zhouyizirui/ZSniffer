package grief.packetcaptor;

import java.io.IOException;
import java.util.ArrayList;

import grief.configuration.Config;
import jpcap.*;
import jpcap.packet.Packet;


public class Captor {
	
	public int deviceindex;
	public int packetindex;
	public JpcapCaptor mycaptor;
	public PacketCaptor captorhandler;
	public NetworkInterface[] devices;
	public ArrayList<Packet> packets=new ArrayList<Packet>();
	public Packet packet=null;
	
	public Captor(NetworkInterface[] devices,int deviceindex)
	{
		this.deviceindex=deviceindex;
		this.devices=devices;
	}
	public void initialCaptor()
	{
		try 
		{
			mycaptor=JpcapCaptor.openDevice(devices[deviceindex], 65535, Config.isromiscuous, 20);
			if(Config.filter.equals(""))
			{		
			}
			else
			{
				mycaptor.setFilter(Config.filter, true); //ether,fddi, tr, ip, ip6, arp, rarp, decnet, tcp and udp.
			}
			packetindex=0;
		} 
		catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		captorhandler=new PacketCaptor();
	}
	public void startCapture() 
	{
		mycaptor.processPacket(1, captorhandler);
	}
	
	public void stopCapture()
	{
		mycaptor.close();
	}
	class PacketCaptor implements PacketReceiver
	{
		@Override
		public void receivePacket(Packet temppacket) {
			// TODO Auto-generated method stub
			packetindex++;
			packet=temppacket;
			packets.add(temppacket);
		}
		
	}

	
	public int getPacketindex() {
		return packetindex;
	}
	public ArrayList<Packet> getPackets() {
		return packets;
	}
	public Packet getPacket() {
		return packet;
	}
	
}
