package grief.packetanalyzer;
import grief.packetstat.PacketStat;

import java.text.SimpleDateFormat;

import jpcap.packet.*;

public class SimpleAnalyzer extends Analyzer{
	
	public int no=0;
	public boolean ismac=false;
	public String network;
	public String transport;
	public int length;
	public String time;
	public String source;
	public String destination;
	public String sourceport=new String();
	public String destport=new String();
	public String data;
	public Packet packet;
	public DatalinkPacket datalinkpacket;
	public EthernetPacket ethernetpacket;
	public IPPacket ippacket;
	public ARPPacket arppacket;
	public TCPPacket tcppacket;
	public UDPPacket udppacket;
	public void simpleanalysis(Packet mainpacket,int packetindex)
	{
		no=packetindex;
		PacketStat.totalpacket++;
		data=null;
		SimpleDateFormat sdf=new SimpleDateFormat("HH:mm:ss");
		time=sdf.format(new java.util.Date());
		packet=mainpacket;
		length=packet.len;
		datalinkpacket=packet.datalink;
		ethernetpacket=(EthernetPacket)datalinkpacket;	
		if(Integer.toHexString(ethernetpacket.frametype & 0xffff).equals("800"))
		{
			network="IP";
			ismac=false;
			PacketStat.ippacket++;
			ippacket=(IPPacket)packet;
			source=ippacket.src_ip.toString();
			source=source.substring(1,source.length());
			destination=ippacket.dst_ip.toString();
			destination=destination.substring(1,destination.length());
			if(ippacket.protocol==1)
			{
				transport="ICMP";
				ismac=true;
				PacketStat.icmppacket++;
			}
			else if(ippacket.protocol==6)
			{
				transport="TCP";
				tcppacket=(TCPPacket)ippacket;
				sourceport=tcppacket.src_port+"";
				destport=tcppacket.dst_port+"";
				PacketStat.tcppacket++;
			}
			else if(ippacket.protocol==17)
			{
				transport="UDP";
				udppacket=(UDPPacket)ippacket;
				sourceport=udppacket.src_port+"";
				destport=udppacket.dst_port+"";
				PacketStat.udppacket++;
			}
			else if(ippacket.protocol==2)
			{
				transport="IGMP";
				ismac=true;
				PacketStat.igmppacket++;
			}
			else
			{
				transport="Unknow";
			}
		}
		else if(Integer.toHexString(ethernetpacket.frametype & 0xffff).equals("806"))
		{
			source=bytetoString(ethernetpacket.src_mac);
			destination=bytetoString(ethernetpacket.dst_mac);
			network="ARP";
			ismac=true;
			arppacket=(ARPPacket)packet;
			PacketStat.arppacket++;
			
			if(Integer.toHexString(arppacket.operation & 0xffff).equals("1"))
			{
				transport="Request";
			}
			else if(Integer.toHexString(arppacket.operation & 0xffff).equals("2"))
			{
				transport="Reply";
			}
		}
		else if(Integer.toHexString(ethernetpacket.frametype & 0xffff).equals("86dd"))
		{
			PacketStat.ipv6packet++;
			ismac=true;
			source="Unknow";
			destination="Unknow";
			network="Ipv6";
			transport="Unknow";
		}
		else 
		{
			ismac=true;
			source="Unknow";
			destination="Unknow";
			network="Unknow";
			transport="Unknow";
		}
		
	}
	
	public String bytetoString(byte mac[])
	{
		String retstring=new String();
		for(int i=0;i<mac.length;i++)
		{
			if(Integer.toHexString(mac[i] & 0xff).length()<2)
			{
				retstring=retstring+"0"+Integer.toHexString(mac[i] & 0xff);
			}
			else
			{
				retstring=retstring+Integer.toHexString(mac[i] & 0xff);
			}
			
			
			if(i!=mac.length-1)
			{
				retstring=retstring+"-";
			}
		}
		return retstring;
	}
	
	
	
	public boolean isIsmac() {
		return ismac;
	}

	public String getSourceport() {
		return sourceport;
	}

	public String getDestport() {
		return destport;
	}

	public int getNo() {
		return no;
	}
	public String getNetwork() {
		return network;
	}
	public String getTransport() {
		return transport;
	}
	public int getLength() {
		return length;
	}
	public String getTime() {
		return time;
	}
	public String getSource() {
		return source;
	}
	public String getDestination() {
		return destination;
	}
	public String getData() {
		return data;
	}
	public Packet getPacket() {
		return packet;
	}
	
	
	
}
