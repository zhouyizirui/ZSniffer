package grief.packetanalyzer;
import grief.dns.DnsPacket;

import java.util.ArrayList;

import jpcap.packet.*;

public class DetailAnalyzer extends Analyzer{

	public Packet packet;
	public DatalinkPacket datalinkpacket;
	public EthernetPacket ethernetpacket;
	public byte[] packetbyte;
	public byte[] temppacket;
	public StringBuffer hexstringbuffer=new StringBuffer();
	public StringBuffer charstringbuffer=new StringBuffer();
	public ArrayList<String> framestring=new ArrayList<String>();
	public ArrayList<String> ethernetstring=new ArrayList<String>();
	public ArrayList<String> networkstring=new ArrayList<String>();
	public ArrayList<String> transportstring=new ArrayList<String>();
	public int analysislayer=2;
	
	public DetailAnalyzer()
	{
		
	}
	public void analysisBinary(Packet mypacket)
	{
		this.packet=mypacket;
		if(packet.caplen==packet.len)
		{
			datalinkpacket=packet.datalink;
			ethernetpacket=(EthernetPacket)datalinkpacket;
			packetbyte=new byte[packet.caplen];
			System.arraycopy(packet.header, 0, packetbyte, 0, packet.header.length);
			System.arraycopy(packet.data, 0, packetbyte, packet.header.length, packet.data.length);
			temppacket=new byte[packetbyte.length];
			binaryToHex();
			frameInfo();
			ethernetInfo();
		}
		else
		{
			analysislayer=0;
		}
	}
	public void binaryToHex()
	{
		hexstringbuffer.append("\n");
		hexstringbuffer.append("0x0000: ");
		for(int i=0;i<packetbyte.length;i++)
		{
			String temp=Integer.toHexString(packetbyte[i] & 0xff);
			if(temp.length()==1)
			{
				temp="0"+temp;
			}
			hexstringbuffer.append(temp+" ");
			if(packetbyte[i]<32 || packetbyte[i]>126)
			{
				temppacket[i]=46;
			}
			else
			{
				temppacket[i]=packetbyte[i];
			}
			
			charstringbuffer.append(new String(temppacket,i,1)+" ");
			
			if((i+1)%10==0)
			{
				hexstringbuffer.append(" ");
				hexstringbuffer.append(charstringbuffer+"\n");
				if(i+1<100 && i+1<packetbyte.length)
				{
					hexstringbuffer.append("0x00"+(i+1)+": ");
				}
				else if(i+1>=100 && i+1<1000 && i+1<packetbyte.length)
				{
					hexstringbuffer.append("0x0"+(i+1)+": ");
				}
				else if(i+1<packetbyte.length)
				{
					hexstringbuffer.append("0x"+(i+1)+": ");	
				}
				charstringbuffer.setLength(0);
			}
			
			if(i==packetbyte.length-1 && (i+1)%10!=0)
			{
				for(int j=0;j<10-packetbyte.length%10;j++)
				{
					hexstringbuffer.append("   ");
				}
				hexstringbuffer.append(" "+charstringbuffer+"\n");
			}
		}
	}
	public void frameInfo()
	{
		String temp;
		temp="Total: "+packet.len+" bytes";
		framestring.add(temp);
		temp="Header: "+packet.header.length+" bytes";
		framestring.add(temp);
		temp="Data: "+packet.data.length+" bytes";
		framestring.add(temp);
	}
	
	public void ethernetInfo()
	{
		String temp;
		temp="Src: "+byteToString(ethernetpacket.src_mac);
		ethernetstring.add(temp);
		temp="Des: "+byteToString(ethernetpacket.dst_mac);
		ethernetstring.add(temp);
		temp=Integer.toHexString(ethernetpacket.frametype & 0xffff);
		if(temp.length()<4)
		temp="0x0"+temp;
		else
		temp="0x"+temp;
		
		if(temp.equals("0x0800"))
		{
			temp=temp+"(IP)";
			ipInfo();
		}
		else if(temp.equals("0x0806"))
		{
			temp=temp+"(ARP)";
			arpInfo();
		}
		else
		{
			temp=temp+"(Unknow)";
		}
		temp="Type: "+temp;
		
		ethernetstring.add(temp);
	}
	
	public void arpInfo()
	{
		String temp;
		String tempbyte;
		
		temp="Hardware: 0x";
		tempbyte=Integer.toHexString(packetbyte[14] & 0xff);
		if(tempbyte.length()<2)
		tempbyte="0"+tempbyte;
		temp=temp+tempbyte;
		
		tempbyte=Integer.toHexString(packetbyte[15] & 0xff);
		if(tempbyte.length()<2)
		tempbyte="0"+tempbyte;
		temp=temp+tempbyte;
		networkstring.add(temp);
		
		temp="Protocol: 0x";
		tempbyte=Integer.toHexString(packetbyte[16] & 0xff);
		if(tempbyte.length()<2)
		tempbyte="0"+tempbyte;
		temp=temp+tempbyte;
		
		tempbyte=Integer.toHexString(packetbyte[17] & 0xff);
		if(tempbyte.length()<2)
		tempbyte="0"+tempbyte;
		temp=temp+tempbyte;
		networkstring.add(temp);
		
		temp="Operation: 0x";
		tempbyte=Integer.toHexString(packetbyte[20] & 0xff);
		if(tempbyte.length()<2)
		tempbyte="0"+tempbyte;
		temp=temp+tempbyte;
		
		tempbyte=Integer.toHexString(packetbyte[21] & 0xff);
		if(tempbyte.length()<2)
		tempbyte="0"+tempbyte;
		temp=temp+tempbyte;
		
		if(temp.equals("Operation: 0x0001"))
		temp=temp+"(Request)";
		else if(temp.equals("Operation: 0x0002"))
		temp=temp+"(Reply)";
		networkstring.add(temp);
		
		temp="SrcMac: ";
		byte [] tempmac=new byte[6];
		temp=temp+bytesToString(tempmac, 22);
		networkstring.add(temp);
		
		temp="SrcIp: ";
		temp=temp+byteToIp(28);
		networkstring.add(temp);
		
		temp="DestMac: ";
		temp=temp+bytesToString(tempmac, 32);
		networkstring.add(temp);
		
		temp="DestIp: ";
		temp=temp+byteToIp(38);
		networkstring.add(temp);
		
		analysislayer=3;
	
	}
	
	
	
	public void ipInfo()
	{
		String temp;
		
		IPPacket ippacket=(IPPacket)packet;
		
		temp=ippacket.src_ip.toString();
		temp=temp.substring(1, temp.length());
		temp="Source: "+temp;
		networkstring.add(temp);

		
		temp=ippacket.dst_ip.toString();
		temp=temp.substring(1,temp.length());
		temp="Destination: "+temp;
		networkstring.add(temp);
		
		
		temp=ippacket.protocol+"";
		if(temp.endsWith("1"))
		{
			temp=temp+"(ICMP)";
			icmpInfo();
		}
		else if(temp.equals("2"))
		{
			temp=temp+"(IGMP)";
			igmpInfo();
		}
		else if(temp.equals("6"))
		{
			temp=temp+"(TCP)";
			tcpInfo();
		}
		else if(temp.equals("17"))
		{
			temp=temp+"(UDP)";
			udpInfo();
		}
		else
		{
			temp=temp+"(Unknow)";
		}
		temp="Type: "+temp;
		networkstring.add(temp);
		
		temp="Version: "+(int)ippacket.version;
		networkstring.add(temp);
		temp="Length: "+ippacket.length;
		networkstring.add(temp);
		temp="TOS: "+ippacket.rsv_tos;
		networkstring.add(temp);
		
		if(packetbyte.length>28)
		{
			
			int flag=packetbyte[20] & 0xf0; //1110 0000
			temp="Flags: "+flag/16;
			networkstring.add(temp);
			if(flag==128)
			{
				temp="1... Reserved bit: Yes";
			}
			else
			{
				temp="0... Reserved bit: No";
			}
			networkstring.add(temp);
			if(flag==64)
			{
				temp=".1.. Don't fragment: Yes";
			}
			else
			{
				temp=".0.. Don't fragment: No";
			}
			networkstring.add(temp);
			
			if(flag==32)
			{
				temp="..1. More fragments: Yes";
			}
			else
			{
				temp="..0. More fragments: No";
			}
			networkstring.add(temp);
			
			temp="TTL: "+ippacket.hop_limit;
			networkstring.add(temp);
			temp="Idetification: "+ippacket.ident;
			networkstring.add(temp);
			
		}	
	}
	
	public void icmpInfo()
	{
		String temp;
		ICMPPacket icmppacket=(ICMPPacket)(IPPacket)packet;
		temp="Type: ";
		temp=temp+(int)(icmppacket.type & 0xff);
		if(temp.equals("Type: 8"))
		{
			temp=temp+"(Request)";
		}
		else if(temp.equals("Type: 0"))
		{
			temp=temp+"(Reply)";
		}
		transportstring.add(temp);
		
		temp="Code: ";
		temp=temp+(int)(icmppacket.code & 0xff);
		if(temp.equals("Code: 0"))
		{
			temp=temp+"(Ping)";
		}
		transportstring.add(temp);
		
		temp="Identification: ";
		temp=temp+"0x"+Integer.toHexString(icmppacket.id & 0xffff);
		transportstring.add(temp);
		
		
		temp="Sequence: ";
		temp=temp+(int)(icmppacket.seq & 0xffff);
		transportstring.add(temp);
		
		analysislayer=4;
		
	}
	
	public void igmpInfo()
	{
		String temp;
		temp="Version: ";
		if(Integer.toHexString(packetbyte[34] & 0xff).equals("11"))
		{
			temp=temp+1;
		}
		else if(Integer.toHexString(packetbyte[34] & 0xff).equals("94"))
		{
			temp=temp+2;
		}
		transportstring.add(temp);
		
		temp="Type: ";
		if((int)(packetbyte[34] & 0x0f)==1)
		{
			temp=temp+"Query";
		}
		else if((int)(packetbyte[34] & 0x0f)==2)
		{
			temp=temp+"Report";
		}
		else if((int)(packetbyte[34] & 0x0f)==4)
		{
			if((int)(packetbyte[38] & 0xff)==16)
			{
				temp=temp+"Report(V2)";
			}
			else 
			{
				temp=temp+"Unknow";
			}
		}
		transportstring.add(temp);
		
		temp="MulticastAdd: ";
		if(packetbyte.length==46)
		temp=temp+byteToIp(42);
		else
		temp=temp+byteToIp(38);
		
		analysislayer=4;
		
	}
	
	public void udpInfo()
	{
		String temp;
		UDPPacket udppacket=(UDPPacket)(IPPacket)packet;
		temp="Src Port: "+udppacket.src_port;
		transportstring.add(temp);
		
		temp="Des Port: "+udppacket.dst_port;
		transportstring.add(temp);
		
		temp="Length: "+udppacket.length;
		transportstring.add(temp);
		
		analysislayer=4;
		
		if(udppacket.src_port==53 || udppacket.dst_port==53)
		{
			DnsPacket.packet=packet;
			analysislayer=5;
		}
	}
	
	public void tcpInfo()
	{
		String temp;
		TCPPacket tcppacket=(TCPPacket)(IPPacket)packet;
		temp="Src Port: ";
		temp=temp+tcppacket.src_port;
		transportstring.add(temp);
		
		temp="Des Port: ";
		temp=temp+tcppacket.dst_port;
		transportstring.add(temp);
		
		temp="Seq: ";
		temp=temp+tcppacket.sequence;
		transportstring.add(temp);
		
		temp="ACK: ";
		temp=temp+tcppacket.ack_num;
		transportstring.add(temp);
		
		temp="Header:";
		temp=temp+(int)(packetbyte[46] & 0xf0);
		transportstring.add(temp);
		
		temp="Flags: ";
		if(Integer.toHexString(packetbyte[47] & 0xff).length()<2)
		temp=temp+"0x0"+Integer.toHexString(packetbyte[47] & 0xff);
		else
		temp=temp+"0x"+Integer.toHexString(packetbyte[47] & 0xff);
		transportstring.add(temp);
		
		temp="0... .... CWR: No";
		transportstring.add(temp);
		
		temp=".0.. .... ECN: No";
		transportstring.add(temp);
		
		if((int)(packetbyte[47] & 0x20)==32)
		{
			temp="..1. .... URG: Yes";
		}
		else
		{
			temp="..0. .... URG: No";
		}
		transportstring.add(temp);
		
		if((int)(packetbyte[47] & 0x10)==16)
		{
			temp="...1 .... ACK: Yes";
		}
		else
		{
			temp="...0 .... ACK: No";
		}
		transportstring.add(temp);
		
		if((int)(packetbyte[47] & 0x08)==8)
		{
			temp=".... 1... PSH: Yes";
		}
		else
		{
			temp=".... 0... PSH: No";
		}
		transportstring.add(temp);
		
		if((int)(packetbyte[47] & 0x04)==4)
		{
			temp=".... .1.. RST: Yes";
		}
		else
		{
			temp=".... .0.. RST: No";
		}
		transportstring.add(temp);
		
		if((int)(packetbyte[47] & 0x02)==2)
		{
			temp=".... ..1. SYN: Yes";
		}
		else
		{
			temp=".... ..0. SYN: No";
		}
		transportstring.add(temp);
		
		if((int)(packetbyte[47] & 0x01)==1)
		{
			temp=".... ...1 FIN: Yes";
		}
		else
		{
			temp=".... ...0 FIN: No";
		}
		transportstring.add(temp);
		
		temp="Window: ";
		temp=temp+tcppacket.window;
		transportstring.add(temp);
		
		analysislayer=4;
		
	}
	
	public String byteToString(byte mac[])
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
	
	
	
	public String bytesToString(byte tempmac[],int src)
	{
		String retstring=new String();
		for(int i=0;i<6;i++)
		{
			tempmac[i]=packetbyte[src+i];
		}
		retstring=byteToString(tempmac);
		return retstring;
	}
	
	public String byteToIp(int src)
	{
		String retstring=new String();
		for(int i=0;i<4;i++)
		{
			retstring=retstring+(int)(packetbyte[src+i] & 0xff); //将byte转化为int型时，如果不进行与操作，byte将保留高位符号位。
			if(i!=3)
			{
				retstring=retstring+".";
			}
		}
		return retstring;
	}
	
	public ArrayList<String> getFramestring() {
		return framestring;
	}
	
	
	public ArrayList<String> getEthernetstring() {
		return ethernetstring;
	}
	
	
	public ArrayList<String> getNetworkstring() {
		return networkstring;
	}
	public ArrayList<String> getTransportstring() {
		return transportstring;
	}
	public int getAnalysislayer() {
		return analysislayer;
	}
	public byte[] getPacketbyte() {
		return packetbyte;
	}
	public StringBuffer getHexstringbuffer() {
		return hexstringbuffer;
	}

}
