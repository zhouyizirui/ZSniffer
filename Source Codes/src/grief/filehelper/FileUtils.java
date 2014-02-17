package grief.filehelper;

import grief.configuration.Config;
import grief.packetstat.PacketStat;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Properties;

import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Shell;


import jpcap.packet.*;

public class FileUtils {

	StringBuffer stringbuffer=new StringBuffer();
	SimpleDateFormat sdf=new SimpleDateFormat("HH：mm：ss");
	String time;
	
	public FileUtils()
	{
		
	}
	
	public void getReport()
	{
		Properties props=System.getProperties();
		stringbuffer.append("******************************Configuration******************************"+"\r\n");
		stringbuffer.append("\r\n");
		stringbuffer.append("Operation System: "+props.getProperty("os.name")+"\r\n");
		stringbuffer.append("Interface: "+Config.Interface+"\r\n");
		stringbuffer.append("Datalink Type: "+Config.DatalinkType+"\r\n");
		stringbuffer.append("Mac Address: "+Config.MacAddress+"\r\n");
		stringbuffer.append("Ip Address: "+Config.Ipv4Address+"\r\n");
		stringbuffer.append("\r\n");
		
		stringbuffer.append("*********************************Result*********************************"+"\r\n");
		stringbuffer.append("\r\n");
		stringbuffer.append("Packet number: "+PacketStat.totalpacket+"\r\n");
		stringbuffer.append("Ip number: "+PacketStat.ippacket+"\r\n");
		stringbuffer.append("Ipv6 number: "+PacketStat.ipv6packet+"\r\n");
		stringbuffer.append("ARP number: "+PacketStat.arppacket+"\r\n");
		stringbuffer.append("UDP number: "+PacketStat.udppacket+"\r\n");
		stringbuffer.append("TCP number: "+PacketStat.tcppacket+"\r\n");
		stringbuffer.append("ICMP number: "+PacketStat.icmppacket+"\r\n");
		stringbuffer.append("IGMP number: "+PacketStat.igmppacket+"\r\n");
		
	
		
	}
	
	public void writeReportFile()
	{
		time=sdf.format(new java.util.Date());
		File file=new File(Config.savepath+"/Report"+"("+time+")"+".txt");
		if(!file.exists())
		{
			try 
			{
				file.createNewFile();
			} 
			catch (IOException e) 
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else
		{
			file.delete();
		}
		
		try 
		{
			BufferedWriter output=new BufferedWriter(new FileWriter(file));
			output.write(new String(stringbuffer));
			output.close();
		} 
		catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public void writePackets(ArrayList <Packet> packets)
	{
		if(packets.size()!=0)
		{
			File file=new File(Config.savepath+"/Packets"+"("+time+")"+".dat");
			try 
			{
				FileOutputStream fileoutput=new FileOutputStream(file);
				ObjectOutputStream outputstream=new ObjectOutputStream(fileoutput);
				outputstream.writeObject(packets);
				fileoutput.close();
			} 
			catch (IOException e) 
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else
		{
			Shell shell=new Shell();
			MessageBox messagebox=new MessageBox(shell, SWT.ICON_WARNING);
			messagebox.setText("注意");
			messagebox.setMessage("没有数据可以存储！仅生成报告！");
			messagebox.open();
		}
	}
	public ArrayList<Packet> readPackets(String filepath)
	{
		ArrayList<Packet> packets=new ArrayList<Packet>();
		
		if(filepath.length()<8)
		{
			return packets;
		}
		else if(!filepath.endsWith(").dat"))
		{
			return packets;
		}
		File file=new File(filepath);
		try 
		{
			FileInputStream fileinput=new FileInputStream(file);
			ObjectInputStream inputstream=new ObjectInputStream(fileinput);
			packets=(ArrayList<Packet>)inputstream.readObject();
			fileinput.close();
		} 
		catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return packets;
	}
}
