package grief.dns;

import java.util.ArrayList;

import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.widgets.Dialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.TreeItem;

import jpcap.packet.*;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Tree;

public class DnsDialog extends Dialog {

	protected Object result;
	protected Shell shell;
	public Packet packet;
	public UDPPacket udppacket;
	public Tree tree;
	public TreeItem roottree;
	public TreeItem treeleaf;
	public TreeItem answerleaf;
	public ArrayList<String> resourcestring=new ArrayList<String>();
	StringBuffer sb=new StringBuffer();
	/**
	 * Create the dialog.
	 * @param parent
	 * @param style
	 */
	public DnsDialog(Shell parent, int style) {
		super(parent, style);
		packet=DnsPacket.packet;
		setText("DNS Packet Analyzer");
	}

	/**
	 * Open the dialog.
	 * @return the result
	 */
	public Object open() {
		createContents();
		shell.open();
		shell.layout();
		Display display = getParent().getDisplay();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		return result;
	}

	/**
	 * Create contents of the dialog.
	 */
	private void createContents() {
		shell = new Shell(getParent(), getStyle());
		shell.setSize(509, 566);
		shell.setText(getText());
		shell.setBackground(new Color(Display.getDefault(), 255, 255, 255));
		
		Label lblDnsPacket = new Label(shell, SWT.NONE);
		lblDnsPacket.setBounds(192, 10, 99, 17);
		lblDnsPacket.setText("DNS Packet");
		lblDnsPacket.setBackground(new Color(Display.getDefault(), 255, 255, 255));
		lblDnsPacket.setFont(new Font(Display.getDefault(), "свт╡", 13, SWT.NORMAL));
		
		Group grpDnsAnalyzer = new Group(shell, SWT.NONE);
		grpDnsAnalyzer.setText("Dns Analyzer");
		grpDnsAnalyzer.setBounds(25, 33, 453, 485);
		grpDnsAnalyzer.setBackground(new Color(Display.getDefault(), 255, 255, 255));
		
		tree = new Tree(grpDnsAnalyzer, SWT.BORDER);
		tree.setBounds(10, 21, 433, 454);
		setTreeItem();
	}
	public void setTreeItem()
	{
		int i=0;
		String temp;
		
		roottree=new TreeItem(tree, SWT.NULL);
		roottree.setText("Header");
		
		temp="0x";
		for(i=0;i<2;i++)
		{
			if(Integer.toHexString(packet.data[i] & 0xff).length()<2)
			{
				temp=temp+"0"+Integer.toHexString(packet.data[i] & 0xff);
			}
			else
			{
				temp=temp+Integer.toHexString(packet.data[i] & 0xff);
			}
		}
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Mark: "+temp);
		
		if((int)(packet.data[2] & 0x80)==128)
		{
			temp="1"+"(Answer)";
		}
		else
		{
			temp="0"+"(Ask)";
		}
		treeleaf=new TreeItem(roottree,SWT.NULL);
		treeleaf.setText("QR Flag: "+temp);
		
		if((int)(packet.data[2] & 0x78)==0)
		{ 
			temp="0"+"(Standard Query)";
		}
		else if((int)(packet.data[2] & 0x78)==1)
		{
			temp="1"+"(Reverse Query)";
		}
		else if((int)(packet.data[2] & 0x78)==2)
		{
			temp="2"+"(Server Status Query)";
		}
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Option code: "+temp);
		
		temp=""+(int)(packet.data[2] & 0x04)/4;
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Authoritative Answer: "+temp);
		
		temp=""+(int)(packet.data[2] & 0x02)/2;
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Truncated: "+temp);
		
		temp=""+(int)(packet.data[2] & 0x01);
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Recursion desired: "+temp);
		
		temp=""+(int)(packet.data[3] & 0x80)/128;
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Recursion avaliable: "+temp);
		
		temp=""+"000";
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Zero: "+temp);
		
		if((int)(packet.data[3] & 0x0f)==0)
		{
			temp="0"+"(Right Name)";
		}
		else
		{
			temp="1"+"(Wrong Name)";
		}
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Return Code: "+temp);
		
		temp=""+(int)(packet.data[5] & 0xff);
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Number Of Question: "+temp);
		
		temp=""+(int)(packet.data[7] & 0xff);
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Number Of Resource: "+temp);
		
		temp=""+(int)(packet.data[9] & 0xff);
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Number Of Authorized Resource: "+temp);
		
		temp=""+(int)(packet.data[11] & 0xff);
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Number Of Other Resource: "+temp);
		
		roottree=new TreeItem(tree, SWT.NULL);
		roottree.setText("Question");
		
		temp="";
		for(i=13;(int)(packet.data[i] & 0xff)!=0;i++)
		{
			if((int)(packet.data[i] & 0xff)>30)
			{
				temp=temp+new String(packet.data,i,1);
			}
			else
			{
				temp=temp+".";
			}
		}	
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Name: "+temp);
		
		if((int)(packet.data[i+2])==1)
		{
			temp=(int)packet.data[i+2]+"(IP Address)"+"\n";
		}
		else if((int)(packet.data[i+2])==2)
		{
			temp=(int)packet.data[i+2]+"(Name Server)"+"\n";
		}
		else if((int)(packet.data[i+2])==13)
		{ 
			temp=(int)packet.data[i+2]+"(Host Information)"+"\n";
		}
		else if((int)(packet.data[i+2])==5)
		{
			temp=(int)packet.data[i+2]+"(Pointer Record)"+"\n";
		}
		else
		{
			temp=(int)packet.data[i+2]+"(Other)"+"\n";
		}
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Question Type: "+temp);
		
		if((int)packet.data[i+4]==1)
		{
			temp="1"+"(Always 1, Means Internet)";
		}
		else
		{
			temp="0"+"(Something Wrong)";
		}
		treeleaf=new TreeItem(roottree, SWT.NULL);
		treeleaf.setText("Question: "+temp);
		
		if(i+5!=packet.data.length)
		{
			i=i+5;
			int count=1;
			roottree=new TreeItem(tree, SWT.NULL);
			roottree.setText("Answers");
			
			while(i<packet.data.length)
			{
				answerleaf=new TreeItem(roottree,SWT.NULL);
				answerleaf.setText("Answer"+count);
				resourcestring.removeAll(resourcestring);
				i=analysisResource(i);
				for(int j=0;j<6;j++)
				{
					treeleaf=new TreeItem(answerleaf, SWT.NULL);
					treeleaf.setText(resourcestring.get(j));
				}
				count++;
			}
			
		}
	}
	public int analysisResource(int index)
	{
		String temp;
		int length;
		int i;
		int type=0; 
		temp="0x";
		if(Integer.toHexString(packet.data[index] & 0xff).length()<2)
		{
			temp=temp+"0"+Integer.toHexString(packet.data[index] & 0xff);
		}
		else
		{
			temp=temp+Integer.toHexString(packet.data[index] & 0xff);
		}
		
		if(Integer.toHexString(packet.data[index+1] & 0xff).length()<2)
		{
			temp=temp+"0"+Integer.toHexString(packet.data[index+1] & 0xff);
		}
		else
		{
			temp=temp+Integer.toHexString(packet.data[index+1] & 0xff);
		}
		resourcestring.add("Name Pointer: "+temp);
		
		temp="0x";
		if(Integer.toHexString(packet.data[index+2] & 0xff).length()<2)
		{
			temp=temp+"0"+Integer.toHexString(packet.data[index+2] & 0xff);
		}
		else
		{
			temp=temp+Integer.toHexString(packet.data[index+2] & 0xff);
		}
		
		if(Integer.toHexString(packet.data[index+3] & 0xff).length()<2)
		{
			temp=temp+"0"+Integer.toHexString(packet.data[index+3] & 0xff);
		}
		else
		{
			temp=temp+Integer.toHexString(packet.data[index+3] & 0xff);
		}
		
		if(temp.equals("0x0001"))
		{
			type=1;
			temp=temp+"(IP Address)";
		}
		else if(temp.equals("0x0005"))
		{
			type=0;
			temp=temp+"(Correct Name)";
		}
		else if(temp.equals("0x0002"))
		{
			type=0;
			temp=temp+"(Name Server)";
		}
		else
		{
			type=0;
			temp=temp+"(UnAnalyzed)";
		}
		resourcestring.add("Criterion Name: "+temp);
		
		temp="";
		if((int)packet.data[index+5]==1)
		{
			temp="1"+"(Always 1, Means Internet)"+"\n";
		}
		else
		{
			temp="0"+"(Something Wrong)"+"\n";
		}
		resourcestring.add("Question: "+temp);
		
		index=index+6;
		
		temp=""+((int)(packet.data[index+2] & 0xff)*256+(int)(packet.data[index+3] & 0xff));
		resourcestring.add("TTL: "+temp);
		
		index=index+4;
		
		temp=""+((int)(packet.data[index] & 0xff)*256+(int)(packet.data[index+1] & 0xff));
		length=((int)(packet.data[index] & 0xff)*256+(int)(packet.data[index+1] & 0xff))-1;
		resourcestring.add("Data Length: "+temp);
		
		temp="";
		index=index+3;
		if(type==0)
		{
			for(i=0;i<length;i++)
			{
				if(((int)(packet.data[index+i] & 0xff)>96 && (int)(packet.data[index+i] & 0xff)<123) || ((int)(packet.data[index+i] & 0xff)>47 && (int)(packet.data[index+i] & 0xff)<58))
				{
					temp=temp+new String(packet.data,i+index,1);
				}
				else if((int)(packet.data[index+i] & 0xff)<20)
				{
					temp=temp+".";
				}
			}
		}
		else
		{
			index=index-1;
			length=length+1;
			for(i=0;i<length;i++)
			{	
				temp=temp+(int)(packet.data[index+i] & 0xff);
				if(i!=length-1)
				{
					temp=temp+".";
				}
			}
		}
		resourcestring.add("Resource: "+temp);
		return index+i;
	}
}
	

