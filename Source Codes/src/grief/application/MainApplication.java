package grief.application;

import java.util.ArrayList;

import grief.chartdisplay.ChartAnalyzer;
import grief.configuration.Config;
import grief.dns.DnsDialog;
import grief.filehelper.FileUtils;
import grief.packetanalyzer.DetailAnalyzer;
import grief.packetanalyzer.SimpleAnalyzer;
import grief.packetcaptor.Captor;
import grief.packetstat.PacketStat;

import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.widgets.DirectoryDialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.TreeItem;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Group;
import jpcap.*;
import jpcap.packet.*;

import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.custom.StyleRange;
import org.eclipse.swt.custom.StyledText;

public class MainApplication {
	public Group group;
	public Combo combo;
	public Button applybutton;
	public Label lblInterface;
	public Label lblType;
	public Label lblIpvAddress;
	public Label lblMacAddress;
	public Label lblDescription;
	public Label lblTotal;
	public Label lblIp;
	public Label lblArp;
	public Label lblIcmp;
	public Label lblIgmp;
	public Label lblUdp;
	public Label lblTcp ;
	public Label lbltotalfilter;
	NetworkInterface[] devices=new NetworkInterface[5];
	protected Shell shell;
	public Captor captor;
	public SimpleAnalyzer simpleanalyzer;
	public DetailAnalyzer detailanalyzer;
	private Button btnPa;
	public Button btnStart;
	public Label lblFilter ;
	private Text filtertext;
	private Table table;
	public TableColumn tblclmnNo;
	public TableColumn tblclmnNetwork;
	public TableColumn tblclmnLength;
	public TableColumn tblclmnTime;
	public TableColumn tblclmnSource; 
	public TableColumn tblclmnDestination; 
	public TableColumn tblclmnData;
	private CaptureThread capturethread; 
	private DisplayThread displaythread;
	private Runnable runnable;
	private Button btnStop;
	private Label lblSavePath;
	private Text pathtext;
	private Button btnfilepath;
	private Button btnClearAll;
	private TableColumn tblclmnTransport;
	public ArrayList<Packet> packets=new ArrayList<Packet>();
	public int displaypacketindex=0;
	private Text addfiltertext;
	private Text portfiltertext;
	private Label lblIpv;
	private StyledText styledText ;
	private Tree tree;
	private TreeItem roottree;
	private TreeItem treeitem;
	public int laststart;
	public int lastoffset;
	public Button btnSave;
	public Button btnChart;
	public Button btnImport;
	public boolean firstclick=true;
	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			MainApplication window = new MainApplication();
			window.open();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Open the window.
	 */
	public void open() {
		Display display = Display.getDefault();
		createContents();
		shell.open();
		shell.layout();
		initialApplication();
		
		
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}
	/**
	 * Create contents of the window.
	 */
	public void createContents() {
		shell = new Shell();
		shell.setSize(1100, 687);
		shell.setText("Sniffer");
		
		group = new Group(shell, SWT.NONE);
		group.setBounds(10, 10, 322, 334);
		group.setText("Configuration");
		
		combo = new Combo(group, SWT.NONE);
		combo.setBounds(68, 31, 244, 25);
		//combo.addSelectionListener(listener);
		
		lblInterface = new Label(group, SWT.NONE);
		lblInterface.setBounds(8, 34, 54, 17);
		lblInterface.setText("Interface:");
		
		applybutton = new Button(group, SWT.NONE);
		applybutton.setBounds(26, 297, 61, 27);
		applybutton.setText("Apply");
		applybutton.addSelectionListener(new ApplyClickListener());
		
		lblDescription = new Label(group, SWT.NONE);
		lblDescription.setText("Description:");
		lblDescription.setBounds(8, 184, 304, 17);
		
		lblType = new Label(group, SWT.NONE);
		lblType.setBounds(8, 207, 304, 17);
		lblType.setText("Type:");
		
		lblIpvAddress = new Label(group, SWT.NONE);
		lblIpvAddress.setText("IPV4 Address:");
		lblIpvAddress.setBounds(8, 230, 304, 17);
		
		lblMacAddress = new Label(group, SWT.NONE);
		lblMacAddress.setText("MAC Address:");
		lblMacAddress.setBounds(8, 253, 304, 17);
		
		btnPa = new Button(group, SWT.CHECK);
		btnPa.setBounds(214, 161, 98, 17);
		btnPa.setText("Promiscuous");
		
		lblFilter= new Label(group, SWT.NONE);
		lblFilter.setBounds(8, 65, 54, 17);
		lblFilter.setText("CapFilter:");
		
		filtertext = new Text(group, SWT.BORDER);
		filtertext.setBounds(68, 62, 244, 23);
		
		btnStart = new Button(group, SWT.NONE);
		btnStart.setBounds(93, 297, 63, 27);
		btnStart.setText("Start");
		btnStart.setEnabled(false);
		btnStart.addSelectionListener(new StartClickListener());
		
		btnStop = new Button(group, SWT.NONE);
		btnStop.setBounds(167, 297, 61, 27);
		btnStop.setText("Stop");
		btnStop.setEnabled(false);
		btnStop.addSelectionListener(new StopClickListener());
		
		lblSavePath = new Label(group, SWT.NONE);
		lblSavePath.setBounds(8, 135, 54, 17);
		lblSavePath.setText("SavePath:");
		
		pathtext = new Text(group, SWT.BORDER);
		pathtext.setBounds(68, 132, 217, 23);
		
		btnfilepath = new Button(group, SWT.NONE);
		btnfilepath.setBounds(291, 130, 21, 27);
		btnfilepath.setText("...");
		btnfilepath.addSelectionListener(new PathClickListener());
		
		btnClearAll = new Button(group, SWT.NONE);
		btnClearAll.setBounds(234, 297, 61, 27);
		btnClearAll.setEnabled(false);
		btnClearAll.setText("Clear");
		btnClearAll.addSelectionListener(new ClearClickListener());
		
		
		Label lblIpfilter = new Label(group, SWT.NONE);
		lblIpfilter.setBounds(8, 97, 54, 17);
		lblIpfilter.setText("AddFilter:");
		
		addfiltertext = new Text(group, SWT.BORDER);
		addfiltertext.setBounds(68, 94, 112, 23);
		
		Label lblPortfilter = new Label(group, SWT.NONE);
		lblPortfilter.setBounds(186, 97, 54, 17);
		lblPortfilter.setText("PortFilter:");
		
		portfiltertext = new Text(group, SWT.BORDER);
		portfiltertext.setBounds(246, 94, 66, 23);
		
		lbltotalfilter = new Label(group, SWT.NONE);
		lbltotalfilter.setBounds(8, 274, 304, 17);
		lbltotalfilter.setText("Filter:");
		
		Group grpPackets = new Group(shell, SWT.NONE);
		grpPackets.setText("Packets");
		grpPackets.setBounds(338, 10, 736, 334);
		
		table = new Table(grpPackets, SWT.BORDER | SWT.FULL_SELECTION);
		table.setBounds(10, 21, 716, 305);
		table.setHeaderVisible(true);
		table.setLinesVisible(true);
		table.addSelectionListener(new TableItemSelectListener());
		
		tblclmnNo = new TableColumn(table, SWT.NONE);
		tblclmnNo.setWidth(52);
		tblclmnNo.setText("No");
		
		tblclmnNetwork = new TableColumn(table, SWT.NONE);
		tblclmnNetwork.setWidth(66);
		tblclmnNetwork.setText("Network");
		
		tblclmnTransport = new TableColumn(table, SWT.NONE);
		tblclmnTransport.setWidth(74);
		tblclmnTransport.setText("Transport");
		
		tblclmnLength = new TableColumn(table, SWT.NONE);
		tblclmnLength.setWidth(52);
		tblclmnLength.setText("Length");
		
		tblclmnTime= new TableColumn(table, SWT.NONE);
		tblclmnTime.setWidth(62);
		tblclmnTime.setText("Time");
		
		tblclmnSource= new TableColumn(table, SWT.NONE);
		tblclmnSource.setWidth(143);
		tblclmnSource.setText("Source");
		
		tblclmnDestination= new TableColumn(table, SWT.NONE);
		tblclmnDestination.setWidth(147);
		tblclmnDestination.setText("Destination");
		
		tblclmnData= new TableColumn(table, SWT.NONE);
		tblclmnData.setWidth(76);
		tblclmnData.setText("Data");
		
		Group grpAnalysis = new Group(shell, SWT.NONE);
		grpAnalysis.setText("Analysis");
		grpAnalysis.setBounds(338, 350, 736, 289);
		
		tree= new Tree(grpAnalysis, SWT.BORDER);
		tree.setBounds(10, 21, 264, 258);
		tree.addListener(SWT.MouseDoubleClick,new Listener(){

			@Override
			public void handleEvent(Event e) {
				// TODO Auto-generated method stub
				TreeItem treeitem=tree.getItem(new Point(e.x,e.y));
				if(treeitem!=null)
				{
					String str=treeitem.getText();
					if(str.equals("More Information"))
					{
						new DnsDialog(shell, SWT.DIALOG_TRIM  | SWT.APPLICATION_MODAL).open();
					}
				}
			}
			
		});
		
		styledText= new StyledText(grpAnalysis, SWT.BORDER | SWT.V_SCROLL | SWT.MULTI );
		styledText.setBounds(280, 21, 446, 258);
		styledText.addSelectionListener(new HexTextSelectionListener());
		
		Group grpStatistic = new Group(shell, SWT.NONE);
		grpStatistic.setText("Statistic");
		grpStatistic.setBounds(10, 350, 322, 289);
		
		lblTotal = new Label(grpStatistic, SWT.NONE);
		lblTotal.setBounds(45, 50, 79, 17);
		lblTotal.setText("Frame: 0");
		
		lblIp= new Label(grpStatistic, SWT.NONE);
		lblIp.setBounds(45, 119, 79, 17);
		lblIp.setText("IP: 0");
		
		lblArp= new Label(grpStatistic, SWT.NONE);
		lblArp.setBounds(45, 96, 79, 17);
		lblArp.setText("ARP: 0");
		
		lblIcmp= new Label(grpStatistic, SWT.NONE);
		lblIcmp.setBounds(45, 234, 79, 17);
		lblIcmp.setText("ICMP: 0");
		
		lblIgmp = new Label(grpStatistic, SWT.NONE);
		lblIgmp.setBounds(45, 257, 79, 17);
		lblIgmp.setText("IGMP: 0");
		
		lblUdp= new Label(grpStatistic, SWT.NONE);
		lblUdp.setBounds(45, 211, 79, 17);
		lblUdp.setText("UDP: 0");
		
		lblTcp= new Label(grpStatistic, SWT.NONE);
		lblTcp.setBounds(45, 188, 79, 17);
		lblTcp.setText("TCP: 0");
		
		lblIpv = new Label(grpStatistic, SWT.NONE);
		lblIpv.setBounds(45, 142, 79, 17);
		lblIpv.setText("IPv6: 0");
		
		Label lblNewLabel = new Label(grpStatistic, SWT.NONE);
		lblNewLabel.setBounds(22, 73, 91, 17);
		lblNewLabel.setText("Network layer");
		
		Label lblDatalinkLayer = new Label(grpStatistic, SWT.NONE);
		lblDatalinkLayer.setBounds(22, 27, 91, 17);
		lblDatalinkLayer.setText("Datalink layer");
		
		Label lblTransportLayer = new Label(grpStatistic, SWT.NONE);
		lblTransportLayer.setText("Transport layer");
		lblTransportLayer.setBounds(22, 165, 102, 17);
		
		btnSave = new Button(grpStatistic, SWT.NONE);
		btnSave.setBounds(218, 121, 80, 27);
		btnSave.setText("Save");
		btnSave.addSelectionListener(new SaveClickListener());
		btnSave.setEnabled(false);
		
		btnChart= new Button(grpStatistic, SWT.NONE);
		btnChart.setBounds(218, 213, 80, 27);
		btnChart.setText("Chart");
		btnChart.addSelectionListener(new ChartClickListner());
		
		btnImport= new Button(grpStatistic, SWT.NONE);
		btnImport.setBounds(218, 167, 80, 27);
		btnImport.setText("Import");
		btnImport.addSelectionListener(new ImportClickListener());
	}
	public void initialApplication()
	{
		getDevices();
	}
	public void getDevices()
	{
		
		try 
		{
			devices=JpcapCaptor.getDeviceList();			
		}
		catch(Exception e)
		{
			
		}
		for(int i=0;i<devices.length;i++)
		{
			combo.add(devices[i].description);
			combo.select(0);
		}
	}
	
	public void displaypacket()
	{	
		if(displaypacketindex<packets.size())
		{	
		runnable=new Runnable(){

			@Override
			public void run() {
				 //TODO Auto-generated method stub
				if(displaypacketindex<packets.size())
				{
					simpleanalyzer=new SimpleAnalyzer();
					simpleanalyzer.simpleanalysis((Packet)packets.get(displaypacketindex),displaypacketindex);
					
			
					if(!Config.addfilter.equals("") && Config.portfilter.equals(""))
						{
							if(( Config.addfilter.equals(simpleanalyzer.getSource()) || Config.addfilter.equals(simpleanalyzer.getDestination())) && !simpleanalyzer.isIsmac() )
							{
								TableItem tableItem= new TableItem(table, SWT.NONE);
								tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
										simpleanalyzer.getSource()+":"+simpleanalyzer.getSourceport(),simpleanalyzer.getDestination()+":"+simpleanalyzer.getDestport(),simpleanalyzer.getData() });
							}
						}
					else if(!Config.portfilter.equals("") && Config.addfilter.equals(""))
						{
							if(( Config.portfilter.equals(simpleanalyzer.getSourceport()) || Config.portfilter.equals(simpleanalyzer.getDestport())) && !simpleanalyzer.isIsmac())
							{
								TableItem tableItem= new TableItem(table, SWT.NONE);
								tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
										simpleanalyzer.getSource()+":"+simpleanalyzer.getSourceport(),simpleanalyzer.getDestination()+":"+simpleanalyzer.getDestport(),simpleanalyzer.getData() });
							}
						}
					
					else if(!Config.portfilter.equals("") && !Config.addfilter.equals(""))
					{
						if((Config.portfilter.equals(simpleanalyzer.getSourceport()) || Config.portfilter.equals(simpleanalyzer.getDestport())) && 
								(Config.addfilter.equals(simpleanalyzer.getSource()) || Config.addfilter.equals(simpleanalyzer.getDestination()))  && !simpleanalyzer.isIsmac() )
						{
							TableItem tableItem= new TableItem(table, SWT.NONE);
							tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
									simpleanalyzer.getSource()+":"+simpleanalyzer.getSourceport(),simpleanalyzer.getDestination()+":"+simpleanalyzer.getDestport(),simpleanalyzer.getData() });
						}
					}
					else
					{
						if(!simpleanalyzer.isIsmac())
						{
							TableItem tableItem= new TableItem(table, SWT.NONE);
							tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
							simpleanalyzer.getSource()+":"+simpleanalyzer.getSourceport(),simpleanalyzer.getDestination()+":"+simpleanalyzer.getDestport(),simpleanalyzer.getData() });
						}
						else
						{
							TableItem tableItem= new TableItem(table, SWT.NONE);
							tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
							simpleanalyzer.getSource(),simpleanalyzer.getDestination(),simpleanalyzer.getData() });
						}
					}
					displaypacketindex++;
					lblTotal.setText("Frame: "+PacketStat.totalpacket);
					lblIp.setText("IP: "+PacketStat.ippacket);
					lblIcmp.setText("ICMP: "+PacketStat.icmppacket);
					lblIgmp.setText("IGMP: "+PacketStat.igmppacket);
					lblArp.setText("ARP: "+PacketStat.arppacket);
					lblUdp.setText("UDP: "+PacketStat.udppacket);
					lblTcp.setText("TCP: "+PacketStat.tcppacket);
					lblIpv.setText("IPv6: "+PacketStat.ipv6packet);
							
				}
			}
			
		};
		Display.getDefault().asyncExec(runnable);	
		
		}
		
	}
	
	
	public boolean isDisplayPacket(int packetindex)
	{
		boolean retval=false;
		Packet packet=packets.get(packetindex);
		byte [] packethead=new byte[packet.header.length];
		if((int)(packethead[13] & 0xff)==6)
		{
			if(!Config.addfilter.equals("") || !Config.portfilter.equals(""))
			{
			}
		}
		return retval;

	}
	
	public void displayImportPacket()
	{
		SimpleAnalyzer simpleanalyzer=new SimpleAnalyzer();
		for(int i=0;i<packets.size();i++)
		{
			simpleanalyzer.simpleanalysis(packets.get(i), i);
			if(simpleanalyzer.isIsmac())
			{
				TableItem tableItem= new TableItem(table, SWT.NONE);
				tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
				simpleanalyzer.getSource(),simpleanalyzer.getDestination(),simpleanalyzer.getData() });
			}
			else
			{
				TableItem tableItem= new TableItem(table, SWT.NONE);
				tableItem.setText( new String[]{simpleanalyzer.getNo()+"",simpleanalyzer.getNetwork(),simpleanalyzer.getTransport(),simpleanalyzer.getLength()+"",simpleanalyzer.getTime(),
				simpleanalyzer.getSource()+":"+simpleanalyzer.getSourceport(),simpleanalyzer.getDestination()+":"+simpleanalyzer.getDestport(),simpleanalyzer.getData() });
			}
		}
		
	}
	public int reddisplay(int hexdisplay)
	{
		int retval;
		retval=40+60*(hexdisplay/60)+2*(((hexdisplay%60)-8)/3);
		return retval;
	}
	public int redoffset(int hexoffset)
	{
		int retval=0;
		return retval;
	}
	
	public void clearArguments()
	{
		table.removeAll();
		tree.removeAll();
		packets.removeAll(packets);
		packets.clear();
		styledText.setText("");
		displaypacketindex=0;
		
		PacketStat.arppacket=0;
		PacketStat.icmppacket=0;
		PacketStat.igmppacket=0;
		PacketStat.ippacket=0;
		PacketStat.ipv6packet=0;
		PacketStat.tcppacket=0;
		PacketStat.totalpacket=0;
		PacketStat.udppacket=0;
		
		lblTotal.setText("Frame: "+PacketStat.totalpacket);
		lblIp.setText("IP: "+PacketStat.ippacket);
		lblIcmp.setText("ICMP: "+PacketStat.icmppacket);
		lblIgmp.setText("IGMP: "+PacketStat.igmppacket);
		lblArp.setText("ARP: "+PacketStat.arppacket);
		lblUdp.setText("UDP: "+PacketStat.udppacket);
		lblTcp.setText("TCP: "+PacketStat.tcppacket);
		lblIpv.setText("IPv6: "+PacketStat.ipv6packet);
		
	}
	
	public void setfilterlabel()
	{
		String filter;
		String add;
		String port;
		
		if(Config.filter.equals(""))
		{
			filter="null";
		}
		else
		{
			filter=Config.filter;
		}
		
		if(Config.addfilter.equals(""))
		{
			add="null";
		}
		else
		{
			add=Config.addfilter;
		}		
		
		if(Config.portfilter.equals(""))
		{
			port="null";
		}
		else
		{
			port=Config.portfilter;
		}
		
		lbltotalfilter.setText("Filter: "+filter+" AND "+add+" AND "+port);
	}
	
	class CaptureThread extends Thread
	{
		@Override
		public void run() {
			// TODO Auto-generated method stub
			super.run();
			
			while(!this.isInterrupted())
			{
				captor.startCapture();
				packets=captor.getPackets();
			}
			if(this.isInterrupted())
			{
				captor.stopCapture();
			}
		}
	}
	
	class DisplayThread extends Thread
	{

		@Override
		public void run() {
			// TODO Auto-generated method stub
			super.run();
			while(!this.isInterrupted())
			{
				if(displaypacketindex<packets.size())
				{
					displaypacket();
				}
				
			}
			if(this.isInterrupted())
			{
			}
		}
		
	}
	
	
	class PathClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			DirectoryDialog dialog=new DirectoryDialog(shell);
			dialog.setMessage("选择要保存的文件夹");
			dialog.setText("选择目录");
			dialog.setFilterPath("C:\\");
			String filepath=dialog.open();
			if(filepath!=null)
			{
				pathtext.setText(filepath);
			}
		}
		
	}
	
	class ChartClickListner implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			new ChartAnalyzer(shell, SWT.APPLICATION_MODAL | SWT.DIALOG_TRIM  ).open();
			//Chart chart=new Chart(shell, SWT.NONE);
		}
		
	}
	
	class SaveClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
			if(!Config.savepath.equals(""))
			{
				if(MessageDialog.openConfirm(shell, "保存信息", "是否将数据包和报告保存到"+Config.savepath+"?"))	
				{
					FileUtils utils=new FileUtils();
					utils.getReport();
					utils.writeReportFile();
					utils.writePackets(packets);
					
				}
			}
			else
			{
				MessageBox messagebox=new MessageBox(shell, SWT.ICON_WARNING);
				messagebox.setText("注意");
				messagebox.setMessage("没有指定存储路径");
				messagebox.open();
			}
		}
		
	}
	
	class ImportClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			clearArguments();
			FileDialog filedialog=new FileDialog(shell, SWT.OPEN);
			filedialog.setText("打开");
			filedialog.setFilterPath(Config.savepath);
			String [] filefilter={"*.dat"};
			filedialog.setFilterExtensions(filefilter);
			String selected=filedialog.open();
			if(selected!=null)
			{
				FileUtils utils=new FileUtils();
				packets=utils.readPackets(selected);
				if(packets.size()==0)
				{
					MessageBox messagebox=new MessageBox(shell,SWT.ICON_ERROR);
					messagebox.setText("读取错误");
					messagebox.setMessage("不是数据包文件，请重新选择!");
					messagebox.open();
				}
				else
				{
					displayImportPacket();
					btnClearAll.setEnabled(true);
					lblTotal.setText("Frame: "+PacketStat.totalpacket);
					lblIp.setText("IP: "+PacketStat.ippacket);
					lblIcmp.setText("ICMP: "+PacketStat.icmppacket);
					lblIgmp.setText("IGMP: "+PacketStat.igmppacket);
					lblArp.setText("ARP: "+PacketStat.arppacket);
					lblUdp.setText("UDP: "+PacketStat.udppacket);
					lblTcp.setText("TCP: "+PacketStat.tcppacket);
					lblIpv.setText("IPv6: "+PacketStat.ipv6packet);
				}
			}
			
		}
		
	}
	
	class ApplyClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
		
			int index=combo.getSelectionIndex();
			String IPv4address=new String();	
			String MACaddress=new String();
			
			for(int i=0;i<devices[index].mac_address.length;i++)
			{
				MACaddress=MACaddress+Integer.toHexString(devices[index].mac_address[i] & 0xff);
				if(i!=devices[index].mac_address.length-1)
				{
					MACaddress=MACaddress+"-";
				}
			}
			
			for(NetworkInterfaceAddress add : devices[index].addresses)
				{
					if(add.address.toString().length()<17)
					{
						IPv4address=add.address.toString();
						IPv4address=IPv4address.substring(1, IPv4address.length());
					}
				}
			lblDescription.setText("Description:  "+devices[index].description);
			lblType.setText("Type: "+devices[index].datalink_description);
			lblIpvAddress.setText("IPV4 Address:  "+IPv4address);
			lblMacAddress.setText("MAC Address:  "+MACaddress);
			
			
			Config.deviceindex=index;
			Config.DatalinkType=devices[index].datalink_description;
			Config.Interface=devices[index].description;
			Config.Ipv4Address=IPv4address;
			Config.MacAddress=MACaddress;
			Config.isromiscuous=btnPa.getSelection();
			Config.filter=filtertext.getText();
			Config.savepath=pathtext.getText();
			Config.addfilter=addfiltertext.getText();
			Config.portfilter=portfiltertext.getText();
			
			
			setfilterlabel();
			
			
			if(btnPa.getSelection()==true)
			{
				Config.isromiscuous=true;
			}
			else
			{
				Config.isromiscuous=false;
			}
			
			btnStart.setEnabled(true);
			
		}
	}
	class StartClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			clearArguments();
			captor=new Captor(devices, Config.deviceindex);
			captor.initialCaptor();
			displaypacketindex=0;
			capturethread=new CaptureThread();
			displaythread=new DisplayThread();
			capturethread.start();
			displaythread.start();
			btnStop.setEnabled(true);
			btnClearAll.setEnabled(true);
			btnStart.setEnabled(false);
			btnSave.setEnabled(false);
		}
		
	}
	class StopClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			capturethread.interrupt();
			displaythread.interrupt(); 
			capturethread=null;
			displaythread=null;
			btnStart.setEnabled(true);
			btnStop.setEnabled(false);
			btnSave.setEnabled(true);
			firstclick=false;
		}
		
	}
	class ClearClickListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			clearArguments();
			
			//table.clearAll();
		}
		
	}
	class TableItemSelectListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			styledText.setText("");
			int tableitem=table.getSelectionIndex();
			TableItem item=table.getItem(tableitem);
			Font font=new Font(Display.getDefault(), "幼圆", 10, SWT.NORMAL);
			detailanalyzer=new DetailAnalyzer();
			detailanalyzer.analysisBinary(packets.get(Integer.parseInt(item.getText(0))));
			System.err.println(""+Integer.parseInt(item.getText(0))+"   "+packets.size());
			styledText.setText(detailanalyzer.getHexstringbuffer().toString());
			styledText.setFont(font);
			
			tree.removeAll();

			
			if(detailanalyzer.getAnalysislayer()!=0)
			{
				roottree=new TreeItem(tree, SWT.NULL); //Display frame information
				roottree.setText("Frame");
				
				for(int i=0;i<detailanalyzer.getFramestring().size();i++)
				{
					treeitem=new TreeItem(roottree,SWT.NULL);
					treeitem.setText(detailanalyzer.getFramestring().get(i));
				}
				
				roottree=new TreeItem(tree, SWT.NULL);  //Display ethernet information
				roottree.setText("Ethernet");

				
				for(int i=0;i<detailanalyzer.getEthernetstring().size();i++)
				{
					treeitem=new TreeItem(roottree,SWT.NULL);
					treeitem.setText(detailanalyzer.getEthernetstring().get(i));
				}
				
				if(detailanalyzer.getAnalysislayer()>=3)
				{
					roottree=new TreeItem(tree, SWT.NULL);  //Display ethernet information
					roottree.setText("Network");
					
					for(int i=0;i<detailanalyzer.getNetworkstring().size();i++)
					{
						treeitem=new TreeItem(roottree,SWT.NULL);
						treeitem.setText(detailanalyzer.getNetworkstring().get(i));
					}
					
					if(detailanalyzer.getAnalysislayer()>=4)
					{
						roottree=new TreeItem(tree, SWT.NULL);  //Display ethernet information
						roottree.setText("Transport");
						
						for(int i=0;i<detailanalyzer.getTransportstring().size();i++)
						{
							treeitem=new TreeItem(roottree,SWT.NULL);
							treeitem.setText(detailanalyzer.getTransportstring().get(i));
						}
						if(detailanalyzer.getAnalysislayer()>=5)
						{
							roottree=new TreeItem(tree, SWT.NULL);  //Display ethernet information
							roottree.setText("Dns");
							
							treeitem=new TreeItem(roottree,SWT.NULL);
							treeitem.setText("More Information");
						}
						
					}
				}
			}			 
			tree.setFont(font);
		}
		
	}
	
	
	class HexTextSelectionListener implements SelectionListener
	{

		@Override
		public void widgetDefaultSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void widgetSelected(SelectionEvent arg0) {
			// TODO Auto-generated method stub
			int hexstart;
			int hexoffset;

			StyleRange stylerange;
			if(styledText.getSelectionRange().y!=0 && styledText.getSelectionRange().y<30 && (styledText.getSelectionRange().x+styledText.getSelectionRange().y)%60<40)
			{
				hexstart=styledText.getSelectionRange().x;
				hexoffset=styledText.getSelectionRange().y;
				laststart=reddisplay(hexstart);
				lastoffset=((hexoffset+1)/3)*2;
				stylerange=new StyleRange(laststart,lastoffset , shell.getDisplay().getSystemColor(SWT.COLOR_BLACK), shell.getDisplay().getSystemColor(SWT.COLOR_RED));
				styledText.setStyleRange(stylerange);
			}
			
			if(styledText.getSelectionRange().y==0)
			{
				stylerange=new StyleRange(laststart,lastoffset, shell.getDisplay().getSystemColor(SWT.COLOR_BLACK), shell.getDisplay().getSystemColor(SWT.COLOR_WHITE));
				styledText.setStyleRange(stylerange);
			}

		}
		
	}
}

