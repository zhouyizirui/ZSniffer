package grief.chartdisplay;

import grief.packetstat.PacketStat;

import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.widgets.Dialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.swtchart.*;
import org.swtchart.ISeries.SeriesType;
import org.eclipse.swt.widgets.Label;

public class ChartAnalyzer extends Dialog {

	protected Object result;
	protected Shell shell;
	public Chart networkchart;
	public Chart transportchart;
	private Label lblByIctgrief;
	
	/**
	 * Create the dialog.
	 * @param parent
	 * @param style
	 */
	public ChartAnalyzer(Shell parent, int style) {
		super(parent, style);
		setText("SWT Dialog");
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
		shell = new Shell(getParent().getDisplay());
		shell.setSize(868, 636);
		shell.setText(getText());
		
		
		transportchart=new Chart(shell, SWT.NONE);
		transportchart.setBounds(420, 20, 400, 550);
		setTransportChart();
		
		networkchart=new Chart(shell,SWT.NONE);
		networkchart.setBounds(10,20,400,550);
		
		lblByIctgrief = new Label(shell, SWT.NONE);
		lblByIctgrief.setBounds(740, 576, 80, 17);
		lblByIctgrief.setText("By ICT_Grief");
		setNetworkChart();
	}
	
	public void setNetworkChart()
	{
		Color color = new Color(Display.getDefault(), 0, 0, 0);
		
		networkchart.getAxisSet().getXAxis(0).getTitle().setText("Protocol");
		networkchart.getAxisSet().getXAxis(0).getTitle().setForeground(color);
		networkchart.getAxisSet().getYAxis(0).getTitle().setText("Percent");
		networkchart.getAxisSet().getYAxis(0).getTitle().setForeground(color);
		networkchart.getTitle().setText("Network");
		networkchart.getTitle().setForeground(color);
		
		ILegend legend = networkchart.getLegend();
		legend.setPosition(SWT.BOTTOM);
		legend.setForeground(color);
		
		IAxis xaxis=networkchart.getAxisSet().getXAxis(0);
		String [] series={"IP","IPv6","ARP","Other"};
		xaxis.setCategorySeries(series);
		xaxis.enableCategory(true);
		IAxisTick xtick=xaxis.getTick();
		xtick.setForeground(color);
		
		IAxis yaxis=networkchart.getAxisSet().getYAxis(0);
		IAxisTick ytick=yaxis.getTick();
		ytick.setForeground(color);
		
		double[] ySeries = {100*(double)(PacketStat.ippacket)/(double)(PacketStat.totalpacket),
							100*(double)(PacketStat.ipv6packet)/(double)(PacketStat.totalpacket),
							100*(double)(PacketStat.arppacket)/(double)(PacketStat.totalpacket),
							100*(double)(PacketStat.totalpacket-PacketStat.ippacket-PacketStat.arppacket-PacketStat.ipv6packet)/(double)(PacketStat.totalpacket+1)
						};
		
		IBarSeries barSeries = (IBarSeries) networkchart.getSeriesSet().createSeries(SeriesType.BAR, "type");
		barSeries.setYSeries(ySeries);
		barSeries.setBarColor(new Color(Display.getDefault(), 255, 70, 0));
		
		
		networkchart.getAxisSet().adjustRange();
		networkchart.getAxisSet().getYAxis(0).setRange(new Range(0,100));
		
	}
	
	public void setTransportChart()
	{
		Color color = new Color(Display.getDefault(), 0, 0, 0);
		
		transportchart.getAxisSet().getXAxis(0).getTitle().setText("Protocol");
		transportchart.getAxisSet().getXAxis(0).getTitle().setForeground(color);
		transportchart.getAxisSet().getYAxis(0).getTitle().setText("Percent");
		transportchart.getAxisSet().getYAxis(0).getTitle().setForeground(color);
		transportchart.getTitle().setText("Transport");
		transportchart.getTitle().setForeground(color);
		
		ILegend legend = transportchart.getLegend();
		legend.setPosition(SWT.BOTTOM);
		legend.setForeground(color);
		
		IAxis xaxis=transportchart.getAxisSet().getXAxis(0);
		String [] series={"TCP","UDP","ICMP","IGMP","Other"};
		xaxis.setCategorySeries(series);
		xaxis.enableCategory(true);
		IAxisTick xtick=xaxis.getTick();
		xtick.setForeground(color);
		
		IAxis yaxis=transportchart.getAxisSet().getYAxis(0);
		IAxisTick ytick=yaxis.getTick();
		ytick.setForeground(color);

		double[] ySeries = {100*((double)PacketStat.tcppacket/(double)PacketStat.ippacket)
							,100*((double)PacketStat.udppacket/(double)PacketStat.ippacket)
							,100*((double)PacketStat.icmppacket/(double)PacketStat.ippacket)
							,100*((double)PacketStat.igmppacket/(double)PacketStat.ippacket)
							,100*((double)(PacketStat.ippacket-(PacketStat.udppacket+PacketStat.icmppacket+PacketStat.igmppacket+PacketStat.tcppacket))/(double)(PacketStat.ippacket+1))
		
		};
		
		IBarSeries barSeries = (IBarSeries) transportchart.getSeriesSet().createSeries(SeriesType.BAR, "type");
		barSeries.setYSeries(ySeries);
		barSeries.setBarColor(new Color(Display.getDefault(), 255, 70, 0));
		
		
		transportchart.getAxisSet().adjustRange();
		transportchart.getAxisSet().getYAxis(0).setRange(new Range(0,100));
	}
	
	
	
}
