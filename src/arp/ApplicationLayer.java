package arp;

import java.awt.Color;
import java.awt.Container;
import java.awt.FileDialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;

import org.jnetpcap.PcapIf;

/**\
 * 
 * - 내 ip주소, 맥 주소 설정 시
 *   - Ethernet
 *     - SetEnetSrcAddress(맥주소)
 *   - ARP
 *     - SetMacAddrSrcAddr(맥주소)
 *     - SetIPAddrSrcAddr(ip주소)
 *   - IP
 *     - SetIPSrcAddress(ip주소)
 *   - NI
 *     - SetAdapterNumber(선택한 adapter번호)
 *
 * - ARP Cache 목적지 ip주소 설정 후 전송
 *   - IP
 *     - SetIPDstAddress(ip주소)
 *
 * - GARP 변경
 *   - Ethernet
 *     - SetEnetSrcAddress(바뀐 내 맥주소)
 *   - ARP
 *     - SetMacAddrSrcAddr(바뀐 내 맥주소)
 *     - SetIPAddrSrcAddr(기존 ip주소)
 *   - IP
 *     - SetIPSrcAddress(기존 ip주소)
 *
 */
public class ApplicationLayer extends JFrame implements BaseLayer {
	public int number_of_upper_layer = 0;
	public String present_layer_name = null;
	public BaseLayer under_layer = null;
	public ArrayList<BaseLayer> array_of_upper_layer = new ArrayList<BaseLayer>();

	private static LayerManager m_layer_mgr = new LayerManager();
	public static boolean exist = false;
	
	String path;
	String[] hosts_name = {"Host B","Host C","Host D"};
	String host = hosts_name[0];
	
	int selected_index;
	static int adapter_number = 0;
	
	private JTextField arp_ip_address_textfield;
	private JTextField hardware_textfield;

	Container content_pane;

	static JTextArea arp_textarea;
	static JTextArea ip_src_address;
	static JTextArea ethernet_src_address;
	JTextArea virtual_ip_textarea;
	JTextArea virtual_mac_textarea;
	JTextArea proxy_area;

	JButton all_item_delete_button;
	JButton arp_send_button;
	JButton item_delete_button;
	JButton my_info_setting_button;

	JLabel nic_title;
	JLabel device_title;
	JLabel virtual_mac_title;
	JLabel virtual_ip_title;
	
	static JComboBox<String> nic_combo_box;
	JComboBox str_combo;
	JComboBox<String> select_host;

	FileDialog fd;
	
  public static void main(String[] args) throws IOException {
//  // TODO Auto-generated method stub
	  	m_layer_mgr.addLayer(new NILayer("NI"));
  		m_layer_mgr.addLayer(new ApplicationLayer("APP"));
  		m_layer_mgr.addLayer(new IPLayer("IP"));
  		m_layer_mgr.addLayer(new ARPLayer("ARP"));
  		m_layer_mgr.addLayer(new EthernetLayer("Ethernet"));

  		m_layer_mgr.connectLayers(" NI ( *Ethernet ( *ARP ( *IP ( +APP ( -IP ) ) ) *IP ( +APP ( -IP ) ) ) ) ");

  		System.out.println(((IPLayer) m_layer_mgr.getLayer("IP")).GetUnderLayer(0).getLayerName()); // ARP
  		System.out.println(((IPLayer) m_layer_mgr.getLayer("IP")).GetUnderLayer(1).getLayerName()); // Ethernet
  		System.out.println(((EthernetLayer)m_layer_mgr.getLayer("Ethernet")).GetUpperLayer(0).getLayerName()); // ARP
  		System.out.println(((EthernetLayer)m_layer_mgr.getLayer("Ethernet")).GetUpperLayer(1).getLayerName()); // IP
  	}

    public ApplicationLayer (String pName) {
        present_layer_name = pName;
        
        exist = true;
        
        setTitle("ARP");
		setBounds(250, 250, 1450, 480);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		content_pane = this.getContentPane();
		getContentPane().setLayout(null);
		
		/**
         * ARP
         */
		// layer
		JPanel arp_cache_title = new JPanel();
		arp_cache_title.setBounds(14, 12, 458, 366);
		arp_cache_title.setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		arp_cache_title.setLayout(null);
		content_pane.add(arp_cache_title);

		// ARP결과 입력창
		arp_textarea = new JTextArea();
		arp_textarea.setEditable(false);
		arp_textarea.setBounds(14, 24, 430, 227);
		arp_cache_title.add(arp_textarea);
		
		// cache테이블에서 원하는 주소 하나만 지우는 버튼
		item_delete_button = new JButton("Item Delete");
		item_delete_button.setBounds(35, 263, 165, 35);
	    arp_cache_title.add(item_delete_button);
	    item_delete_button.addActionListener(new ActionListener() {
	    	public void actionPerformed(ActionEvent arg0) {
	            String delete_ip = JOptionPane.showInputDialog("Item's IP Address");
	            if(delete_ip != null) {
	            	if(((ARPLayer) m_layer_mgr.getLayer("ARP")).cacheTable.containsKey(delete_ip)) {
	            		Object[] value = ((ARPLayer) m_layer_mgr.getLayer("ARP")).cacheTable.get(delete_ip);
	            		if(System.currentTimeMillis()-(long)value[3]/1000 > 1) { 
	            			// cache table에서 입력한 ip주소에 해당하는 값 제거
	            			((ARPLayer) m_layer_mgr.getLayer("ARP")).cacheTable.remove(delete_ip);
	            			((ARPLayer) m_layer_mgr.getLayer("ARP")).updateARPCacheTable();
	            		}
	            	}
	            }
	    	}
	    });

		// cache테이블 전체 지우는 버튼
		all_item_delete_button = new JButton("All Delete");
	    all_item_delete_button.setBounds(240, 263, 165, 35);
	    arp_cache_title.add(all_item_delete_button);
	    all_item_delete_button.addActionListener(new ActionListener() {
	    	public void actionPerformed(ActionEvent arg0) {
	    		Set key = ((ARPLayer) m_layer_mgr.getLayer("ARP")).cacheTable.keySet();
	            ArrayList<String> delete_key = new ArrayList<String>();
	            for(Iterator iterator = key.iterator();iterator.hasNext();) {
	            	String key_value = (String)iterator.next();
	            	Object[] value = ((ARPLayer) m_layer_mgr.getLayer("ARP")).cacheTable.get(key_value);
	            	if(System.currentTimeMillis()-(long)value[3]/100 <= 5) {
	            		try {
	            			Thread.sleep(System.currentTimeMillis()-(long)value[3]);
	            		} catch (InterruptedException e) {
	            			e.printStackTrace();
	            		}
	            		delete_key.add(key_value);
	            	} else delete_key.add(key_value);
	            }
	            
	            // cacheTable에서 deleteKey에 담긴 키 값들을 가진 bucket 삭제
	            for(int i=0;i<delete_key.size();i++) ((ARPLayer) m_layer_mgr.getLayer("ARP")).cacheTable.remove(delete_key.get(i));
	            ((ARPLayer) m_layer_mgr.getLayer("ARP")).updateARPCacheTable();
	    	}
	    });
	    
	    
	    JLabel ip_title = new JLabel("IP 주소");
		ip_title.setBounds(14, 310, 56, 27);
		arp_cache_title.add(ip_title);
	    
		// 요청 보낼 주소 입력창
	 	arp_ip_address_textfield = new JTextField();
	 	arp_ip_address_textfield.setBounds(71, 307, 239, 32);
	 	arp_cache_title.add(arp_ip_address_textfield);
	 	arp_ip_address_textfield.setColumns(10);

	    // ARP 전송 버튼
		arp_send_button = new JButton("Send");
		arp_send_button.setBounds(324, 307, 107, 32);
		arp_cache_title.add(arp_send_button);
		arp_send_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				// ip주소를 입력한 경우
				if (arp_ip_address_textfield.getText() != "") {
					String input = arp_ip_address_textfield.getText();
					byte[] bytes = input.getBytes();

					String[] ipAddr_st = input.split("\\.");
					byte[] ipAddr_dst = new byte[4];
					for(int i=0;i<4;i++) ipAddr_dst[i] = (byte)Integer.parseInt(ipAddr_st[i]);

					((IPLayer) m_layer_mgr.getLayer("IP")).SetIPDstAddress(ipAddr_dst);
					
					// IP계층의 Send함수 호출
					under_layer.send(bytes, bytes.length);

				}
				else {
					JOptionPane.showMessageDialog(null, "ip주소를 입력해주십시오");
				}
			}
		});

		/**
		 * Proxy ARP
		 */
		// layout
		JPanel proxy_panel = new JPanel();
		proxy_panel.setToolTipText("Proxy ARP Entry");
		proxy_panel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		proxy_panel.setBounds(486, 12, 466, 366);
		getContentPane().add(proxy_panel);
		proxy_panel.setLayout(null);

		// ARP Cache테이블 출력창
		proxy_area = new JTextArea();
		proxy_area.setEditable(false);
		proxy_area.setBounds(14, 30, 430, 173);
		proxy_panel.add(proxy_area);
		
		// 호스트 선택
		device_title = new JLabel("Device");
		device_title.setBounds(110, 207, 90, 30);
		proxy_panel.add(device_title);
		select_host = new JComboBox<String>(hosts_name);
		select_host.setBounds(200, 210, 140, 25);
		select_host.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				// 호스트 이름 선택
				host = hosts_name[select_host.getSelectedIndex()];
			}
		});
		proxy_panel.add(select_host);
		
		// IP주소 입력
		virtual_ip_title = new JLabel("IP 주소");
		virtual_ip_title.setBounds(110, 237, 90, 30);
		proxy_panel.add(virtual_ip_title);
		virtual_ip_textarea = new JTextArea();
		virtual_ip_textarea.setBounds(200, 245, 180, 20);
		virtual_ip_textarea.setEnabled(true);
		proxy_panel.add(virtual_ip_textarea);
		
		// 이더넷 주소(맥주소) 입력
		virtual_mac_title = new JLabel("Ethernet 주소");
		virtual_mac_title.setBounds(110, 270, 90, 30);
		proxy_panel.add(virtual_mac_title);
		virtual_mac_textarea = new JTextArea();
		virtual_mac_textarea.setBounds(200, 275, 180, 20);
		virtual_mac_textarea.setEnabled(true);
		proxy_panel.add(virtual_mac_textarea);

		// ARP Cache테이블에 가상의 호스트 추가 버튼
		JButton btnAdd = new JButton("Add");
		btnAdd.setBounds(42, 305, 165, 35);
		proxy_panel.add(btnAdd);
		btnAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ARPLayer arpLayer = (ARPLayer) m_layer_mgr.getLayer("ARP");
				// ARP계층의 proxyTable을 가져온다.
				HashMap<String, Object[] > proxyTable = ((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable;
				
				// 빈 값이 없는지 조건검사
				// ip가 4자리, mac주소가 6자리가 아니라면 에러가 발생한다
				if (arpLayer!=null && !virtual_ip_textarea.getText().equals("") && !virtual_mac_textarea.getText().equals("")) {
					String hostName = host;
					
					// 입력받은 ip주소
					StringTokenizer ipString = new StringTokenizer(virtual_ip_textarea.getText(), ".");
					byte[] ipAddress = new byte[4];
					for (int i = 0; i < 4; i++) {
						String ss = ipString.nextToken();
						int s = Integer.parseInt(ss);
						ipAddress[i] = (byte) (s & 0xFF);
					}
					
					// 입력받은 맥주소
					StringTokenizer macString = new StringTokenizer(virtual_mac_textarea.getText(), ":");
					byte[] mac_address = new byte[6];
					for (int i = 0; i < 6; i++) {
						String ss = macString.nextToken();
						int s = Integer.parseInt(ss, 16);
						mac_address[i] = (byte) (s & 0xFF);
					}
					Object[] value = new Object[3];
					value[0] = hostName;
					value[1] = mac_address;
					value[2] = ipAddress;
					
					// proxyTable에 생성한 가상 호스트 객체를추가해준다. 
					proxyTable.put(virtual_ip_textarea.getText(), value);
					
					// proxy table내용을 proxyArea에 업데이트(지우고 다시 쓴다)
					String print_result ="";
					for(Iterator iterator = proxyTable.keySet().iterator(); iterator.hasNext();) {
						String key_ip = (String)iterator.next();
						Object[] obj = proxyTable.get(key_ip);
						print_result = print_result+"    "+(String)obj[0]+"\t";
						byte[] mac = (byte[])proxyTable.get(key_ip)[1];
						String ip_String =key_ip;
						String mac_String ="";
						

						for(int j=0;j<5;j++) mac_String = mac_String + String.format("%X:",mac[j]);
						mac_String = mac_String + String.format("%X",mac[5]);
						
						print_result = print_result+ip_String+"\t    "+mac_String+"\n";
					}

					System.out.println(proxyTable.size()+"  "+print_result);
					proxy_area.setText(print_result);
				}
			}
		});

		// ARP Cache테이블 삭제 버튼
		JButton arp_delete_button = new JButton("Delete");
		arp_delete_button.setBounds(249, 305, 165, 35);
		proxy_panel.add(arp_delete_button);
		arp_delete_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String delete_ip = JOptionPane.showInputDialog("Host's IP Address");
				if(delete_ip != null) {
					if(((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable.containsKey(delete_ip)) {
						// 테이블에서 제거
						((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable.remove(delete_ip);
						
						// 삭제 후 Proxy table 출력창 업데이트
						// cache table은 ARP계층에 updateARPCacheTable함수가 있었지만 proxy table업데이트 함수는 없음
						String print_result ="";
						for(Iterator iterator = ((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable.keySet().iterator(); iterator.hasNext();) {
							String key_ip = (String)iterator.next();
							Object[] obj = ((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable.get(key_ip);
							print_result = print_result+"    "+(String)obj[0]+"\t";
							byte[] mac = (byte[])((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable.get(key_ip)[1];
							String ip_String =key_ip;
							String mac_String ="";
							
							for(int j=0;j<5;j++) mac_String = mac_String + String.format("%X:",mac[j]);
							mac_String = mac_String + String.format("%X",mac[5]);
							
							print_result = print_result+ip_String+"\t    "+mac_String+"\n";
						}
						int proxy_size = ((ARPLayer) m_layer_mgr.getLayer("ARP")).proxyTable.size();
						proxy_area.setText(print_result);
					}
				}
			}
		});

		JMenu mn_new_menu = new JMenu("New menu");
		mn_new_menu.setBounds(-206, 226, 375, 183);
		proxy_panel.add(mn_new_menu);

		JButton close_button = new JButton("종료");  
		close_button.setBounds(16, 383, 165, 35);
		getContentPane().add(close_button);
		close_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				exist = false;
				dispose();
			}
		});

		/**
		 * Gratuitous ARP
		 */
		// layout
		JPanel garp_panel = new JPanel();
		garp_panel.setBorder(new TitledBorder(null, "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		garp_panel.setBounds(960, 12, 466, 83);
		getContentPane().add(garp_panel);
		garp_panel.setLayout(null);

		JLabel hw_title = new JLabel("H/W 주소");
		hw_title.setBounds(14, 36, 70, 18);
		garp_panel.add(hw_title);

		hardware_textfield = new JTextField();
		hardware_textfield.setColumns(10);
		hardware_textfield.setBounds(83, 29, 239, 32);
		garp_panel.add(hardware_textfield);

		JButton garp_send_button = new JButton("Send");
		garp_send_button.setBounds(340, 29, 107, 32);
		garp_panel.add(garp_send_button);
		
		garp_send_button.addActionListener(new ActionListener() {
	         public void actionPerformed(ActionEvent arg0) {
	        	 // 입력값이 존재하는지 검사
	        	 if (hardware_textfield.getText() != "") {
	        		 String input = hardware_textfield.getText();
	        		 StringTokenizer st = new StringTokenizer(input, ":");
	               
	        		 // 입력받은 맥 주소가 :로 구분되는 6자리가 아니라면 에러 발생
	        		 byte[] hwAddress = new byte[6];
	        		 for (int i = 0; i < 6; i++) {
	        			 String ss = st.nextToken();
	        			 int s = Integer.parseInt(ss,16);
	        			 hwAddress[i] = (byte) (s & 0xFF);
	        		 }
	              
	        		 //IP계층의 Send함수 호출
	        		 under_layer.send(hwAddress, hwAddress.length, "GARP");
	               
	        		 // DF:DF:DF:DF:DF:DF 포맷을 만들어줌
	        		 String mac_address = String.format("%X:", hwAddress[0]) + String.format("%X:", hwAddress[1])
	        		 + String.format("%X:", hwAddress[2]) + String.format("%X:", hwAddress[3])
	        		 + String.format("%X:", hwAddress[4]) + String.format("%X", hwAddress[5]);
	        		 
	        		 // SimplestDlg.serSRCAddr(mac_address);
	        		 if(ethernet_src_address.getText().compareTo("") != 0 && ip_src_address.getText().compareTo("") !=0) {
	        	           ethernet_src_address.setText(mac_address);
	        	           String[] values_ethernet_src = ethernet_src_address.getText().split(":");

	        	           byte[] ethernet_src = new byte[6];
	        	           for(int i=0;i<6;i++) {
	        	              ethernet_src[i] = (byte) Integer.parseInt(values_ethernet_src[i],16);
	        	           }

	        	           String[] values_ip_source = ip_src_address.getText().split("\\.");

	        	           byte[] ip_src = new byte[4];
	        	           for(int i=0;i<4;i++) {
	        	              ip_src[i] = (byte) Integer.parseInt(values_ip_source[i]);
	        	           }

	        	           ((EthernetLayer) m_layer_mgr.getLayer("Ethernet")).SetEnetSrcAddress(ethernet_src);
	        	           ((ARPLayer) m_layer_mgr.getLayer("ARP")).SetMacAddrSrcAddr(ethernet_src);

	        	           ((IPLayer) m_layer_mgr.getLayer("IP")).SetIPSrcAddress(ip_src);
	        	           ((ARPLayer) m_layer_mgr.getLayer("ARP")).SetIPAddrSrcAddr(ip_src);
//	        	           ((NILayer) m_layer_mgr.getLayer("NI")).SetAdapterNumber(adapter_number);
	        		 }
	            } else {
	               JOptionPane.showMessageDialog(null, "H_W 주소를 입력해주십시오");
	            }
	         }
	      });
		
		/**
		 * Address
		 */
		// layout
		JPanel address_panel = new JPanel();
		address_panel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "setting", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		address_panel.setBounds(960, 100, 466, 277);
	    getContentPane().add(address_panel);
	    address_panel.setLayout(null);
	    
	    // 이더넷 주소
	    JLabel Elblsrc = new JLabel("Ethernet Source");
	    Elblsrc.setBounds(50, 147, 170, 20);
	    address_panel.add(Elblsrc);
	    ethernet_src_address = new JTextArea();
	    ethernet_src_address.setBounds(150, 147, 170, 20);
	    address_panel.add(ethernet_src_address);
	    
	    // 하드웨어 주소 선택
	    // 방법 1
	    nic_combo_box = new JComboBox();
		nic_combo_box.setBounds(150, 110, 165, 20);
		address_panel.add(nic_combo_box);
//
//		for (int i = 0; ((NILayer) m_layer_mgr.getLayer("NI")).getAdapterList().size() > i; i++) {
//			PcapIf pcapIf = ((NILayer) m_layer_mgr.getLayer("NI")).GetAdapterObject(i);
//			nic_combo_box.addItem(pcapIf.getName());
//		}
//
//		nic_combo_box.addActionListener(new ActionListener() { // Event Listener
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				JComboBox jcombo = (JComboBox) e.getSource();
//				adapter_number = jcombo.getSelectedIndex();
//				System.out.println("Index: " + adapter_number);
//				try {
//					ethernet_src_address.setText("");
//					ethernet_src_address.append(get_MacAddress(((NILayer) m_layer_mgr.getLayer("NI"))
//							.GetAdapterObject(adapter_number).getHardwareAddress()));
//
//				} catch (IOException e1) {
//					e1.printStackTrace();
//				}
//			}
//		});
	    nic_title = new JLabel("NIC 선택");
	    nic_title.setBounds(50, 110, 170, 20);
	    address_panel.add(nic_title);

	    // 방법 2
	    String[] adapterna= new String[((NILayer) m_layer_mgr.getLayer("NI")).m_pAdapterList.size()];

	    for(int i=0;i<((NILayer) m_layer_mgr.getLayer("NI")).m_pAdapterList.size();i++)
	    	adapterna[i] = ((NILayer) m_layer_mgr.getLayer("NI")).m_pAdapterList.get(i).getDescription();

	    str_combo= new JComboBox(adapterna);
	    str_combo.setBounds(150, 110, 165, 20);
	    str_combo.setVisible(true);
	    address_panel.add(str_combo);
	    str_combo.addActionListener(new ActionListener() {
	    	public void actionPerformed(ActionEvent e) {
	            JComboBox cb = (JComboBox) e.getSource(); 
	            adapter_number = cb.getSelectedIndex();

	            try {
	            	byte[] mac = ((NILayer) m_layer_mgr.getLayer("NI")).m_pAdapterList.get(adapter_number).getHardwareAddress();
	            	final StringBuilder buf = new StringBuilder();
	            	for(byte b:mac) {
	            		if(buf.length()!=0) buf.append(":");
	            		if(b>=0 && b<16) buf.append('0');
	            		buf.append(Integer.toHexString((b<0)? b+256:b).toUpperCase());
	            	}
	            	byte[] ipSrcAddress = ((((NILayer)m_layer_mgr.getLayer("NI")).m_pAdapterList.get(adapter_number).getAddresses()).get(0)).getAddr().getData();
	            	final StringBuilder buf2 = new StringBuilder();
	            	for(byte b:ipSrcAddress) {
	            		if(buf2.length()!=0) buf2.append(".");
	            		buf2.append(b&0xff);
	            	}
	            	ip_src_address.setText(buf2.toString());
	            	ethernet_src_address.setText(buf.toString());
	            } catch (IOException e1) {
	            	e1.printStackTrace();
	            }
	    	}
	    });
	    
	    // ip주소 입력
	    JLabel myIpTitle = new JLabel("IP Source");
	    myIpTitle.setBounds(50, 187, 190, 20);
	    address_panel.add(myIpTitle);

	    ip_src_address = new JTextArea();
	    ip_src_address.setBounds(150, 187, 170, 20);
	    address_panel.add(ip_src_address);
	    
	    // 자신의 ip주소와 맥주소 입력 후 설정완료 버튼
	    my_info_setting_button = new JButton("Setting");// setting
		my_info_setting_button.setBounds(200, 220, 100, 20);
		address_panel.add(my_info_setting_button);// setting
		my_info_setting_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if(my_info_setting_button.getText() == "Setting") {
	        		 
					String src_ip_string = ip_src_address.getText();
		        	if(src_ip_string.compareTo("") == 0) {
		        		System.out.println("자신의 ip주소를 설정하지 않았습니다");
		        	} else {
		        		String[] values_ethernet_src = ethernet_src_address.getText().split(":");
		        		byte[] ethernet_src = new byte[6];
		        		for(int i=0;i<6;i++) {
		        			ethernet_src[i] = (byte) Integer.parseInt(values_ethernet_src[i],16);
		                }
		        		 
		        		((EthernetLayer) m_layer_mgr.getLayer("Ethernet")).SetEnetSrcAddress(ethernet_src);
		                ((ARPLayer) m_layer_mgr.getLayer("ARP")).SetMacAddrSrcAddr(ethernet_src);
		                 
		                String[] values_ip_source = ip_src_address.getText().split("\\.");
		                byte[] ip_src = new byte[4];
		                for(int i=0;i<4;i++) {
		                    ip_src[i] = (byte) Integer.parseInt(values_ip_source[i]);
		                }
		                 
		                ((IPLayer) m_layer_mgr.getLayer("IP")).SetIPSrcAddress(ip_src);
		                ((ARPLayer) m_layer_mgr.getLayer("ARP")).SetIPAddrSrcAddr(ip_src);
		                ((NILayer) m_layer_mgr.getLayer("NI")).SetAdapterNumber(adapter_number);
		                
		                ip_src_address.setEnabled(false);
		        		ethernet_src_address.setEnabled(false);
		        		str_combo.setEnabled(false);
		        		my_info_setting_button.setText("Reset");
		        	}
	        	} else {
	        		 my_info_setting_button.setText("Reset");
	        		 ethernet_src_address.setEnabled(true);
	                 ip_src_address.setEnabled(true);
	                 str_combo.setEnabled(true);
	        	}
	         }
		});
	    
		setVisible(true);
    }
    
    
    public String getMacAddress(byte[] byte_mac_address) {

		String mac_address = "";
		for (int i = 0; i < 6; i++) {
			mac_address += String.format("%02X%s", byte_mac_address[i], (i < mac_address.length() - 1) ? "" : "");
			if (i != 5) {
				mac_address += "-";
			}
		}

		System.out.println("present MAC address: " + mac_address);
		return mac_address;
	}

	public boolean receive(byte[] input) {
		byte[] data = input;

		return false;
	}



	@Override
	public void setUnderLayer(BaseLayer under_layer) {
		// TODO Auto-generated method stub
		if (under_layer == null)
			return;
		this.under_layer = under_layer;
	}

	@Override
	public void setUpperLayer(BaseLayer upper_layer) {
		// TODO Auto-generated method stub
		if (upper_layer == null)
			return;
		this.array_of_upper_layer.add(number_of_upper_layer++, upper_layer);
		// number_of_upper_layer++;
	}

	@Override
	public String getLayerName() {
		// TODO Auto-generated method stub
		return present_layer_name;
	}

	@Override
	public BaseLayer getUnderLayer() {
		// TODO Auto-generated method stub
		if (under_layer == null)
			return null;
		return under_layer;
	}

	@Override
	public BaseLayer getUpperLayer(int nindex) {
		// TODO Auto-generated method stub
		if (nindex < 0 || nindex > number_of_upper_layer || number_of_upper_layer < 0)
			return null;
		return array_of_upper_layer.get(nindex);
	}

	@Override
	public void setUpperUnderLayer(BaseLayer uu_layer) {
		this.setUpperLayer(uu_layer);
		uu_layer.setUnderLayer(this);

	}
	
	@Override
	public BaseLayer getUnderLayer(int nindex) {
		return null;
	}
}
