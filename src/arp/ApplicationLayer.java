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
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

    private static LayerManager m_LayerMgr = new LayerManager();
    public static boolean exist = false;

    String path;
    JTextArea proxyArea;

    //private static LayerManager m_LayerMgr = new LayerManager();
    int selected_index;
    private JTextField arpIPAddressTextField;

    Container contentPane;
    Container proxyContentPane;

    static JTextArea TotalArea;
    static JTextArea IPSrcAddress;
    static JTextArea EthernetSrcAddress;
    JTextArea srcMacAddress;
    JTextArea virtualIPTextArea;
    JTextArea virtualMacTextArea;

    JButton allItemDeleteButton;
    JButton arpSendButton;
    JButton itemDeleteButton;
    JButton Setting_Button;

    JLabel choice;
    JLabel lbl_Device;
    JLabel virtualMacTitle;
    JLabel virtualIPTitle;

    static JComboBox<String> NICComboBox;
    static int adapterNumber = 0;
    JComboBox strCombo;

    JComboBox<String> selectHost;

    String[] hostsName = {"Host B","Host C","Host D"};
    String host = hostsName[0];

    // Address

    FileDialog fd;
    private JTextField hardwareTextField;

    /**
     * @wbp.nonvisual location=108,504
     */
    private final JPopupMenu popupMenu = new JPopupMenu();

    public static void main(String[] args) throws IOException {
//  // TODO Auto-generated method stub
        m_LayerMgr.addLayer(new NILayer("NI"));
        m_LayerMgr.addLayer(new ApplicationLayer("APP"));
        m_LayerMgr.addLayer(new IPLayer("IP"));
        m_LayerMgr.addLayer(new ARPLayer("ARP"));
        m_LayerMgr.addLayer(new EthernetLayer("Ethernet"));

        m_LayerMgr.connectLayers(" NI ( *Ethernet ( *ARP ( *IP ( +APP ( -IP ) ) ) *IP ( +APP ( -IP ) ) ) ) ");

        System.out.println(((IPLayer) m_LayerMgr.getLayer("IP")).getUnderLayer(0).getLayerName()); // ARP
        System.out.println(((IPLayer) m_LayerMgr.getLayer("IP")).getUnderLayer(1).getLayerName()); // Ethernet
        System.out.println(((EthernetLayer)m_LayerMgr.getLayer("Ethernet")).getUpperLayer(0).getLayerName()); // ARP
        System.out.println(((EthernetLayer)m_LayerMgr.getLayer("Ethernet")).getUpperLayer(1).getLayerName()); // IP
    }

    public ApplicationLayer (String pName) {
        pLayerName = pName;

        exist = true;

        setTitle("ARP");
        setBounds(250, 250, 1450, 480);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        contentPane = this.getContentPane();
        getContentPane().setLayout(null);

        /**
         * ARP
         */
        // layer
        JPanel ARP_Cache = new JPanel();
        ARP_Cache.setBounds(14, 12, 458, 366);
        ARP_Cache.setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
        ARP_Cache.setLayout(null);
        contentPane.add(ARP_Cache);

        // ARP결과 입력창
        TotalArea = new JTextArea();
        TotalArea.setEditable(false);
        TotalArea.setBounds(14, 24, 430, 227);
        ARP_Cache.add(TotalArea);

        // cache테이블에서 원하는 주소 하나만 지우는 버튼
        itemDeleteButton = new JButton("Item Delete");
        itemDeleteButton.setBounds(35, 263, 165, 35);
        ARP_Cache.add(itemDeleteButton);
        itemDeleteButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                String delete_ip = JOptionPane.showInputDialog("Item's IP Address");
                if(delete_ip != null) {
                    if(((ARPLayer) m_LayerMgr.getLayer("ARP")).cacheTable.containsKey(delete_ip)) {
                        Object[] value = ((ARPLayer) m_LayerMgr.getLayer("ARP")).cacheTable.get(delete_ip);
                        if(System.currentTimeMillis()-(long)value[3]/1000 > 1) {
                            // cache table에서 입력한 ip주소에 해당하는 값 제거
                            ((ARPLayer) m_LayerMgr.getLayer("ARP")).cacheTable.remove(delete_ip);
                            ((ARPLayer) m_LayerMgr.getLayer("ARP")).updateARPCacheTable();
                        }
                    }
                }
            }
        });

        // cache테이블 전체 지우는 버튼
        allItemDeleteButton = new JButton("All Delete");
        allItemDeleteButton.setBounds(240, 263, 165, 35);
        ARP_Cache.add(allItemDeleteButton);
        allItemDeleteButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                Set key = ((ARPLayer) m_LayerMgr.getLayer("ARP")).cacheTable.keySet();
                ArrayList<String> deleteKey = new ArrayList<String>();
                for(Iterator iterator = key.iterator();iterator.hasNext();) {
                    String keyValue = (String)iterator.next();
                    Object[] value = ((ARPLayer) m_LayerMgr.getLayer("ARP")).cacheTable.get(keyValue);
                    if(System.currentTimeMillis()-(long)value[3]/100 <= 5) {
                        try {
                            Thread.sleep(System.currentTimeMillis()-(long)value[3]);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        deleteKey.add(keyValue);
                    } else deleteKey.add(keyValue);
                }

                // cacheTable에서 deleteKey에 담긴 키 값들을 가진 bucket 삭제
                for(int i=0;i<deleteKey.size();i++) ((ARPLayer) m_LayerMgr.getLayer("ARP")).cacheTable.remove(deleteKey.get(i));
                ((ARPLayer) m_LayerMgr.getLayer("ARP")).updateARPCacheTable();
            }
        });


        JLabel lblIp = new JLabel("IP 주소");
        lblIp.setBounds(14, 310, 56, 27);
        ARP_Cache.add(lblIp);

        // 요청 보낼 주소 입력창
        arpIPAddressTextField = new JTextField();
        arpIPAddressTextField.setBounds(71, 307, 239, 32);
        ARP_Cache.add(arpIPAddressTextField);
        arpIPAddressTextField.setColumns(10);

        // ARP 전송 버튼
        arpSendButton = new JButton("Send");
        arpSendButton.setBounds(324, 307, 107, 32);
        ARP_Cache.add(arpSendButton);
        arpSendButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                // ip주소를 입력한 경우
                if (arpIPAddressTextField.getText() != "") {
                    String input = arpIPAddressTextField.getText();
                    byte[] bytes = input.getBytes();

                    String[] ipAddr_st = input.split("\\.");
                    byte[] ipAddr_dst = new byte[4];
                    for(int i=0;i<4;i++) ipAddr_dst[i] = (byte)Integer.parseInt(ipAddr_st[i]);

                    ((IPLayer) m_LayerMgr.getLayer("IP")).SetIPDstAddress(ipAddr_dst);

                    // IP계층의 Send함수 호출
                    p_UnderLayer.send(bytes, bytes.length);

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
        JPanel Proxy_Entry = new JPanel();
        Proxy_Entry.setToolTipText("Proxy ARP Entry");
        Proxy_Entry.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
        Proxy_Entry.setBounds(486, 12, 466, 366);
        getContentPane().add(Proxy_Entry);
        Proxy_Entry.setLayout(null);

        // ARP Cache테이블 출력창
        proxyArea = new JTextArea();
        proxyArea.setEditable(false);
        proxyArea.setBounds(14, 30, 430, 173);
        Proxy_Entry.add(proxyArea);

        // 호스트 선택
        lbl_Device = new JLabel("Device");
        lbl_Device.setBounds(110, 207, 90, 30);
        Proxy_Entry.add(lbl_Device);
        selectHost = new JComboBox<String>(hostsName);
        selectHost.setBounds(200, 210, 140, 25);
        selectHost.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                // 호스트 이름 선택
                host = hostsName[selectHost.getSelectedIndex()];
            }
        });
        Proxy_Entry.add(selectHost);

        // IP주소 입력
        virtualIPTitle = new JLabel("IP 주소");
        virtualIPTitle.setBounds(110, 237, 90, 30);
        Proxy_Entry.add(virtualIPTitle);
        virtualIPTextArea = new JTextArea();
        virtualIPTextArea.setBounds(200, 245, 180, 20);
        virtualIPTextArea.setEnabled(true);
        Proxy_Entry.add(virtualIPTextArea);

        // 이더넷 주소(맥주소) 입력
        virtualMacTitle = new JLabel("Ethernet 주소");
        virtualMacTitle.setBounds(110, 270, 90, 30);
        Proxy_Entry.add(virtualMacTitle);
        virtualMacTextArea = new JTextArea();
        virtualMacTextArea.setBounds(200, 275, 180, 20);
        virtualMacTextArea.setEnabled(true);
        Proxy_Entry.add(virtualMacTextArea);

        // ARP Cache테이블에 가상의 호스트 추가 버튼
        JButton btnAdd = new JButton("Add");
        btnAdd.setBounds(42, 305, 165, 35);
        Proxy_Entry.add(btnAdd);
        btnAdd.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ARPLayer arpLayer = (ARPLayer) m_LayerMgr.getLayer("ARP");
                // ARP계층의 proxyTable을 가져온다.
                HashMap<String, Object[] > proxyTable = ((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable;

                // 빈 값이 없는지 조건검사
                // ip가 4자리, mac주소가 6자리가 아니라면 에러가 발생한다
                if (arpLayer!=null && !virtualIPTextArea.getText().equals("") && !virtualMacTextArea.getText().equals("")) {
                    String hostName = host;

                    // 입력받은 ip주소
                    StringTokenizer ipString = new StringTokenizer(virtualIPTextArea.getText(), ".");
                    byte[] ipAddress = new byte[4];
                    for (int i = 0; i < 4; i++) {
                        String ss = ipString.nextToken();
                        int s = Integer.parseInt(ss);
                        ipAddress[i] = (byte) (s & 0xFF);
                    }

                    // 입력받은 맥주소
                    StringTokenizer macString = new StringTokenizer(virtualMacTextArea.getText(), ":");
                    byte[] macAddress = new byte[6];
                    for (int i = 0; i < 6; i++) {
                        String ss = macString.nextToken();
                        int s = Integer.parseInt(ss, 16);
                        macAddress[i] = (byte) (s & 0xFF);
                    }
                    Object[] value = new Object[3];
                    value[0] = hostName;
                    value[1] = macAddress;
                    value[2] = ipAddress;

                    // proxyTable에 생성한 가상 호스트 객체를추가해준다.
                    proxyTable.put(virtualIPTextArea.getText(), value);

                    // proxy table내용을 proxyArea에 업데이트(지우고 다시 쓴다)
                    String printResult ="";
                    for(Iterator iterator = proxyTable.keySet().iterator(); iterator.hasNext();) {
                        String keyIP = (String)iterator.next();
                        Object[] obj = proxyTable.get(keyIP);
                        printResult = printResult+"    "+(String)obj[0]+"\t";
                        byte[] mac = (byte[])proxyTable.get(keyIP)[1];
                        String ip_String =keyIP;
                        String mac_String ="";


                        for(int j=0;j<5;j++) mac_String = mac_String + String.format("%X:",mac[j]);
                        mac_String = mac_String + String.format("%X",mac[5]);

                        printResult = printResult+ip_String+"\t    "+mac_String+"\n";
                    }

                    System.out.println(proxyTable.size()+"  "+printResult);
                    proxyArea.setText(printResult);
                }
            }
        });

        // ARP Cache테이블 삭제 버튼
        JButton btnDelete = new JButton("Delete");
        btnDelete.setBounds(249, 305, 165, 35);
        Proxy_Entry.add(btnDelete);
        btnDelete.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                String delete_ip = JOptionPane.showInputDialog("Host's IP Address");
                if(delete_ip != null) {
                    if(((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable.containsKey(delete_ip)) {
                        // 테이블에서 제거
                        ((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable.remove(delete_ip);

                        // 삭제 후 Proxy table 출력창 업데이트
                        // cache table은 ARP계층에 updateARPCacheTable함수가 있었지만 proxy table업데이트 함수는 없음
                        String printResult ="";
                        for(Iterator iterator = ((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable.keySet().iterator(); iterator.hasNext();) {
                            String keyIP = (String)iterator.next();
                            Object[] obj = ((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable.get(keyIP);
                            printResult = printResult+"    "+(String)obj[0]+"\t";
                            byte[] mac = (byte[])((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable.get(keyIP)[1];
                            String ip_String =keyIP;
                            String mac_String ="";

                            for(int j=0;j<5;j++) mac_String = mac_String + String.format("%X:",mac[j]);
                            mac_String = mac_String + String.format("%X",mac[5]);

                            printResult = printResult+ip_String+"\t    "+mac_String+"\n";
                        }
                        int proxySize = ((ARPLayer) m_LayerMgr.getLayer("ARP")).proxyTable.size();
                        proxyArea.setText(printResult);
                    }
                }
            }
        });

        JMenu mnNewMenu = new JMenu("New menu");
        mnNewMenu.setBounds(-206, 226, 375, 183);
        Proxy_Entry.add(mnNewMenu);

        JButton btnEnd = new JButton("종료");
        btnEnd.setBounds(16, 383, 165, 35);
        getContentPane().add(btnEnd);
        btnEnd.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                exist = false;
                dispose();
            }
        });

        /**
         * Gratuitous ARP
         */
        // layout
        JPanel GratuitousARP = new JPanel();
        GratuitousARP.setBorder(new TitledBorder(null, "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, null));
        GratuitousARP.setBounds(960, 12, 466, 83);
        getContentPane().add(GratuitousARP);
        GratuitousARP.setLayout(null);

        JLabel hwTitle = new JLabel("H/W 주소");
        hwTitle.setBounds(14, 36, 70, 18);
        GratuitousARP.add(hwTitle);

        hardwareTextField = new JTextField();
        hardwareTextField.setColumns(10);
        hardwareTextField.setBounds(83, 29, 239, 32);
        GratuitousARP.add(hardwareTextField);

        JButton garpSendButton = new JButton("Send");
        garpSendButton.setBounds(340, 29, 107, 32);
        GratuitousARP.add(garpSendButton);

        garpSendButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                // 입력값이 존재하는지 검사
                if (hardwareTextField.getText() != "") {
                    String input = hardwareTextField.getText();
                    StringTokenizer st = new StringTokenizer(input, ":");

                    // 입력받은 맥 주소가 :로 구분되는 6자리가 아니라면 에러 발생
                    byte[] hwAddress = new byte[6];
                    for (int i = 0; i < 6; i++) {
                        String ss = st.nextToken();
                        int s = Integer.parseInt(ss,16);
                        hwAddress[i] = (byte) (s & 0xFF);
                    }

                    //IP계층의 Send함수 호출
                    p_UnderLayer.send(hwAddress, hwAddress.length, "GARP");

                    // DF:DF:DF:DF:DF:DF 포맷을 만들어줌
                    String macAddress = String.format("%X:", hwAddress[0]) + String.format("%X:", hwAddress[1])
                            + String.format("%X:", hwAddress[2]) + String.format("%X:", hwAddress[3])
                            + String.format("%X:", hwAddress[4]) + String.format("%X", hwAddress[5]);

                    // SimplestDlg.serSRCAddr(macAddress);
                    if(EthernetSrcAddress.getText().compareTo("") != 0 && IPSrcAddress.getText().compareTo("") !=0) {
                        EthernetSrcAddress.setText(macAddress);
                        String[] valuesES = EthernetSrcAddress.getText().split(":");

                        byte[] Esrc = new byte[6];
                        for(int i=0;i<6;i++) {
                            Esrc[i] = (byte) Integer.parseInt(valuesES[i],16);
                        }

                        String[] valuesIS = IPSrcAddress.getText().split("\\.");

                        byte[] Isrc = new byte[4];
                        for(int i=0;i<4;i++) {
                            Isrc[i] = (byte) Integer.parseInt(valuesIS[i]);
                        }

                        ((EthernetLayer) m_LayerMgr.getLayer("Ethernet")).SetEnetSrcAddress(Esrc);
                        ((ARPLayer) m_LayerMgr.getLayer("ARP")).SetMacAddrSrcAddr(Esrc);

                        ((IPLayer) m_LayerMgr.getLayer("IP")).SetIPSrcAddress(Isrc);
                        ((ARPLayer) m_LayerMgr.getLayer("ARP")).SetIPAddrSrcAddr(Isrc);
//	        	           ((NILayer) m_LayerMgr.getLayer("NI")).SetAdapterNumber(index);
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
        JPanel addressPanel = new JPanel();
        addressPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "setting", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
        addressPanel.setBounds(960, 100, 466, 277);
        getContentPane().add(addressPanel);
        addressPanel.setLayout(null);

        // 이더넷 주소
        JLabel Elblsrc = new JLabel("Ethernet Source");
        Elblsrc.setBounds(50, 147, 170, 20);
        addressPanel.add(Elblsrc);
        EthernetSrcAddress = new JTextArea();
        EthernetSrcAddress.setBounds(150, 147, 170, 20);
        addressPanel.add(EthernetSrcAddress);

        // 하드웨어 주소 선택
        // 방법 1
        NICComboBox = new JComboBox();
        NICComboBox.setBounds(150, 110, 165, 20);
        addressPanel.add(NICComboBox);
//
//		for (int i = 0; ((NILayer) m_LayerMgr.getLayer("NI")).getAdapterList().size() > i; i++) {
//			PcapIf pcapIf = ((NILayer) m_LayerMgr.getLayer("NI")).GetAdapterObject(i);
//			NICComboBox.addItem(pcapIf.getName());
//		}
//
//		NICComboBox.addActionListener(new ActionListener() { // Event Listener
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				JComboBox jcombo = (JComboBox) e.getSource();
//				adapterNumber = jcombo.getSelectedIndex();
//				System.out.println("Index: " + adapterNumber);
//				try {
//					srcMacAddress.setText("");
//					srcMacAddress.append(get_MacAddress(((NILayer) m_LayerMgr.getLayer("NI"))
//							.GetAdapterObject(adapterNumber).getHardwareAddress()));
//
//				} catch (IOException e1) {
//					e1.printStackTrace();
//				}
//			}
//		});
//	    choice = new JLabel("NIC 선택");
//	    choice.setBounds(50, 110, 170, 20);
//	    addressPanel.add(choice);

        // 방법 2
        String[] adapterna= new String[((NILayer) m_LayerMgr.getLayer("NI")).m_pAdapterList.size()];

        for(int i=0;i<((NILayer) m_LayerMgr.getLayer("NI")).m_pAdapterList.size();i++)
            adapterna[i] = ((NILayer) m_LayerMgr.getLayer("NI")).m_pAdapterList.get(i).getDescription();

        strCombo= new JComboBox(adapterna);
        strCombo.setBounds(150, 110, 165, 20);
        strCombo.setVisible(true);
        addressPanel.add(strCombo);
        strCombo.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JComboBox cb = (JComboBox) e.getSource();
                adapterNumber = cb.getSelectedIndex();

                try {
                    byte[] mac = ((NILayer) m_LayerMgr.getLayer("NI")).m_pAdapterList.get(adapterNumber).getHardwareAddress();
                    final StringBuilder buf = new StringBuilder();
                    for(byte b:mac) {
                        if(buf.length()!=0) buf.append(":");
                        if(b>=0 && b<16) buf.append('0');
                        buf.append(Integer.toHexString((b<0)? b+256:b).toUpperCase());
                    }
                    byte[] ipSrcAddress = ((((NILayer)m_LayerMgr.getLayer("NI")).m_pAdapterList.get(adapterNumber).getAddresses()).get(0)).getAddr().getData();
                    final StringBuilder buf2 = new StringBuilder();
                    for(byte b:ipSrcAddress) {
                        if(buf2.length()!=0) buf2.append(".");
                        buf2.append(b&0xff);
                    }
                    IPSrcAddress.setText(buf2.toString());
                    EthernetSrcAddress.setText(buf.toString());
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        });

        // ip주소 입력
        JLabel myIpTitle = new JLabel("IP Source");
        myIpTitle.setBounds(50, 187, 190, 20);
        addressPanel.add(myIpTitle);

        IPSrcAddress = new JTextArea();
        IPSrcAddress.setBounds(150, 187, 170, 20);
        addressPanel.add(IPSrcAddress);

        // 자신의 ip주소와 맥주소 입력 후 설정완료 버튼
        Setting_Button = new JButton("Setting");// setting
        Setting_Button.setBounds(200, 220, 100, 20);
        addressPanel.add(Setting_Button);// setting
        Setting_Button.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                if(Setting_Button.getText() == "Setting") {

                    String srcIP = IPSrcAddress.getText();
                    if(srcIP.compareTo("") == 0) {
                        System.out.println("자신의 ip주소를 설정하지 않았습니다");
                    } else {
                        String[] valuesES = EthernetSrcAddress.getText().split(":");
                        byte[] Esrc = new byte[6];
                        for(int i=0;i<6;i++) {
                            Esrc[i] = (byte) Integer.parseInt(valuesES[i],16);
                        }

                        ((EthernetLayer) m_LayerMgr.getLayer("Ethernet")).SetEnetSrcAddress(Esrc);
                        ((ARPLayer) m_LayerMgr.getLayer("ARP")).SetMacAddrSrcAddr(Esrc);

                        String[] valuesIS = IPSrcAddress.getText().split("\\.");
                        byte[] Isrc = new byte[4];
                        for(int i=0;i<4;i++) {
                            Isrc[i] = (byte) Integer.parseInt(valuesIS[i]);
                        }

                        ((IPLayer) m_LayerMgr.getLayer("IP")).SetIPSrcAddress(Isrc);
                        ((ARPLayer) m_LayerMgr.getLayer("ARP")).SetIPAddrSrcAddr(Isrc);
                        ((NILayer) m_LayerMgr.getLayer("NI")).SetAdapterNumber(adapterNumber);

                        IPSrcAddress.setEnabled(false);
                        EthernetSrcAddress.setEnabled(false);
                        strCombo.setEnabled(false);
                        Setting_Button.setText("Reset");
                    }
                } else {
                    Setting_Button.setText("Reset");
                    EthernetSrcAddress.setEnabled(true);
                    IPSrcAddress.setEnabled(true);
                    strCombo.setEnabled(true);
                }
            }
        });

        setVisible(true);
    }


    public String get_MacAddress(byte[] byte_MacAddress) {

        String MacAddress = "";
        for (int i = 0; i < 6; i++) {
            MacAddress += String.format("%02X%s", byte_MacAddress[i], (i < MacAddress.length() - 1) ? "" : "");
            if (i != 5) {
                MacAddress += "-";
            }
        }

        System.out.println("present MAC address: " + MacAddress);
        return MacAddress;
    }

    public boolean Receive(byte[] input) {
        byte[] data = input;

        return false;
    }



    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
        // nUpperLayerCount++;
    }

    @Override
    public String getLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer getUnderLayer() {
        // TODO Auto-generated method stub
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer getUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void setUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);

    }

    @Override
    public BaseLayer getUnderLayer(int nindex) {
        return null;
    }
}