package arp;

import java.util.ArrayList;
import java.util.Arrays;

public class EthernetLayer implements BaseLayer {
    public int n_upper_layer_count = 0;
    public String p_layer_name = null;
    public BaseLayer p_under_layer = null;
    public ArrayList<BaseLayer> p_upper_layer = new ArrayList<BaseLayer>();
    public final static int HEARER_SIZE = 14;
    private static byte[] arp_mac_dstaddr = null;

    public byte[] chat_file_dstaddr;
    public byte[] ex_ethernetaddr = new byte[6];

    private class _ETHERNET_ADDR {
        private byte[] addr = new byte[6];

        public _ETHERNET_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
            this.addr[4] = (byte) 0x00;
            this.addr[5] = (byte) 0x00;
        }
    }

    private class _ETHERNET_HEADER {
        _ETHERNET_ADDR enet_dstaddr;
        _ETHERNET_ADDR enet_srcaddr;
        byte[] enet_type;
        byte[] enet_data;

        public _ETHERNET_HEADER() {
            this.enet_dstaddr = new _ETHERNET_ADDR();
            this.enet_srcaddr = new _ETHERNET_ADDR();
            this.enet_type = new byte[2];
            this.enet_data = null;
        }
    }

    _ETHERNET_HEADER m_sHeader = new _ETHERNET_HEADER();

    public EthernetLayer(String pName) {
        // super(pName);
        // TODO Auto-generated constructor stub
        p_layer_name = pName;

    }

    public void setEnetSrcAddress(byte[] srcAddress) {
        // TODO Auto-generated method stub
        m_sHeader.enet_srcaddr.addr[0] = srcAddress[0];
        m_sHeader.enet_srcaddr.addr[1] = srcAddress[1];
        m_sHeader.enet_srcaddr.addr[2] = srcAddress[2];
        m_sHeader.enet_srcaddr.addr[3] = srcAddress[3];
        m_sHeader.enet_srcaddr.addr[4] = srcAddress[4];
        m_sHeader.enet_srcaddr.addr[5] = srcAddress[5];

    }

    public void setEnetDstAddress(byte[] dstAddress) {
        // TODO Auto-generated method stub
        m_sHeader.enet_dstaddr.addr[0] = dstAddress[0];
        m_sHeader.enet_dstaddr.addr[1] = dstAddress[1];
        m_sHeader.enet_dstaddr.addr[2] = dstAddress[2];
        m_sHeader.enet_dstaddr.addr[3] = dstAddress[3];
        m_sHeader.enet_dstaddr.addr[4] = dstAddress[4];
        m_sHeader.enet_dstaddr.addr[5] = dstAddress[5];

    }

    public static void setMacAddrDstAddr(byte[] dstAddress) {
        arp_mac_dstaddr = dstAddress;
    }

    public byte[] ObjToByteDATA(_ETHERNET_HEADER Header, byte[] input, int length) {
        byte[] buf = new byte[length + HEARER_SIZE];

        buf[0] = Header.enet_dstaddr.addr[0];
        buf[1] = Header.enet_dstaddr.addr[1];
        buf[2] = Header.enet_dstaddr.addr[2];
        buf[3] = Header.enet_dstaddr.addr[3];
        buf[4] = Header.enet_dstaddr.addr[4];
        buf[5] = Header.enet_dstaddr.addr[5];
        buf[6] = Header.enet_srcaddr.addr[0];
        buf[7] = Header.enet_srcaddr.addr[1];
        buf[8] = Header.enet_srcaddr.addr[2];
        buf[9] = Header.enet_srcaddr.addr[3];
        buf[10] = Header.enet_srcaddr.addr[4];
        buf[11] = Header.enet_srcaddr.addr[5];
        buf[12] = Header.enet_type[0];
        buf[13] = Header.enet_type[1];

        for (int i = 0; i < length; i++) {
            buf[HEARER_SIZE + i] = input[i];
        }
        return buf;
    }

    public boolean send(byte[] input, int length) {
        m_sHeader.enet_data = input;
        if (m_sHeader.enet_data.length > 1500)
            return false;
        byte[] frame;   //(Header + input)전체 frame
        if(input[6] == 0x00 && input[7] == 0x03){   //(이게 맞나 싶음), IP에서 왔을 때
            m_sHeader.enet_type[0] = (byte) 0x08;
            m_sHeader.enet_type[1] = (byte) 0x00;   //상위 프로토콜 설정(ARP)

            m_sHeader.enet_dstaddr.addr = ((IPLayer)getUpperLayer(1)).chatDST_mac; //목적지 mac주소
            frame = ObjToByteDATA(m_sHeader, input, length);

//            byte[] dst_mac_frame = Arrays.copyOfRange(frame, 0, 6);
//            String dst_mac_addr = macByteArrToString(dst_mac_frame);        //목적지 mac주소
//            byte[] src_mac_frame = Arrays.copyOfRange(frame, 6, 12);
//            String src_mac_addr = macByteArrToString(src_mac_frame);        //출발지 mac주소
//              주소를 화면에 출력하는 경우 필요함
        } else{                                     //ARP일 때
            m_sHeader.enet_type[0] = (byte) 0x08;
            m_sHeader.enet_type[1] = (byte) 0x06;   //상위 프로토콜 설정(ARP)

            if (input[6] == 0x00 && input[7] == 0x01) {         //ARP요청
                byte[] dst_addr = new byte[6];
                Arrays.fill(dst_addr, (byte) 0xff);
                setEnetDstAddress(dst_addr);
            } else if (input[6] == 0x00 && input[7] == 0x02) {  //ARP응답
                byte[] dst_addr = new byte[6];  //도착지 mac주소
                if(input[18]==0x00 &&input[19]==0x00 &&input[20]==0x00 &&input[21]==0x00 &&input[22]==0x00 &&input[23]==0x00) {
                    Arrays.fill(dst_addr, (byte) 0xff);
                    setEnetDstAddress(dst_addr);    //Header에 도착지 mac주소 설정
                }else {
                    System.arraycopy(input, 18, dst_addr, 0, 6);
                    setEnetDstAddress(dst_addr);    //Header에 도착지 mac주소 설정
                }
            }
            frame = ObjToByteDATA(m_sHeader, input, length);

            System.arraycopy(m_sHeader.enet_srcaddr.addr, 0, ex_ethernetaddr, 0, 6);

            byte[] temp = new byte[6];
            System.arraycopy(input, 8, temp, 0, 6);
            setEnetSrcAddress(temp);                //Header에 출발지 mac주소 설정

        }
        getUnderLayer().send(frame, length + HEARER_SIZE);      //NILayer의 send호출

        return true;
    }


    public String macByteArrToString(byte[] mac_byte_arr){
        return  String.format("%X:", mac_byte_arr[0]) + String.format("%X:", mac_byte_arr[1])
                + String.format("%X:", mac_byte_arr[2]) + String.format("%X:", mac_byte_arr[3])
                + String.format("%X:", mac_byte_arr[4]) + String.format("%X", mac_byte_arr[5]);
    }

    public byte[] removeCappHeader(byte[] input, int length) {
        byte[] rebuf = new byte[length - HEARER_SIZE];
        m_sHeader.enet_data = new byte[length - HEARER_SIZE];
        System.arraycopy(input, HEARER_SIZE, rebuf, 0, length - HEARER_SIZE);
        return rebuf;
    }

    public boolean receive(byte[] input) {

        return true;
    }

    public boolean dstme_Addr(byte[] add) {

        return true;
    }

    public boolean srcme_Addr(byte[] add) {

        return true;
    }

    public boolean dst_you(byte[] add) {// 二쇱냼�솗�씤

        return true;
    }

    public boolean bro_Addr(byte[] add) {// 二쇱냼�솗�씤

        return true;
    }

    @Override
    public void setUnderLayer(BaseLayer pUnder_layer) {
        if (pUnder_layer == null)
            return;
        p_under_layer = pUnder_layer;
    }

    @Override
    public void setUpperLayer(BaseLayer pUpper_layer) {
        if (pUpper_layer == null)
            return;
        this.p_upper_layer.add(n_upper_layer_count++, pUpper_layer);
    }

    @Override
    public String getLayerName() {
        // TODO Auto-generated method stub
        return p_layer_name;
    }

    @Override
    public BaseLayer getUnderLayer() {
        if (p_under_layer == null)
            return null;
        return p_under_layer;
    }

    @Override
    public BaseLayer getUpperLayer(int nindex) {
        if (nindex < 0 || nindex > n_upper_layer_count || n_upper_layer_count < 0)
            return null;
        return p_upper_layer.get(nindex);
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