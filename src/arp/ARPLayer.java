package arp;

import java.util.ArrayList;
import java.util.HashMap;

public class ARPLayer implements BaseLayer{
    public int n_upper_layer_count = 0;    // number - 상위 레이어의 수
    public String p_layer_name = null;    // present - 레이어 이름
    public BaseLayer p_under_layer = null;  // present - 하위 레이어
    public ArrayList<BaseLayer>  p_upper_layer_list = new ArrayList<>();    // 상위 레이어 저장 리스트

    HashMap<String, Object[]> cache_table = new HashMap<>();
    HashMap<String, Object[]> proxy_table = new HashMap<>();

    byte[] sender_mac_addr = null;
    byte[] sender_ip_addr = null;
    byte[] target_mac_addr = null;
    byte[] target_ip_addr = null;

    public static final int APP_HEADER = 28;    // 28 byte의 헤더 길이 고정

    // 생성자 정의
    public ARPLayer (String layer_name){
        this.p_layer_name = layer_name;
    }

    // ARP 헤더 정보 정의
    private class ARPHeader{
        byte[] hard_type;
        byte[] prot_type;
        byte[] hard_size;
        byte[] prot_size;
        byte[] op_code;
        ARPMacAddr _sender_mac_addr;
        ARPIpAddr _sender_ip_addr;
        ARPMacAddr _target_mac_addr;
        ARPIpAddr _target_ip_addr;

        public ARPHeader(){
            hard_type = new byte[2];
            prot_type = new byte[2];
            hard_size = new byte[1];
            prot_size = new byte[1];
            op_code = new byte[2];
            _sender_mac_addr = new ARPMacAddr();
            _sender_ip_addr = new ARPIpAddr();
            _target_mac_addr = new ARPMacAddr();
            _target_ip_addr = new ARPIpAddr();
        }

    }

    private class ARPMacAddr{
        // ARP 의 mac 주소 저장하는 inner class
        // 총 48 bit (6 byte)의 정보 저장
        private byte[] mac = new byte[6];

        public ARPMacAddr(){
            mac[0] = (byte)0x00;
            mac[1] = (byte)0x00;
            mac[2] = (byte)0x00;
            mac[3] = (byte)0x00;
            mac[4] = (byte)0x00;
            mac[5] = (byte)0x00;
        }
    }

    private class ARPIpAddr{
        // ARP 의 ip 주소 저장하는 inner class
        // 총 32 bit (4 byte)의 정보 저장
        private byte[] ip = new byte[4];

        public ARPIpAddr(){
            ip[0] = (byte)0x00;
            ip[1] = (byte)0x00;
            ip[2] = (byte)0x00;
            ip[3] = (byte)0x00;
        }
    }

    @Override
    public String GetLayerName() {
        return p_layer_name;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        if(p_under_layer == null){
            return null;
        }
        return p_under_layer;
    }

    @Override
    public BaseLayer GetUnderLayer(int nindex) {
        return null;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        if (nindex < 0 || nindex > n_upper_layer_count || n_upper_layer_count < 0){
            return null;
        }
        return p_upper_layer_list.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        if(pUnderLayer == null){
            return;
        }
        this.p_under_layer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        if(pUpperLayer == null){
            return;
        }
        this.p_upper_layer_list.add(n_upper_layer_count++, pUpperLayer);
    }

    @Override
    public void SetUnderUpperLayer(BaseLayer pUULayer) {
        BaseLayer.super.SetUnderUpperLayer(pUULayer);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }
}
