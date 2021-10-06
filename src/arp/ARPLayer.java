package arp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

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

    public static final int APP_HEADER_LEN = 28;    // 28 byte 의 헤더 length

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

    /**
     * 상위 레이어(IP Layer)에서 받은 데이터에서 헤더를 붙혀 하위 레이어(ethernet layer)로 보내는 메소드
     * @param _sender_mac_addr  전송자의 mac 주소
     * @param _sender_ip_addr   전송자의 ip 주소
     * @param _target_mac_addr  목적지의 mac 주소
     * @param _target_ip_addr   목적지의 ip 주소
     * @param _op_code          0x0001 : request / 0x0002 : reply
     * @return                  boolean 타입
     */
    public boolean send(byte[] _sender_mac_addr, byte[] _sender_ip_addr, byte[] _target_mac_addr,
                        byte[] _target_ip_addr, byte[] _op_code){
        // hard_type -> 1 로 고정
        // prot_type -> 0x0800 로 고정
        // hard_size -> 6, prot_size -> 4 (byte) 로 고정

        // TODO : 이미 캐시 테이블에 있는 경우, Basic, Proxy, GARP 에 따라 구현 필요
        //      -> Basic    : _sender_mac_addr, _sender_op_addr, _target_ip_addr 존재, _target_mac_addr : ????
        //                  : incomplete -> complete 단계 수행
        //      -> Proxy    : Basic과 동일한 형태의 매개변수 전달 받음
        //                  : 상대 proxy table 확인 절차 필요
        //      -> GARP     : sender 와 target ip 주소가 같음
        //                  : 상대 table 모두 mac 주소 갱신

        
        return true;
    }

    /**
     *  케시 테이블 업데이트
     */
    public void updateCacheTable(){
        // TODO: Application layer 과 연동 필요
        Set keys = cache_table.keySet();

        for(Iterator iterator = keys.iterator(); iterator.hasNext();){
            String key = (String)iterator.next();
            Object[] value =  (Object[]) cache_table.get(key);

            if(value[2].equals("Incomplete")){
                // TODO: Incomplete 상태 Application layer에 업데이트
            }else{
                byte[] mac_addr_byte = (byte[]) value[1];
                String mac_address_string = macByteArrToString(mac_addr_byte);
                // TODO: Application layer 업데이트
            }
        }
    }

    /**
     * byte 형태 mac 주소 문자열로 반환
     * @param mac_byte_arr  byte 배열형의 mac 주소
     * @return
     */
    public String macByteArrToString(byte[] mac_byte_arr){
        return  String.format("%X:", mac_byte_arr[0]) + String.format("%X:", mac_byte_arr[1])
                + String.format("%X:", mac_byte_arr[2]) + String.format("%X:", mac_byte_arr[3])
                + String.format("%X:", mac_byte_arr[4]) + String.format("%X", mac_byte_arr[5]);
    }

    /**
     * byte 형태 ip 주소 문자열로 반환
     * @param ip_byte_arr   byte 배열형의 ip 주소
     * @return
     */
    public String ipByteArrToString(byte[] ip_byte_arr){
        return (ip_byte_arr[0] & 0xFF) + "." + (ip_byte_arr[1] & 0xFF) + "."
                + (ip_byte_arr[2] & 0xFF) + "." + (ip_byte_arr[3] & 0xFF);
    }


    /**
     * 케시 테이블 목록의 시간 확인 위한 스레드 상속 받은 클래스
     */
    class CacheTimer implements Runnable{
        HashMap<String, Object[]> cache_table;
        final int INCOMPLETE_TIME_LIMIT = 3;
        final int COMPLETE_TIME_LIMIT = 20;

        public CacheTimer(HashMap<String, Object[]> _cache_table){
            this.cache_table = _cache_table;
        }

        @Override
        public void run(){
            while(true){
                Set key_set = this.cache_table.keySet();
                ArrayList<String> delete_key = new ArrayList<>();

                for(Iterator iterator = key_set.iterator(); iterator.hasNext(); ){
                    String key = "";
                    if((key = (String)iterator.next()) != null){    // key 값 받아옴
                        Object[] value = this.cache_table.get(key);

                        if(((String)value[2]).equals("Incomplete") &&
                                (System.currentTimeMillis() - (long)value[3])/60000 >= INCOMPLETE_TIME_LIMIT){
                            delete_key.add(key);
                        }

                        if(((String)value[2]).equals("Complete") &&
                                (System.currentTimeMillis() - (long)value[3])/60000 >= COMPLETE_TIME_LIMIT){
                            delete_key.add(key);
                        }
                    }
                }

                for(String del_key : delete_key){
                    this.cache_table.remove(del_key);
                }

                // TODO : 케시 테이블 업데이트 메소드 구현
                updateCacheTable();

                try{
                    Thread.sleep(100);
                } catch (InterruptedException e){
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public String getLayerName() {
        return p_layer_name;
    }

    @Override
    public BaseLayer getUnderLayer() {
        if(p_under_layer == null){
            return null;
        }
        return p_under_layer;
    }

    @Override
    public BaseLayer getUnderLayer(int nindex) {
        return null;
    }

    @Override
    public BaseLayer getUpperLayer(int nindex) {
        if (nindex < 0 || nindex > n_upper_layer_count || n_upper_layer_count < 0){
            return null;
        }
        return p_upper_layer_list.get(nindex);
    }

    @Override
    public void setUnderLayer(BaseLayer pUnderLayer) {
        if(pUnderLayer == null){
            return;
        }
        this.p_under_layer = pUnderLayer;
    }

    @Override
    public void setUpperLayer(BaseLayer pUpperLayer) {
        if(pUpperLayer == null){
            return;
        }
        this.p_upper_layer_list.add(n_upper_layer_count++, pUpperLayer);
    }

    @Override
    public void setUnderNUpperLayer(BaseLayer pUULayer) {
        BaseLayer.super.setUnderNUpperLayer(pUULayer);
    }


    @Override
    public void setUpperUnderLayer(BaseLayer pUULayer) {
        this.setUpperLayer(pUULayer);
        pUULayer.setUnderLayer(this);
    }
}
