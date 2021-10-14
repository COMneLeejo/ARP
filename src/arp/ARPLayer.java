

import javax.swing.*;
import java.util.*;

public class ARPLayer implements BaseLayer {
    public int n_upper_layer_count = 0;    // number - 상위 레이어의 수
    public String p_layer_name = null;    // present - 레이어 이름
    public BaseLayer p_under_layer = null;  // present - 하위 레이어
    public ArrayList<BaseLayer> p_upper_layer_list = new ArrayList<>();    // 상위 레이어 저장 리스트

    HashMap<String, Object[]> cache_table = new HashMap<>();
    HashMap<String, Object[]> proxy_table = new HashMap<>();

    byte[] sender_mac_addr = null;
    byte[] sender_ip_addr = null;
    byte[] target_mac_addr = null;
    byte[] target_ip_addr = null;

    public static byte[] host_mac_addr = new byte[6]; // 자신 (host) 의 mac 주소 저장하는 공간
    public static byte[] host_ip_addr = new byte[4];

    public void setHostMacAddr(byte[] addr) {
        host_mac_addr[0] = addr[0];
        host_mac_addr[1] = addr[1];
        host_mac_addr[2] = addr[2];
        host_mac_addr[3] = addr[3];
        host_mac_addr[4] = addr[4];
        host_mac_addr[5] = addr[5];
    }

    public void setHostIpAddr(byte[] addr) {
        host_ip_addr[0] = addr[0];
        host_ip_addr[1] = addr[1];
        host_ip_addr[2] = addr[2];
        host_ip_addr[3] = addr[3];
    }

    public static final int ARP_HEADER_LEN = 28;    // 28 byte 의 헤더 length
    ARPHeader arp_header = new ARPHeader();

    // 생성자 정의
    public ARPLayer(String layer_name) {
        this.p_layer_name = layer_name;
    }

    // ARP 헤더 정보 정의
    private class ARPHeader {
        byte[] hard_type;
        byte[] prot_type;
        byte[] hard_size;
        byte[] prot_size;
        byte[] op_code;
        ARPMacAddr sender_mac_addr;
        ARPIpAddr sender_ip_addr;
        ARPMacAddr target_mac_addr;
        ARPIpAddr target_ip_addr;

        public ARPHeader() {
            hard_type = new byte[2];
            prot_type = new byte[2];
            hard_size = new byte[1];
            prot_size = new byte[1];
            op_code = new byte[2];
            sender_mac_addr = new ARPMacAddr();
            sender_ip_addr = new ARPIpAddr();
            target_mac_addr = new ARPMacAddr();
            target_ip_addr = new ARPIpAddr();
        }

    }

    private class ARPMacAddr {
        // ARP 의 mac 주소 저장하는 inner class
        // 총 48 bit (6 byte)의 정보 저장
        private byte[] mac = new byte[6];

        public ARPMacAddr() {
            mac[0] = (byte) 0x00;
            mac[1] = (byte) 0x00;
            mac[2] = (byte) 0x00;
            mac[3] = (byte) 0x00;
            mac[4] = (byte) 0x00;
            mac[5] = (byte) 0x00;
        }
    }

    private class ARPIpAddr {
        // ARP 의 ip 주소 저장하는 inner class
        // 총 32 bit (4 byte)의 정보 저장
        private byte[] ip = new byte[4];

        public ARPIpAddr() {
            ip[0] = (byte) 0x00;
            ip[1] = (byte) 0x00;
            ip[2] = (byte) 0x00;
            ip[3] = (byte) 0x00;
        }
    }

    /**
     * 상위 레이어(IP Layer)에서 받은 데이터에서 헤더를 붙혀 하위 레이어(ethernet layer)로 보내는 메소드
     *
     * @param _sender_mac_addr 전송자의 mac 주소
     * @param _sender_ip_addr  전송자의 ip 주소
     * @param _target_mac_addr 목적지의 mac 주소
     * @param _target_ip_addr  목적지의 ip 주소
     * @param _op_code         0x0001 : request / 0x0002 : reply
     * @return boolean 타입
     */
    public boolean send(byte[] _sender_mac_addr, byte[] _sender_ip_addr, byte[] _target_mac_addr,
                        byte[] _target_ip_addr, byte[] _op_code) {
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

        String target_ip_string = ipByteArrToString(_target_ip_addr);
        Object[] value = new Object[4];

        // ARP request / reply 먼저 구분
        if (_op_code[0] == (byte) 0x00 && _op_code[1] == (byte) 0x01) {
            // ARP request의 경우


            //(1) cache table 우선 확인
            if (cache_table.containsKey(target_ip_string)) {
                if (cache_table.get(target_ip_string)[2].equals("Complete")) {
                    // 이미 테이블에 존재하는 key인 경우
                    value = Arrays.copyOf(cache_table.get(target_ip_string), cache_table.get(target_ip_string).length);
                }
            } else {
                // 이 외의 경우는 모두 "Incomplete" 상태
                // value[0]: 현재 테이블의 크기, value[1]: 상대방 mac 주소, value[2]: 상태, value[3]: 현재 시간
                value[0] = cache_table.size() + 1;  // ??
                value[1] = _target_mac_addr;        // 전달 받은 타겟의 mac 주소 -> new bye[6] 형태 / GARP의 경우 변경된 mac 주소
                value[2] = "Incomplete";
                value[3] = System.currentTimeMillis();
            }

            // basic arp 이므로 케시 테이블 업데이트
            if (!ipByteArrToString(_sender_ip_addr).equals(ipByteArrToString(_target_ip_addr))) {
                // GARP 체크
                // GARP 의 경우 케시 테이블 업데이트 필요 x
                cache_table.put(target_ip_string, value);
                updateCacheTable();
            }

            // 다른 헤더 정보 입력
            arp_header.hard_type[0] = (byte) 0x00;
            arp_header.hard_type[1] = (byte) 0x01;

            arp_header.prot_type[0] = (byte) 0x08;
            arp_header.prot_type[1] = (byte) 0x00;

            arp_header.hard_size[0] = (byte) 0x06;
            arp_header.prot_size[0] = (byte) 0x04;

            arp_header.op_code = _op_code;

            arp_header.sender_mac_addr.mac = host_mac_addr;
            arp_header.sender_ip_addr.ip = _sender_ip_addr;
            arp_header.target_mac_addr.mac = _target_mac_addr;
            arp_header.target_ip_addr.ip = _target_ip_addr;

            byte[] bytes = objToByte(arp_header);
            (this.getUnderLayer()).send(bytes, bytes.length);
        }

        return true;
    }

    private int byte2ToInt(byte value1, byte value2) {
        return (int) ((value1 << 8) | (value2));
    }

    @Override
    public boolean receive(byte[] input) {

        //TODO: 1. garp : senderIp == targetIp
        //          (1)CacheTable에서 senderIP 찾기
        //          (2)있으면 변경
        //          (3)없으면 추가
        //      2. Proxy : ProxyTable에 TargetIp가 존재하는 지 검사
        //          <존재하는 경우>
        //              (1)targetMac 추가
        //              (2)opcode 2로 변경
        //              (3)Swapping
        //              (4)Send
        //          <존재하지 않는 경우>
        //              (1)Drop -> return false
        //      3. Basic
        //          (1)targetMac = host_mac_addr
        //          (2)Opcode = 2 로 변경
        //          (3)Swapping
        //          (4)Send
        //
        if(input == null){
            return false;
        }
        Object[] value = new Object[4];
        byte[] opcode = new byte[2];
        System.arraycopy(input, 6, opcode, 0, 2);

        System.out.println(byte2ToInt(opcode[0], opcode[1]));

        String[] arp_request_array = this.arpRequest(input);
        String sender_mac = arp_request_array[0];
        String sender_ip = arp_request_array[1];
        String target_mac = arp_request_array[2];
        String target_ip = arp_request_array[3];

        if (sender_ip.equals(target_ip)) {
            //GARP
            if (!cache_table.containsKey(sender_ip)) {
                //cache_table에 존재하지 않을 경우
                value[0] = cache_table.size();
                value[1] = this.sender_mac_addr;
                value[2] = "Complete";
                value[3] = System.currentTimeMillis();
            } else {
                //cache_table에 존재하는 경우
                value[0] = cache_table.get(sender_ip)[0];
                value[1] = this.sender_mac_addr;
                value[2] = cache_table.get(sender_ip)[2];
                value[3] = System.currentTimeMillis();
            }
            cache_table.put(sender_ip, value);
            updateCacheTable();
            return true;
        } else if (this.proxy_table.containsKey(target_ip)) {
            //Proxy
            byte[] proxy_target_mac = (byte[]) this.proxy_table.get(target_ip)[1];

            //opcode 2로 변경(reply)
            byte[] newOpcode = new byte[2];
            newOpcode[0] = (byte) 0x00;
            newOpcode[1] = (byte) 0x02;

            //target과 sender를 swapping하여 send
            this.send(proxy_target_mac, this.target_ip_addr, this.sender_mac_addr, this.sender_ip_addr, newOpcode);
            return true;

        } else {

            if (opcode[0] == 0x00 && opcode[1] == 0x01) {
                this.target_mac_addr = host_mac_addr;

                //opcode 2로 변경(reply)
                byte[] newOpcode = new byte[2];
                newOpcode[0] = (byte) 0x00;
                newOpcode[1] = (byte) 0x02;

                // 케시 테이블 업데이트
                if (!cache_table.containsKey(ipByteArrToString(this.sender_ip_addr))) {
                    value[0] = cache_table.size();
                    value[1] = this.sender_mac_addr;
                    value[2] = "Complete";
                    value[3] = System.currentTimeMillis();
                }
                cache_table.put(ipByteArrToString(this.sender_ip_addr), value);
                updateCacheTable();

                //target과 sender를 swapping하여 send
                this.send(this.target_mac_addr, this.target_ip_addr, this.sender_mac_addr, this.sender_ip_addr, newOpcode);
            }

            if (opcode[0] == 0x00 && opcode[1] == 0x02) {
                if (!cache_table.containsKey(sender_ip)) {
                    //cache_table에 존재하지 않을 경우
                    value[0] = cache_table.size();
                    value[1] = this.sender_mac_addr;
                    value[2] = "Complete";
                    value[3] = System.currentTimeMillis();
                } else {
                    //cache_table에 존재하는 경우
                    value[0] = cache_table.get(sender_ip)[0];
                    value[1] = this.sender_mac_addr;
                    value[2] = "Complete";
                    value[3] = System.currentTimeMillis();
                }
                cache_table.put(sender_ip, value);
                updateCacheTable();
                return true;
            }

            return true;
        }

    }

    /**
     * receive함수에서 input이 들어오면 opcode, sender, target의 ip, mac 주소를 string값으로 반환하는 메소드
     * 전역변수(target_mac_addr, target_ip_addr, sender_mac_addr, sender_mac_ip) 초기화 진행
     *
     * @param input ethernet header를 제외한 ARP Request/Reply
     * @return [0] : senderMac
     * [1] : senderIp
     * [2] : targetMac
     * [3] : targetIp
     */
    public String[] arpRequest(byte[] input) {
        String[] arp_request_array = new String[4];

        byte[] sender_mac = new byte[6];
        byte[] sender_ip = new byte[4];
        byte[] target_mac = new byte[6];
        byte[] target_ip = new byte[4];

        System.arraycopy(input, 8, sender_mac, 0, 6);
        System.arraycopy(input, 14, sender_ip, 0, 4);
        System.arraycopy(input, 18, target_mac, 0, 6);
        System.arraycopy(input, 24, target_ip, 0, 4);

        //target, sender의 mac, ip 주소를 byte로 저장한 전역변수 초기화
        this.target_mac_addr = target_mac;
        this.target_ip_addr = target_ip;
        this.sender_mac_addr = sender_mac;
        this.sender_ip_addr = sender_ip;

        ////target, sender의 mac, ip 주소를 string으로 변환하여 배열로 저장
        arp_request_array[0] = this.macByteArrToString(sender_mac);
        arp_request_array[1] = this.ipByteArrToString(sender_ip);
        arp_request_array[2] = this.macByteArrToString(target_mac);
        arp_request_array[3] = this.ipByteArrToString(target_ip);

        return arp_request_array;

    }

    public byte[] objToByte(ARPHeader _arp_header) {
        byte[] header = new byte[ARP_HEADER_LEN];

        header[0] = _arp_header.hard_type[0];
        header[1] = _arp_header.hard_type[1];
        header[2] = _arp_header.prot_type[0];
        header[3] = _arp_header.prot_type[1];
        header[4] = _arp_header.hard_size[0];
        header[5] = _arp_header.prot_size[0];
        header[6] = _arp_header.op_code[0];
        header[7] = _arp_header.op_code[1];

        for (int i = 0; i < 6; i++) {
            // mac 주소
            header[i + 8] = _arp_header.sender_mac_addr.mac[i];
            header[i + 18] = _arp_header.target_mac_addr.mac[i];
        }

        for (int i = 0; i < 4; i++) {
            // ip 주소
            header[i + 14] = _arp_header.sender_ip_addr.ip[i];
            header[i + 24] = _arp_header.target_ip_addr.ip[i];
        }

        return header;
    }

    /**
     * 케시 테이블 업데이트
     */
    public void updateCacheTable() {
        // TODO: Application layer 과 연동 필요
        ApplicationLayer.arp_textarea.setText("");

        Set keys = cache_table.keySet();
        for (Iterator iterator = keys.iterator(); iterator.hasNext(); ) {
            String key = (String) iterator.next();
            Object[] value = (Object[]) cache_table.get(key);

            if (value[2] == null) {
                // TODO: Trash 값 없애기
//                ApplicationLayer.arp_textarea.append("       " + key + "\t" + "??????????????\t trash\n");
            } else if (value[2].equals("Incomplete")) {
                // TODO: Incomplete 상태 Application layer에 업데이트
                ApplicationLayer.arp_textarea.append("       " + key + "\t" + "??????????????\t incomplete\n");
            } else {
                byte[] mac_addr_byte = (byte[]) value[1];
                String mac_address_string = macByteArrToString(mac_addr_byte);
                // TODO: Application layer 업데이트
                ApplicationLayer.arp_textarea.append("       " + key + "\t" + mac_address_string + "\t complete\n");
            }
        }
    }

    /**
     * byte 형태 mac 주소 문자열로 반환
     *
     * @param mac_byte_arr byte 배열형의 mac 주소
     * @return String 형태의 mac wnth
     */
    public String macByteArrToString(byte[] mac_byte_arr) {
        return String.format("%X:", mac_byte_arr[0]) + String.format("%X:", mac_byte_arr[1])
                + String.format("%X:", mac_byte_arr[2]) + String.format("%X:", mac_byte_arr[3])
                + String.format("%X:", mac_byte_arr[4]) + String.format("%X", mac_byte_arr[5]);
    }

    /**
     * byte 형태 ip 주소 문자열로 반환
     *
     * @param ip_byte_arr byte 배열형의 ip 주소
     * @return String 형태의 ip 주소
     */
    public String ipByteArrToString(byte[] ip_byte_arr) {
        return (ip_byte_arr[0] & 0xFF) + "." + (ip_byte_arr[1] & 0xFF) + "."
                + (ip_byte_arr[2] & 0xFF) + "." + (ip_byte_arr[3] & 0xFF);
    }


    /**
     * 케시 테이블 목록의 시간 확인 위한 스레드 상속 받은 클래스
     */
    class CacheTimer implements Runnable {
        HashMap<String, Object[]> cache_table;
        final int INCOMPLETE_TIME_LIMIT = 3;
        final int COMPLETE_TIME_LIMIT = 20;

        public CacheTimer(HashMap<String, Object[]> _cache_table) {
            this.cache_table = _cache_table;
        }

        @Override
        public void run() {
            while (true) {
                Set key_set = this.cache_table.keySet();
                ArrayList<String> delete_key = new ArrayList<>();

                for (Iterator iterator = key_set.iterator(); iterator.hasNext(); ) {
                    String key = "";
                    if ((key = (String) iterator.next()) != null) {    // key 값 받아옴
                        Object[] value = this.cache_table.get(key);

                        if (((String) value[2]).equals("Incomplete") &&
                                (System.currentTimeMillis() - (long) value[3]) / 60000 >= INCOMPLETE_TIME_LIMIT) {
                            delete_key.add(key);
                        }

                        if (((String) value[2]).equals("Complete") &&
                                (System.currentTimeMillis() - (long) value[3]) / 60000 >= COMPLETE_TIME_LIMIT) {
                            delete_key.add(key);
                        }
                    }
                }

                for (String del_key : delete_key) {
                    this.cache_table.remove(del_key);
                }

                // TODO : 케시 테이블 업데이트 메소드 구현
                updateCacheTable();

                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
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
        if (p_under_layer == null) {
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
        if (nindex < 0 || nindex > n_upper_layer_count || n_upper_layer_count < 0) {
            return null;
        }
        return p_upper_layer_list.get(nindex);
    }

    @Override
    public void setUnderLayer(BaseLayer pUnderLayer) {
        if (pUnderLayer == null) {
            return;
        }
        this.p_under_layer = pUnderLayer;
    }

    @Override
    public void setUpperLayer(BaseLayer pUpperLayer) {
        if (pUpperLayer == null) {
            return;
        }
        this.p_upper_layer_list.add(n_upper_layer_count++, pUpperLayer);
    }

    @Override
    public void setUnderUpperLayer(BaseLayer pUULayer) {
        BaseLayer.super.setUnderUpperLayer(pUULayer);
    }


    @Override
    public void setUpperUnderLayer(BaseLayer pUULayer) {
        this.setUpperLayer(pUULayer);
        pUULayer.setUnderLayer(this);
    }
}
