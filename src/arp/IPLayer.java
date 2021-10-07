
import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    public int number_of_upper_layer = 0;
    public int number_of_under_layer = 0;
    public String present_layer_name = null;
    public BaseLayer under_layer = null;
    public ArrayList<BaseLayer> array_of_upper_layer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> array_of_under_layer = new ArrayList<BaseLayer>();

    public final static int size_of_ip_header = 8;             //IP 헤더의 크기
    public final static int pos_of_ip_src_from_ip_header = 0;  //IP 헤더에서 src IP의 시작위치
    public final static int pos_of_ip_dst_from_ip_header = 4;  //IP 헤더에서 dst IP의 시작위치
    public final static int size_of_ip_addr = 4;               //IP 주소 크기


    private class IPLayer_Header {

        byte[] ip_src_addr;		// IP address of source
        byte[] ip_dst_addr;		// IP address of destination
        byte[] ip_data;			// data

        public IPLayer_Header(){
            this.ip_src_addr = new byte[size_of_ip_addr];
            this.ip_dst_addr = new byte[size_of_ip_addr];
            this.ip_data = null;
        }
    }

    IPLayer_Header ip_header = new IPLayer_Header();

    public IPLayer(String layer_name) {
        present_layer_name = layer_name;
        ip_header = new IPLayer_Header();
    }

    public void setIPSrcAddress(byte[] src_address) {
        for (int i = 0; i < size_of_ip_addr; i++)
            ip_header.ip_src_addr[i] = src_address[i];
    }

    public void setIPDstAddress(byte[] dst_address) {
        for (int i = 0; i < size_of_ip_addr; i++)
            ip_header.ip_dst_addr[i] = dst_address[i];
    }

    public byte[] objToByte(IPLayer_Header header, byte[] input, int length) {
        byte[] buf = new byte[length + size_of_ip_header];

        for (int i = 0; i < size_of_ip_addr; i++) {
            buf[pos_of_ip_src_from_ip_header + i] = header.ip_src_addr[i];
            buf[pos_of_ip_dst_from_ip_header + i] = header.ip_dst_addr[i];
        }
        for (int i = 0; i < length; i++) {
            buf[size_of_ip_header + i] = input[i];
        }

        return buf;
    }

    /**
     * header를 추가해 ARPLayer에 전송 => GARP
     *
     * @param input 보낼 데이터
     * @param length input의 length
     * @param obj GARP를 인식
     * @return
     */
    public boolean send(byte[] input, int length, Object obj){

        byte[] opcode = new byte[2];
        opcode[0] = (byte)0x00;
        opcode[1] = (byte)0x04;

        byte[] mac_addr = new byte[6];
        System.arraycopy(input, 24, mac_addr, 0,6);

        byte[] bytes = objToByte(ip_header,input,length);
        //ip src, ip dst, mac src(my mac add!), mac dst, opcode, data
        ((ARPLayer)this.getUnderLayer(0)).send(ip_header.ip_src_addr, ip_header.ip_src_addr, mac_addr, new byte[6], opcode, bytes);

        return true;
    }

    /**
     * header를 추가해 ARPLayer에 전송 => ARP
     * 
     * @param input 보낼 데이터
     * @param length input의 length
     * @return
     */
    public boolean send(byte[] input, int length) {

        byte[] opcode = new byte[2];
        opcode[0] = (byte)0x00;
        opcode[1] = (byte)0x01;

        byte[] bytes = objToByte(ip_header, input, length);
        //ip src, ip dst, mac src, mac dst, opcode, data
        ((ARPLayer)this.getUnderLayer(0)).send(ip_header.ip_src_addr, ip_header.ip_dst_addr, new byte[6], new byte[6], opcode, bytes);

        return true;
    }

    public byte[] removeIPHeader(byte[] input, int length) {

        byte[] return_data = new byte[length - size_of_ip_header];
        for(int i = 0; i < length - size_of_ip_header; i++) {
            return_data[i] = input[i + size_of_ip_header];
        }
        return return_data;
    }

    /**
     * 받은 데이터에서 ip header를 제거하여 AppLayer로 전송
     * 
     * @param input 받은 데이터
     * @return 전송 결과
     */
    public synchronized boolean receive(byte[] input) {

        byte[] data = removeIPHeader(input, input.length);

        if(areSrcIpAndMyAddrTheSame(input)) return false;

        //dstIP와 내 IP가 같다 = 나에게 온 패킷
        if(areDstIpAndMyAddrTheSame(input)) {
            this.getUpperLayer(0).receive(data);
            return true;
        }
        return false;
    }

    public boolean areDstIpAndMyAddrTheSame(byte[] input) {
        for(int i = 0; i < size_of_ip_addr; i++)
            if(input[i + pos_of_ip_dst_from_ip_header] != ip_header.ip_src_addr[i]) return false;
        return true;
    }
    
    public boolean areSrcIpAndMyAddrTheSame(byte[] input) {
        for(int i = 0; i < size_of_ip_addr; i++)
            if(input[i + pos_of_ip_src_from_ip_header] != ip_header.ip_src_addr[i]) return false;
        return true;
    }

    @Override
    public String getLayerName() {
        return present_layer_name;
    }

    @Override
    public BaseLayer getUnderLayer() {
        return null;
    }

    @Override
    public BaseLayer getUpperLayer(int index) {
        if (index < 0 || index > number_of_upper_layer)
            return null;
        return array_of_under_layer.get(index);
    }

    @Override
    public void setUnderLayer(BaseLayer under_layer) {
        if (under_layer == null) return;
        this.array_of_upper_layer.add(number_of_under_layer++, under_layer);
    }

    public void setUpperLayer(BaseLayer upper_layer) {
        if (upper_layer == null) return;
        this.array_of_under_layer.add(number_of_upper_layer++, upper_layer);

    }
    @Override
    public void setUpperUnderLayer(BaseLayer upper_under_layer) {
        this.setUpperLayer(upper_under_layer);
        this.setUnderLayer(upper_under_layer);
    }
    
    @Override
    public BaseLayer getUnderLayer(int index) {
        if (index < 0 || index > number_of_under_layer) return null;
        return array_of_upper_layer.get(index);
    }
}