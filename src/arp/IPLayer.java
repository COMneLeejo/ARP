
import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    public int number_of_upper_layer = 0;
    public int number_of_under_layer = 0;
    public String present_layer_name = null;
    public BaseLayer under_layer = null;
    public ArrayList<BaseLayer> array_of_upper_layer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> array_of_under_layer = new ArrayList<BaseLayer>();

    public final static int ip_header_size = 8;
    public final static int ip_src_start_pos = 0;
    public final static int ip_dst_start_pos = 4;
    public final static int ip_addr_size = 4;


    private class IPLayer_Header {

        byte[] ip_src_addr;		// IP address of source
        byte[] ip_dst_addr;		// IP address of destination
        byte[] ip_data;			// data

        public IPLayer_Header(){
            this.ip_src_addr = new byte[ip_addr_size];
            this.ip_dst_addr = new byte[ip_addr_size];
            this.ip_data = null;
        }
    }

    IPLayer_Header ip_header = new IPLayer_Header();

    public IPLayer(String layer_name) {
        present_layer_name = layer_name;
        ip_header = new IPLayer_Header();
    }

    public void setIPSrcAddress(byte[] src_address) {
        for (int i = 0; i < ip_addr_size; i++)
            ip_header.ip_src_addr[i]= src_address[i];
    }

    public void setIPDstAddress(byte[] dst_address) {
        for (int i = 0; i < ip_addr_size; i++)
            ip_header.ip_dst_addr[i]= dst_address[i];
    }

    public byte[] objToByte(IPLayer_Header header, byte[] input, int length) {
        byte[] buf = new byte[length + ip_header_size];

        for (int i = 0; i < ip_addr_size; i++) {
            buf[ip_src_start_pos + i] = header.ip_src_addr[i];
            buf[ip_dst_start_pos + i] = header.ip_dst_addr[i];
        }
        for (int i = 0; i < length; i++) {
            buf[ip_header_size + i] = input[i];
        }

        return buf;
    }

    public boolean send(byte[] input, int length, Object obj){
        byte[] opcode = new byte[2];
        opcode[0] = (byte)0x00;
        opcode[1] = (byte)0x04;

        byte[] mac_addr = new byte[6];
        System.arraycopy(input, 24, mac_addr, 0,6);
        
        byte[] bytes = objToByte(ip_header,input,length);
        ((ARPLayer)this.getUnderLayer(0)).send(ip_header.ip_src_addr, ip_header.ip_src_addr, mac_addr, new byte[6], opcode, bytes);

        return true;
    }

    public boolean send(byte[] input, int length) {

        byte[] opcode = new byte[2];
        opcode[0] = (byte)0x00;
        opcode[1] = (byte)0x01;

        byte[] bytes = objToByte(ip_header, input, length);
        ((ARPLayer)this.getUnderLayer(0)).send(ip_header.ip_src_addr, ip_header.ip_dst_addr, new byte[6], new byte[6], opcode, bytes);

        return true;
    }

    public byte[] removeIPHeader(byte[] input, int length) {

        byte[] return_data = new byte[length - ip_header_size];
        for(int i = 0; i < length - ip_header_size; i++) {
            return_data[i] = input[i + ip_header_size];
        }
        return return_data;
    }

    public synchronized boolean receive(byte[] input) {

        byte[] data = removeIPHeader(input, input.length);

        if(areSrcIpAndMyAddrTheSame(input)) return false;
        if(areDstIpAndMyAddrTheSame(input)) {
            this.getUpperLayer(0).receive(data);
            return true;
        }
        return false;
    }

    public boolean areDstIpAndMyAddrTheSame(byte[] input) {
        for(int i = 0; i < ip_addr_size; i++)
            if(input[i + ip_dst_start_pos] != ip_header.ip_src_addr[i]) return false;
        return true;
    }

    public boolean areSrcIpAndMyAddrTheSame(byte[] input) {
        for(int i = 0; i < ip_addr_size; i++)
            if(input[i + ip_src_start_pos] != ip_header.ip_src_addr[i]) return false;
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