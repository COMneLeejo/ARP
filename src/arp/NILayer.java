package arp;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class NILayer implements BaseLayer {

    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    private Receive_Thread thread = null;
    int m_iNumAdapter;
    public Pcap m_AdapterObject;
    public PcapIf device;
    public List<PcapIf> m_pAdapterList;
    StringBuilder errbuf = new StringBuilder();


    public void packetStartDriver() {

    }

    public PcapIf getAdapterObject(int iIndex) {
        return m_pAdapterList.get(iIndex);
    }

    public void setAdapterNumber(int iNum) {

    }

    public void setAdapterList() {


    }

    public boolean send(byte[] input, int length) {
        ByteBuffer buf = ByteBuffer.wrap(input);
        if (m_AdapterObject.sendPacket(buf) != Pcap.OK) {
            System.err.println(m_AdapterObject.getErr());
            return false;
        }
        return true;
    }

    public boolean receive() {
        return true;
    }

    @Override
    public void setUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        p_UnderLayer = pUnderLayer;
    }

    @Override
    public void setUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
    }

    @Override
    public String getLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer getUnderLayer() {
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

    }

    @Override
    public BaseLayer getUnderLayer(int nindex) {
        // TODO Auto-generated method stub
        return null;
    }
}

class Receive_Thread implements Runnable {
    byte[] data;
    Pcap AdapterObject;
    BaseLayer UpperLayer;

    public Receive_Thread(Pcap m_AdapterObject, BaseLayer m_UpperLayer) {
        // TODO Auto-generated constructor stub
        AdapterObject = m_AdapterObject;
        UpperLayer = m_UpperLayer;
    }

    @Override
    public void run() {
        while (true) {
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
                public void nextPacket(PcapPacket packet, String user) {
                    data = packet.getByteArray(0, packet.size());
                    UpperLayer.receive(data);
                }
            };

            AdapterObject.loop(100000, jpacketHandler, "");
        }
    }
}
