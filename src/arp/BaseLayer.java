import java.util.ArrayList;

public interface BaseLayer {
  public final int m_nUpperLayerCount = 0;
  public final int m_nUnderLayerCount_forIP = 0;
  public final String m_pLayerName = null;
  public final BaseLayer mp_UnderLayer = null;
  public final ArrayList<BaseLayer> mp_aUpperLayer = new ArrayList<BaseLayer>();
  public final ArrayList<BaseLayer> mp_aUnderLayer_forIP = new ArrayList<BaseLayer>();

  public String GetLayerName();

  public BaseLayer GetUnderLayer();
    
  public BaseLayer GetUnderLayer(int nindex);

  public BaseLayer GetUpperLayer(int nindex);

  public void SetUnderLayer(BaseLayer pUnderLayer);

  public void SetUpperLayer(BaseLayer pUpperLayer);

  public default void SetUnderUpperLayer(BaseLayer pUULayer) {}

  public void SetUpperUnderLayer(BaseLayer pUULayer);

  public default boolean Send(byte[] input, int length) {
    return false;
  }
  public default boolean Send(byte[] input, int length, Object ob) {
		return false;
	}
  public default boolean Send(String filename) {
    return false;
  }

  public default boolean Receive(byte[] input) {
    return false;
  }

  public default boolean Receive() {
    return false;
  }
}