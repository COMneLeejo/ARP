import java.util.ArrayList;

public interface BaseLayer {
  public final int number_of_upper_layer = 0;
  public final int number_of_under_layer = 0; //for IP
  public final String present_layer_name = null;
  public final BaseLayer under_layer = null;
  public final ArrayList<BaseLayer> array_of_upper_layer = new ArrayList<BaseLayer>();
  public final ArrayList<BaseLayer> array_of_under_layer = new ArrayList<BaseLayer>(); //for IP

  public String getLayerName();
  public BaseLayer getUnderLayer();
  public BaseLayer getUnderLayer(int index);
  public BaseLayer getUpperLayer(int index);

  public void setUnderLayer(BaseLayer under_layer);
  public void setUpperLayer(BaseLayer upper_layer);
  public default void setUnderNUpperLayer(BaseLayer under_and_upper_layer) {}
  public void setUpperUnderLayer(BaseLayer under_and_upper_layer);

  public default boolean send(byte[] input, int length) {
    return false;
  }
  public default boolean send(byte[] input, int length, Object ob) {
    return false;
  }
  public default boolean send(String filename) {
    return false;
  }

  public default boolean receive(byte[] input) {
    return false;
  }
  public default boolean receive() {
    return false;
  }
}