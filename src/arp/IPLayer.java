
import java.util.ArrayList;

public class IPLayer implements BaseLayer {
    public int number_of_upper_layer = 0;
    public int number_of_under_layer = 0;
    public String present_layer_name = null;
    public BaseLayer under_layer = null;
    public ArrayList<BaseLayer> array_of_upper_layer = new ArrayList<BaseLayer>();
    public ArrayList<BaseLayer> array_of_under_layer = new ArrayList<BaseLayer>();

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