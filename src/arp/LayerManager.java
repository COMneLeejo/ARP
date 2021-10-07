import java.util.ArrayList;
import java.util.StringTokenizer;

public class LayerManager {

	private class Node {
		private String token;
		private Node next;
		public Node(String input){
			this.token = input;
			this.next = null;
		}
	}

	Node head_of_layers;
	Node tail_of_layers;

	private int top_num_of_layers;
	private int size_of_layers;

	private ArrayList<BaseLayer> stack_of_layers = new ArrayList<BaseLayer>();
	private ArrayList<BaseLayer> array_of_layers = new ArrayList<BaseLayer>() ;


	public LayerManager(){
		size_of_layers = 0;
		head_of_layers = null;
		tail_of_layers = null;
		top_num_of_layers = -1;
	}

	public void addLayer(BaseLayer present_layer){
		array_of_layers.add(size_of_layers++, present_layer);
	}

	public BaseLayer getLayer(int index){
		return array_of_layers.get(index);
	}

	public BaseLayer getLayer(String present_layer_name){
		for(int i = 0; i < size_of_layers; i++){
			if(present_layer_name.compareTo(array_of_layers.get(i).getLayerName()) == 0)
				return array_of_layers.get(i);
		}
		return null;
	}

	public void connectLayers(String layers_name){
		makeList(layers_name);
		linkLayer(head_of_layers);
	}

	private void makeList(String layers_name){
		StringTokenizer tokens = new StringTokenizer(layers_name, " ");

		for(; tokens.hasMoreElements();){
			Node current = allocNode(tokens.nextToken());
			addNode(current);
		}
	}

	private Node allocNode(String layer_name){
		Node node = new Node(layer_name);
		return node;
	}

	private void addNode(Node current){
		if(head_of_layers == null){
			head_of_layers = tail_of_layers = current;
		}else{
			tail_of_layers.next = current;
			tail_of_layers = current;
		}
	}

	private void push (BaseLayer present_layer){
		stack_of_layers.add(++top_num_of_layers, present_layer);
		//stack_of_layers.add(present_layer);
		//top_num_of_layers++;
	}

	private BaseLayer pop(){
		BaseLayer present_layer = stack_of_layers.get(top_num_of_layers);
		stack_of_layers.remove(top_num_of_layers);
		top_num_of_layers--;

		return present_layer;
	}

	private BaseLayer top(){
		return stack_of_layers.get(top_num_of_layers);
	}

	private void linkLayer(Node current){
		BaseLayer present_layer = null;

		while(current != null){
			if( present_layer == null)
				present_layer = getLayer(current.token);
			else{
				if(current.token.equals("("))
					push (present_layer);
				else if(current.token.equals(")"))
					pop();
				else{
					char mode = current.token.charAt(0);
					String present_layer_name = current.token.substring(1, current.token.length());

					present_layer = getLayer(present_layer_name);

					switch(mode){
						case '*':
							top().setUpperUnderLayer(present_layer);
							break;
						case '+':
							top().setUpperLayer(present_layer);
							break;
						case '-':
							top().setUnderLayer(present_layer);
							break;
					}
				}
			}

			current = current.next;

		}
	}

	public void deAllocLayer(){
	}

}