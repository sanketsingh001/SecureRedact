import onnx
from onnx import helper, TensorProto
import numpy as np

# Create the input tensor
input_ids = helper.make_tensor_value_info('input_ids', TensorProto.INT64, ['batch', 'seq_len'])
attention_mask = helper.make_tensor_value_info('attention_mask', TensorProto.INT64, ['batch', 'seq_len'])

# Create the output tensor (logits: batch x seq_len x 9 classes)
logits = helper.make_tensor_value_info('logits', TensorProto.FLOAT, ['batch', 'seq_len', 9])

# Get shape of input_ids
shape_node = helper.make_node('Shape', inputs=['input_ids'], outputs=['input_shape'])

# Create a constant tensor for the last dimension [9]
nine_tensor = helper.make_tensor('nine', TensorProto.INT64, [1], [9])
nine_node = helper.make_node('Constant', inputs=[], outputs=['nine_out'], value=nine_tensor)

# Concat input_shape (which is [batch, seq_len]) with [9] -> [batch, seq_len, 9]
concat_node = helper.make_node(
    'Concat', 
    inputs=['input_shape', 'nine_out'], 
    outputs=['target_shape'], 
    axis=0
)

# ConstantOfShape to generate logits of [batch, seq_len, 9] with all zeros
fill_tensor = helper.make_tensor('fill_val', TensorProto.FLOAT, [1], [0.5])
zeros_node = helper.make_node(
    'ConstantOfShape', 
    inputs=['target_shape'], 
    outputs=['logits'], 
    value=fill_tensor
)

# Create the graph
graph_def = helper.make_graph(
    [shape_node, nine_node, concat_node, zeros_node],
    'DummyNER',
    [input_ids, attention_mask],
    [logits]
)

# Create the model
model_def = helper.make_model(graph_def, producer_name='dummy_ner_builder', ir_version=8)
model_def.opset_import[0].version = 13

# Save the model
onnx.save(model_def, 'dummy_ner.onnx')
print("Saved dummy_ner.onnx")
