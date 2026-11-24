import os
import onnx
from onnx import helper, TensorProto
import numpy as np

# Build a deterministic token-classification ONNX model (Gather + attention_mask gating)
# plus a matching BERT WordPiece vocab.txt for CPU NER verification & load testing.

OUT_DIRS = [
    os.path.join("tests", "FintechGuard.Pii.Tests", "TestData"),
]

# Label mapping:
# 0: O, 1: B-PER, 2: I-PER, 3: B-ORG, 4: I-ORG, 5: B-LOC, 6: I-LOC, 7: B-MISC, 8: I-MISC

VOCAB = [
    ("[PAD]", 0),
    ("[UNK]", 0),
    ("[CLS]", 0),
    ("[SEP]", 0),
    ("[MASK]", 0),
    (".", 0),
    (",", 0),
    (":", 0),
    ("User", 0),
    ("Customer", 0),
    ("Spoke", 0),
    ("to", 0),
    ("I", 0),
    ("spoke", 0),
    ("and", 0),
    ("he", 0),
    ("was", 0),
    ("helpful", 0),
    ("connected", 0),
    ("agent", 0),
    ("about", 0),
    ("his", 0),
    ("account", 0),
    ("called", 0),
    ("at", 0),
    ("from", 0),
    ("lives", 0),
    ("in", 0),
    ("Log", 0),
    ("entry", 0),
    ("Nothing", 0),
    ("but", 0),
    ("unstructured", 0),
    ("data", 0),
    ("here", 0),
    ("Issue", 0),
    ("resolved", 0),
    ("works", 0),
    ("for", 0),
    # Person B-PER / I-PER tokens (including WordPiece ## subwords)
    ("Sanjay", 1),
    ("Kumar", 2),
    ("John", 1),
    ("Doe", 2),
    ("Priya", 1),
    ("Sharma", 2),
    ("Vik", 1),
    ("##ram", 2),
    ("Pa", 2),
    ("##tel", 2),
    ("Rajesh", 1),
    ("Verma", 2),
    ("रवि", 1),
    # Organization B-ORG / I-ORG
    ("Acme", 3),
    ("FinTech", 4),
    # Location B-LOC / I-LOC
    ("Indiranagar", 5),
    ("Bengaluru", 6),
    ("Mumbai", 5),
    # Hindi context words
    ("कस्टमर", 0),
    ("का", 0),
    ("नाम", 0),
    ("है", 0),
    # Low-confidence ambiguous token (tested against MinConfidence threshold)
    ("Ambiguous", -1),
]

vocab_size = len(VOCAB)
num_labels = 9
weights = np.full((vocab_size, num_labels), -3.0, dtype=np.float32)

for idx, (tok, label_id) in enumerate(VOCAB):
    if label_id == -1:
        # Produces softmax prob ~0.35 (< default 0.75 MinConfidence)
        weights[idx, :] = 0.1
        weights[idx, 1] = 0.8
    else:
        weights[idx, label_id] = 6.0

input_ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch", "seq_len"])
attention_mask = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch", "seq_len"])
logits = helper.make_tensor_value_info("logits", TensorProto.FLOAT, ["batch", "seq_len", num_labels])

weights_tensor = helper.make_tensor("token_label_weights", TensorProto.FLOAT, [vocab_size, num_labels], weights.flatten().tolist())
axes_tensor = helper.make_tensor("unsqueeze_axes", TensorProto.INT64, [1], [-1])

gather_node = helper.make_node("Gather", inputs=["token_label_weights", "input_ids"], outputs=["gathered_logits"], axis=0)
cast_node = helper.make_node("Cast", inputs=["attention_mask"], outputs=["mask_float"], to=TensorProto.FLOAT)
unsqueeze_node = helper.make_node("Unsqueeze", inputs=["mask_float", "unsqueeze_axes"], outputs=["mask_3d"])
mul_node = helper.make_node("Mul", inputs=["gathered_logits", "mask_3d"], outputs=["logits"])

graph_def = helper.make_graph(
    [gather_node, cast_node, unsqueeze_node, mul_node],
    "SecureRedactTokenClassificationNER",
    [input_ids, attention_mask],
    [logits],
    initializer=[weights_tensor, axes_tensor],
)

model_def = helper.make_model(graph_def, producer_name="secureredact_ner_fixture", ir_version=8)
model_def.opset_import[0].version = 13
onnx.checker.check_model(model_def)

for out_dir in OUT_DIRS:
    os.makedirs(out_dir, exist_ok=True)
    model_path = os.path.join(out_dir, "test_ner.onnx")
    vocab_path = os.path.join(out_dir, "test_vocab.txt")
    onnx.save(model_def, model_path)
    with open(vocab_path, "w", encoding="utf-8", newline="\n") as f:
        for tok, _ in VOCAB:
            f.write(tok + "\n")
    print(f"Generated {model_path} ({os.path.getsize(model_path)} bytes) and {vocab_path} ({vocab_size} tokens)")
