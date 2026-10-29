"""Builds the tiny test model in ./tiny: a 'classifier' that scores a text as an
injection when it contains the word "attack". It exercises tokenization,
windowing, batching and ONNX Runtime without downloading a real model.

    pip install onnx tokenizers && python make_tiny.py
"""

import json
import shutil
from pathlib import Path

import onnx
from onnx import TensorProto, helper
from tokenizers import Tokenizer, models, pre_tokenizers, processors

out = Path(__file__).parent / "tiny"
out.mkdir(exist_ok=True)

vocab = {"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3, "attack": 4}
for i, word in enumerate("hello please summarise this report the a of and to".split()):
    vocab[word] = 5 + i
tok = Tokenizer(models.WordLevel(vocab, unk_token="[UNK]"))
tok.pre_tokenizer = pre_tokenizers.Whitespace()
tok.post_processor = processors.TemplateProcessing(
    single="[CLS] $A [SEP]",
    pair="[CLS] $A [SEP] $B:1 [SEP]:1",
    special_tokens=[("[CLS]", 2), ("[SEP]", 3)],
)
tok.save(str(out / "tokenizer.json"))

# logits[:, 1] = 8 * (count of "attack" tokens) - 4; logits[:, 0] = 0
node = helper.make_node
graph = helper.make_graph(
    [
        node("Constant", [], ["trigger"], value=helper.make_tensor("t", TensorProto.INT64, [], [4])),
        node("Equal", ["input_ids", "trigger"], ["hit"]),
        node("Cast", ["hit"], ["hit_f"], to=TensorProto.FLOAT),
        node("Cast", ["attention_mask"], ["mask_f"], to=TensorProto.FLOAT),
        node("Mul", ["hit_f", "mask_f"], ["masked"]),
        node("ReduceSum", ["masked", "axes"], ["count"], keepdims=1),
        node("Constant", [], ["axes"], value=helper.make_tensor("a", TensorProto.INT64, [1], [1])),
        node("Constant", [], ["scale"], value=helper.make_tensor("s", TensorProto.FLOAT, [], [8.0])),
        node("Constant", [], ["bias"], value=helper.make_tensor("b", TensorProto.FLOAT, [], [4.0])),
        node("Mul", ["count", "scale"], ["scaled"]),
        node("Sub", ["scaled", "bias"], ["positive"]),
        node("Sub", ["positive", "positive"], ["zero"]),
        node("Concat", ["zero", "positive"], ["logits"], axis=1),
    ],
    "tiny",
    [
        helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch", "seq"]),
        helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch", "seq"]),
    ],
    [helper.make_tensor_value_info("logits", TensorProto.FLOAT, ["batch", 2])],
)
# Constants must precede their use for a valid topological order.
order = ["trigger", "axes", "scale", "bias"]
consts = [n for n in graph.node if n.output[0] in order]
rest = [n for n in graph.node if n.output[0] not in order]
del graph.node[:]
graph.node.extend(consts + rest)
model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
model.ir_version = 8
onnx.checker.check_model(model)
onnx.save(model, str(out / "model.onnx"))

(out / "config.json").write_text(
    json.dumps({"id2label": {"0": "SAFE", "1": "INJECTION"}, "max_position_embeddings": 16}, indent=2) + "\n"
)

# The same model as a moderation model (an "unsafe" gate plus one category
# that always passes its threshold) and as an NLI model for topics: there,
# a text "entails" any hypothesis when either of them contains "attack".
variants = {
    "tiny-safety": (
        {"problem_type": "multi_label_classification", "id2label": {"0": "other", "1": "unsafe"}},
        {"thresholds.json": {"unsafe": 0.5, "categories": {"other": 0.4}}},
    ),
    "tiny-nli": ({"id2label": {"0": "not_entailment", "1": "entailment"}}, {}),
}
for name, (config, extra) in variants.items():
    d = out.parent / name
    d.mkdir(exist_ok=True)
    for f in ["model.onnx", "tokenizer.json"]:
        shutil.copy(out / f, d / f)
    (d / "config.json").write_text(json.dumps({**config, "max_position_embeddings": 16}, indent=2) + "\n")
    for f, v in extra.items():
        (d / f).write_text(json.dumps(v, indent=2) + "\n")
