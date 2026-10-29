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
from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, processors

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

# A token-classification ("NER") model: "anna" is tagged B-PERSON and "smith"
# I-PERSON; every other token O.
ner = out.parent / "tiny-ner"
ner.mkdir(exist_ok=True)
ner_vocab = dict(vocab)
for word in ["anna", "smith", "lives", "in", "berlin", "hi", "is", "here"]:
    ner_vocab.setdefault(word, len(ner_vocab))
tok = Tokenizer(models.WordLevel(ner_vocab, unk_token="[UNK]"))
tok.normalizer = normalizers.Lowercase()
tok.pre_tokenizer = pre_tokenizers.Whitespace()
tok.post_processor = processors.TemplateProcessing(
    single="[CLS] $A [SEP]",
    special_tokens=[("[CLS]", 2), ("[SEP]", 3)],
)
tok.save(str(ner / "tokenizer.json"))


def tag(word_id, name):
    # logits for one label: 8 where the token is word_id, else -4; shape [batch, seq, 1]
    return [
        node("Constant", [], [f"{name}_id"], value=helper.make_tensor(f"{name}_t", TensorProto.INT64, [], [word_id])),
        node("Equal", ["input_ids", f"{name}_id"], [f"{name}_hit"]),
        node("Cast", [f"{name}_hit"], [f"{name}_f"], to=TensorProto.FLOAT),
        node("Mul", [f"{name}_f", "twelve"], [f"{name}_s"]),
        node("Sub", [f"{name}_s", "four"], [f"{name}_l"]),
        node("Unsqueeze", [f"{name}_l", "last"], [name]),
    ]


graph = helper.make_graph(
    [
        node("Constant", [], ["twelve"], value=helper.make_tensor("tw", TensorProto.FLOAT, [], [12.0])),
        node("Constant", [], ["four"], value=helper.make_tensor("fo", TensorProto.FLOAT, [], [4.0])),
        node("Constant", [], ["last"], value=helper.make_tensor("la", TensorProto.INT64, [1], [2])),
        *tag(ner_vocab["anna"], "b"),
        *tag(ner_vocab["smith"], "i"),
        node("Sub", ["b", "b"], ["o"]),
        node("Concat", ["o", "b", "i"], ["logits"], axis=2),
    ],
    "tiny_ner",
    [
        helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch", "seq"]),
        helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch", "seq"]),
    ],
    [helper.make_tensor_value_info("logits", TensorProto.FLOAT, ["batch", "seq", 3])],
)
model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
model.ir_version = 8
onnx.checker.check_model(model)
onnx.save(model, str(ner / "model.onnx"))
(ner / "config.json").write_text(
    json.dumps({"id2label": {"0": "O", "1": "B-PERSON", "2": "I-PERSON"}, "max_position_embeddings": 8}, indent=2) + "\n"
)
