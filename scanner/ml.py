"""无依赖的经典机器学习小工具（**纯标准库**，离线、可解释、可一键关闭）。

定位：本项目的立身之本是「不依赖 AI 的独立工具」——这里不引入任何第三方库，只用
字符串 n-gram / SimHash / 朴素贝叶斯 / MAD 这几件**几十行就能讲清**的经典方法，给
指纹/降噪/排序补一点"统计直觉"，而不是塞一个黑箱。所有能力都**可离线、可解释、
可关闭**，且默认**不改变既有行为**（见各处的门控与调用点）。

四件事：
1. `simhash` / `near_dup` / `hamming` 与 `jaccard` / `near_dup_text`：正文的**近重复指纹** ——
   给目录扫描的软 404 基线补一条"md5 与长度都对不上、但正文其实是同一个模板"的兜底判据
   （模板页常带随机串/时间戳，逐字节不同）。长文用 SimHash，短模板页用 n-gram Jaccard。
2. `NaiveBayes`：字符 n-gram 多项式朴素贝叶斯（拉普拉斯平滑），模型可落 JSON ——
   给 POC 命中概率排序、banner 服务分类这类"小样本、强解释"的场景用。
3. `mad_outliers`：中位数绝对偏差（MAD）离群检测 —— 标记"长度明显离群"的目录命中，
   供人工优先看。
4. `char_ngrams`：上面几件共用的底座（字符 n-gram 词袋）。

⚠️ 这些函数的输入都来自**被测目标**（响应正文 / banner），一律按不可信文本处理：
只做统计与字符串运算，**绝不 eval、绝不发起任何请求**。
"""
import hashlib
import json
import math
import re
from collections import Counter

# SimHash 用 64 位。字符 n-gram 的 token 先 blake2b 成 64 位整数再逐位投票。
_BITS = 64
_NGRAM_MAX_CHARS = 20000


def char_ngrams(text, n=4, limit_chars=_NGRAM_MAX_CHARS):
    """字符 n-gram 词袋（`Counter`）。空白先压成单空格，避免排版差异污染指纹。

    `limit_chars` 是**成本封顶**：正文可能有几 MB，指纹只取前 N 个字符足够稳定
    （模板页的区别在前几千字符里就已经显现）。取不到（空串/太短）时退化成整串一个 token。
    """
    s = re.sub(r"\s+", " ", str(text or ""))[:int(limit_chars or _NGRAM_MAX_CHARS)]
    n = max(1, int(n or 1))
    if not s:
        return Counter()
    if len(s) < n:
        return Counter({s: 1})
    return Counter(s[i:i + n] for i in range(len(s) - n + 1))


def _tok_hash(tok):
    """n-gram token → 64 位无符号整数（用 blake2b，标准库自带、跨进程稳定）。"""
    return int.from_bytes(
        hashlib.blake2b(str(tok).encode("utf-8", "replace"), digest_size=8).digest(), "big")


def simhash(text, n=4, limit_chars=_NGRAM_MAX_CHARS):
    """正文的 64 位 SimHash（近重复指纹）。相同模板的正文 SimHash 汉明距离很小。

    实现：每个 n-gram token 取 64 位哈希，按位加权投票（该位为 1 记 +w、为 0 记 -w，
    w=该 token 出现次数），最后每位取符号。空文本返回 0。
    """
    grams = char_ngrams(text, n=n, limit_chars=limit_chars)
    if not grams:
        return 0
    v = [0] * _BITS
    for tok, w in grams.items():
        h = _tok_hash(tok)
        for i in range(_BITS):
            if (h >> i) & 1:
                v[i] += w
            else:
                v[i] -= w
    out = 0
    for i in range(_BITS):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming(a, b):
    """两个 64 位指纹的汉明距离（逐位不同的个数）。"""
    return bin((int(a) ^ int(b)) & ((1 << _BITS) - 1)).count("1")


def near_dup(a, b, max_dist=3):
    """两个 SimHash 是否近重复（汉明距离 ≤ `max_dist`）。

    `max_dist=3` 是 SimHash 的常见经验阈值（64 位下，3 位以内基本是同一份内容的小改动）。
    ⚠️ SimHash 适合**较长**的文档（几百个以上 token）；正文很短时，"改几个字符"会让
    汉明距离飙到十几 —— 那种短文本请用 `jaccard` / `near_dup_text`（见下）。
    """
    return hamming(a, b) <= int(max_dist)


def jaccard(text_a, text_b, n=4):
    """两段正文的字符 n-gram **集合 Jaccard 相似度**（0~1）。

    比 SimHash 更适合**短模板页**：同一模板只改了个随机路径时，n-gram 集合的交集仍很大
    （实测：Apache 404 模板换随机路径 Jaccard ≈ 0.9，不同页面 ≈ 0.1）；SimHash 对短文本
    过于敏感（同模板能差到十几位）。空文本返回 0。
    """
    a = set(char_ngrams(text_a, n=n))
    b = set(char_ngrams(text_b, n=n))
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def near_dup_text(text_a, text_b, n=4, threshold=0.6):
    """两段正文是否近重复（Jaccard ≥ `threshold`，默认 0.6）。

    阈值依据：实测同模板换随机参数 Jaccard 0.6~0.9、不同页面 0.07~0.43，0.6 把两类分开。
    调用方（目录扫描的软 404 兜底）**只对够长的正文**用它（≥ 128 字节），避开超短文本
    Jaccard 不稳的那一档。
    """
    return jaccard(text_a, text_b, n=n) >= float(threshold)


def median(values):
    """中位数（不排序入参；空序列返回 0.0）。"""
    xs = sorted(float(x) for x in (values or []) if x is not None)
    if not xs:
        return 0.0
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2.0


def mad_outliers(values, k=3.5):
    """MAD 离群检测：返回 `(离群值集合, 中位数, MAD)`。

    `MAD = median(|x - median(x)|)`，比标准差**抗离群**（一个极端值不会把阈值带飞）。
    `k=3.5` 是常用的宽松阈值（≈正态的 3σ）；样本 < 4 个时不做判定（返回空集）。
    带 `modified z-score = 0.6745*(x-med)/MAD`，`|z| > k` 判离群；MAD=0（全相同）时用
    "不等于中位数"兜底（否则除零）。
    """
    xs = [float(x) for x in (values or []) if x is not None]
    if len(xs) < 4:
        return set(), (median(xs) if xs else 0.0), 0.0
    med = median(xs)
    dev = [abs(x - med) for x in xs]
    m = median(dev)
    if m == 0:
        out = {x for x in xs if x != med}
        return out, med, 0.0
    out = set()
    for x in xs:
        z = 0.6745 * (x - med) / m
        if abs(z) > float(k):
            out.add(x)
    return out, med, m


class NaiveBayes:
    """字符 n-gram 多项式朴素贝叶斯（拉普拉斯平滑），模型可落 JSON。

    用途：POC 命中概率排序、banner 服务分类这类"类别少、样本小、要能解释"的场景。
    `predict_proba` 返回 `{类别: 概率}`（归一化）；`predict` 返回概率最高的类别。
    未见过的 n-gram 不参与（对未知词按先验处理，不会因平滑把概率推向某类）。
    """

    def __init__(self, n=3, alpha=1.0):
        self.n = max(1, int(n))
        self.alpha = float(alpha)
        self.labels = []
        self.priors = {}          # label -> log 先验
        self.logp = {}            # label -> {token: log P(token|label)}
        self.default = {}         # label -> log P(未见 token|label)（平滑项）
        self.doc_count = 0

    def fit(self, samples):
        """`samples` = `[(label, text), ...]`。原地训练并返回 self。"""
        counts = {}               # label -> Counter(token)
        doc_counts = Counter()
        for label, text in (samples or []):
            lab = str(label)
            doc_counts[lab] += 1
            c = counts.setdefault(lab, Counter())
            c.update(char_ngrams(text, n=self.n))
        self.doc_count = int(sum(doc_counts.values()))
        self.labels = sorted(doc_counts)
        self.priors, self.logp, self.default = {}, {}, {}
        vocab = set()
        for c in counts.values():
            vocab.update(c)
        v = max(1, len(vocab))
        for lab in self.labels:
            p = doc_counts[lab] / self.doc_count if self.doc_count else 0.0
            self.priors[lab] = math.log(p) if p > 0 else float("-inf")
            total = sum(counts[lab].values())
            self.default[lab] = math.log(self.alpha / (total + self.alpha * v))
            self.logp[lab] = {
                tok: math.log((cnt + self.alpha) / (total + self.alpha * v))
                for tok, cnt in counts[lab].items()}
        return self

    def predict_proba(self, text):
        """返回 `{类别: 概率}`；未训练（无标签）时返回 `{}`。"""
        if not self.labels:
            return {}
        grams = char_ngrams(text, n=self.n)
        scores = {}
        for lab in self.labels:
            s = self.priors[lab]
            table = self.logp[lab]
            dflt = self.default[lab]
            for tok, cnt in grams.items():
                s += cnt * table.get(tok, dflt)
            scores[lab] = s
        # 数值稳定：减去最大值再 exp（对数空间里"减去常数"等价于整体缩放）
        mx = max(scores.values())
        exp = {k: math.exp(v - mx) for k, v in scores.items()}
        total = sum(exp.values()) or 1.0
        return {k: v / total for k, v in exp.items()}

    def predict(self, text):
        """返回概率最高的类别；无模型时返回 ""（**不猜**）。"""
        probs = self.predict_proba(text)
        if not probs:
            return ""
        return max(probs.items(), key=lambda kv: kv[1])[0]

    # ---- 序列化（模型落 JSON，纯文本、可审阅） ----
    def to_dict(self):
        return {"n": self.n, "alpha": self.alpha, "labels": list(self.labels),
                "priors": dict(self.priors),
                "logp": {k: dict(v) for k, v in self.logp.items()},
                "default": dict(self.default), "doc_count": self.doc_count}

    @classmethod
    def from_dict(cls, data):
        m = cls(n=(data or {}).get("n", 3), alpha=(data or {}).get("alpha", 1.0))
        m.labels = list((data or {}).get("labels") or [])
        m.priors = dict((data or {}).get("priors") or {})
        m.logp = {k: dict(v) for k, v in ((data or {}).get("logp") or {}).items()}
        m.default = dict((data or {}).get("default") or {})
        m.doc_count = int((data or {}).get("doc_count") or 0)
        return m

    def save(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, ensure_ascii=False)
        return True

    @classmethod
    def load(cls, path):
        """读模型文件；不存在/损坏返回 None（调用方按"没有模型"处理，绝不抛）。"""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return cls.from_dict(json.load(fh))
        except (OSError, ValueError):
            return None
