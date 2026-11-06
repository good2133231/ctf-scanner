"""薄弱边界资产：按子域名/站点名称识别测试、开发、预发布等环境。

这不是漏洞判定，只是一条**人工复核线索**：测试站/开发站通常鉴权更弱、数据更松、
更新更随意，攻击面往往比生产入口更适合先看。误报成本只是多一个标记，所以这里
只做“名称 token”级别的保守识别 —— 不根据页面标题、技术栈或响应内容猜测。

对外只暴露三个函数：

* ``classify(value)``：返回 ``{category, label, token, host, reason}`` 或 ``{}``；
* ``label(value)``：返回可读标签（如“测试站”），没命中返回 ``""``；
* ``is_weak(value)``：布尔快捷方式；
* ``summarize(domains, sites)``：给任务详情页用的分组统计。

名称匹配按 ``.`` / ``-`` / ``_`` 切 token，只认完整 token（``latest`` 不会命中
``test``，``gitlab`` 不会命中 ``lab``），再补 ``test1`` / ``dev01`` 这类数字后缀。
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urlsplit

# token -> (category, label)；category 用于统计，label 直接进徽章
_WORDS: Dict[str, Tuple[str, str]] = {}


def _add(category: str, label: str, words: Iterable[str]) -> None:
    for word in words:
        _WORDS[word] = (category, label)


_add("test", "测试站", (
    "test", "tests", "testing", "testbed", "testenv", "testserver",
    "test-site", "test-www", "test-api", "test-admin", "test-portal",
    "uat", "qa", "sit", "ceshi",
))
_add("dev", "开发站", (
    "dev", "devs", "develop", "development", "devel", "devenv",
    "devserver", "dev-site", "dev-api", "dev-admin", "dev-portal",
    "kaifa",
))
_add("pre", "预发布", (
    "stage", "staging", "stg", "preprod", "pre-production", "preproduction",
    "pre-release", "prerelease", "pre", "gray", "grey", "canary", "yufa",
))
_add("sandbox", "演示/沙箱", (
    "demo", "sandbox", "lab", "labs", "trial", "pilot", "poc",
    "beta", "alpha", "preview", "review", "yanshi",
))

# test1 / dev01 / uat-02 这类数字后缀；base 必须已经在 _WORDS 里
_NUM_SUFFIX = re.compile(
    r"^(test|tests|testing|dev|develop|development|stage|staging|stg|"
    r"preprod|pre|uat|qa|sit|demo|sandbox|lab|beta|alpha|canary|gray|grey)"
    r"(\d{1,3})$",
    re.IGNORECASE,
)
_TOKEN_SPLIT = re.compile(r"[-_]+")


def _host_of(value: object) -> str:
    """从 host / URL / ``scheme://host/path`` 里取小写 host；取不出就返回空串。"""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        host = urlsplit(raw).hostname or ""
    elif raw.startswith("//"):
        host = urlsplit("scheme:" + raw).hostname or ""
    else:
        host = raw.split("/", 1)[0]
        host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    host = host.strip().strip(".").lower()
    return host


def _match_token(token: str) -> Tuple[str, str] | None:
    token = token.lower()
    hit = _WORDS.get(token)
    if hit:
        return hit
    m = _NUM_SUFFIX.match(token)
    if not m:
        return None
    base = m.group(1).lower()
    hit = _WORDS.get(base)
    if hit:
        return hit
    return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classify(value: object) -> Dict[str, str]:
    """按名称判断是否薄弱边界资产。

    返回样例::

        {"category": "test", "label": "测试站",
         "token": "test", "host": "test.example.com",
         "reason": "子域名 token「test」指向测试环境"}

    未命中返回空 dict；IPv4/IPv6、空字符串直接返回空 dict。
    """
    host = _host_of(value)
    if not host or _is_ip(host):
        return {}
    labels = host.split(".")
    # 最后一段是 TLD；多级后缀里的 co/uk 之类不会是环境词，但留着也不命中。
    for label in labels[:-1]:
        for token in _TOKEN_SPLIT.split(label):
            if not token:
                continue
            hit = _match_token(token)
            if not hit:
                continue
            category, label_text = hit
            return {
                "category": category,
                "label": label_text,
                "token": token,
                "host": host,
                "reason": "子域名 token「%s」指向%s" % (token, label_text),
            }
    return {}


def label(value: object) -> str:
    """返回“测试站/开发站/预发布/演示/沙箱”，未命中返回空串。"""
    info = classify(value)
    return str(info.get("label") or "")


def is_weak(value: object) -> bool:
    return bool(classify(value))


def summarize(domains: Iterable[object] = (),
              sites: Iterable[object] = ()) -> Dict[str, object]:
    """给任务详情页汇总薄弱边界资产。

    ``domains`` 与 ``sites`` 可以混装 host/URL；按 host 去重，``total`` 是
    子域名与站点的并集，``subs`` / ``sites`` 分别计数。``examples`` 保留前 5 个
    命中 host（按出现顺序），供页面提示“例如 ...”。
    """
    by: Dict[str, int] = {}
    examples: List[str] = []
    sub_hosts = set()
    site_hosts = set()
    seen_by = set()

    def _take(values: Iterable[object], bucket: set) -> None:
        for value in values:
            info = classify(value)
            if not info:
                continue
            host = str(info["host"])
            bucket.add(host)
            if host not in examples:
                examples.append(host)
            if host not in seen_by:
                seen_by.add(host)
                lab = str(info["label"])
                by[lab] = int(by.get(lab, 0)) + 1

    _take(domains, sub_hosts)
    _take(sites, site_hosts)
    return {
        "total": len(sub_hosts | site_hosts),
        "subs": len(sub_hosts),
        "sites": len(site_hosts),
        "by": by,
        "examples": examples[:5],
    }


__all__ = ["classify", "label", "is_weak", "summarize"]
