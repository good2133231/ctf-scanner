"""凭据文件加解密的管理入口（续98）：`python cli/run_keys.py --status/--encrypt/--change/--verify`。

为什么单独一个入口：加密是一次性的**部署动作**，不该混进扫描路径（扫描期绝不联网、也绝不要口令，
见 `scanner/keystore.py` 文件头）。这个脚本只做三件事：把明文 `config/keys.yaml` 变成口令加密的
`config/keys.enc.yaml`、换口令、以及如实告诉你现在是什么状态。

**红线**：
1. **任何输出都不出现凭据值或口令** —— 状态里只打"某厂商 已填/空"与 `keystore.mask()` 的指纹；
   口令只从 `getpass`（不回显、不进 shell 历史）或环境变量来：`CTFSCANNER_KEYS_PASSPHRASE`
   （新建/加密用；`--change` 时它是**旧**口令）与续295 的 `CTFSCANNER_KEYS_PASSPHRASE_NEW`（新口令）。
2. `--encrypt` 默认**不删明文**，只提示；要删得显式 `--shred`，且删前会**先解密回读校验一次**
   （宁可留两份，也不能出现"密文没验证过就把明文删了"）。
3. 只写 `config/` 下这两个文件，不碰 `settings.yaml`（GUI「策略配置」页会把 settings 整体写回，
   凭据混在里面容易被覆盖 —— 这也是当初把 keys 单独成文件的理由）。
"""
import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import keystore  # noqa: E402
from scanner.utils import is_interactive_stdin  # noqa: E402


def _ask(prompt, confirm=False):
    """取口令：不回显；`--confirm` 时要求输入两遍且必须一致（防手滑把凭据锁死）。"""
    if not is_interactive_stdin():     # 续246：Windows isatty 对 NUL 也真，会挂死在 getpass
        if not confirm:
            # 续162：非交互时先试同机口令文件（与启动解锁同一套守卫）；续292 起候选有两档，
            # 所以那句"用 … 里的口令"必须报**真正命中的那一档**，写死第一个名字就是假话。
            # `confirm=True`（= 设**新**口令）刻意不走这一档：那样 `--change` 会"旧口令=新口令=文件里那句"，
            # 换口令变成一次静默的空操作。
            got, _why, _from = keystore.file_passphrase_detail()
            if got:
                print(f"[i] 用 {_from} 里的口令（{keystore.mask(got)}）")
                return got
        print("[!] 非交互环境：" + keystore.unlock_howto() + "（口令不要写进任何入库文件）")
        return None
    first = getpass.getpass(prompt)
    if not first:
        print("[!] 空口令拒绝 —— 空口令等于没加密。")
        return None
    if confirm:
        again = getpass.getpass("再输入一次以确认：")
        if again != first:
            print("[!] 两次输入不一致，已中止（什么都没写）。")
            return None
    return first


def _vendors(data):
    """把 keys dict 压成"厂商: 已填/空"的**不含值**摘要。"""
    out = []
    for name, val in sorted((data or {}).items()):
        if isinstance(val, dict):
            filled = [k for k, v in sorted(val.items()) if str(v or "").strip()]
            out.append(f"{name}({'已填:' + ','.join(filled) if filled else '全空'})")
        else:
            out.append(f"{name}({'已填' if str(val or '').strip() else '空'})")
    return " ".join(out) or "(空文件)"


def _do_status(args):
    st = keystore.status(args.dst)
    plain_exists = Path(args.src).exists()
    print(f"[*] 凭据状态（密文文件 {Path(args.dst).name}）")
    print(f"    加密文件存在 : {st['encrypted']}")
    print(f"    本机可解密   : {'是' if st['crypto_available'] else '否 —— 未安装 cryptography，密文读不了'}")
    print(f"    当前已解锁   : {st['unlocked']}" + (f"（来源 {st['source']}）" if st["unlocked"] else ""))
    if st["reason"]:
        print(f"    说明         : {st['reason']}")
    print(f"    明文文件仍在 : {plain_exists}"
          + ("  ← 已启用加密就该把明文删掉（--shred，或手工删 config/keys.yaml）"
             if (st["encrypted"] and plain_exists) else ""))
    return 0


def _do_verify(args):
    """只做一件事：证明"这个口令能解开这个文件"，并给出厂商摘要（不含值）。"""
    if not Path(args.dst).exists():
        print(f"[!] 没有 {Path(args.dst)} —— 先用 --encrypt 生成。")
        return 1
    phrase = args.passphrase or _ask("凭据口令（校验）：")
    if not phrase:
        return 1
    text, why = keystore.decrypt_blob(Path(args.dst).read_bytes(), phrase)
    if text is None:
        print(f"[!] 解不开：{why}")
        return 1
    try:
        data = keystore._parse(text)
    except Exception as e:
        print(f"[!] 能解密但内容不是合法 YAML：{e}")
        return 1
    print(f"[+] 口令正确，可解开 {Path(args.dst).name}（{len(text)} 字符）")
    print(f"    内容摘要（只列厂商与字段名，不打印任何值）：{_vendors(data)}")
    return 0


def _do_encrypt(args, change=False):
    src = Path(args.src)
    dst = Path(args.dst)
    if not src.exists():
        # 续295：`--change` 的内容来源是**现有密文**（下面 `text = back` 那一步），明文本来就该是可选的
        # —— 旧代码在这里无条件 return 1，等于"换口令只在还留着明文的那台机器上做得成"，
        # 而新克隆/已经 --shred 过的机器恰恰就是没有明文的（本轮实测撞出：rc=1「找不到明文凭据文件」）。
        if not change:
            print(f"[!] 找不到明文凭据文件 {src} —— 没有可加密的东西。")
            return 1
        if not dst.exists():
            print(f"[!] 既没有明文 {src.name}，也没有密文 {dst.name} —— 无从换口令。")
            return 1
        text = ""
        plain_new = {}
    else:
        text = src.read_text(encoding="utf-8")
        plain_new = keystore._parse(text) or {}
    old = ""
    if change and dst.exists():
        old = args.passphrase or (_ask("旧口令（解现有密文）：") or "")
        if not old:
            return 1
        back, why = keystore.decrypt_blob(dst.read_bytes(), old)
        if back is None:
            print(f"[!] 旧口令解不开现有密文，已中止（明文未动）：{why}")
            return 1
        text = back            # 换口令时以现有密文为准，避免用旧明文覆盖新值
    # 续295：换口令必须有**第二个**来源。只给一个 `--passphrase` / 环境变量时，旧口令与新口令
    # 拿到的是同一个值 ⇒ `--change` 会"以旧口令再加密一次"，报着成功却是**静默空操作**
    # （`_ask` 的注释早就为这一档写过"旧=新=文件里那句"的危险，但非交互那条路没堵）。
    phrase = getattr(args, "new_passphrase", "") or args.passphrase or _ask(
        "新凭据口令（至少一次输入不回显）：", confirm=True)
    if change and phrase and phrase == old:
        print("[!] 新口令与旧口令是同一句 —— `--change` 什么都不改，已中止（什么都没写）。"
              f"非交互请给第二个来源：`--new-passphrase '<新口令>'` 或环境变量 {ENV_NEW_PASSPHRASE}"
              f"（`{keystore.ENV_PASSPHRASE}` 留作**旧口令**）。")
        return 1
    if not phrase:
        return 1
    # 续162：**合并**而不是整份覆盖。老密文能解开就以它为底（补一组不该抹掉另一组），
    # 解不开就照旧用明文整份写 —— 但必须先问清楚，绝不静默丢弃已有的组。
    base, merged_from = None, ""
    if dst.exists() and not change:
        back, why = keystore.decrypt_blob(dst.read_bytes(), phrase)
        if back is None:
            old = args.passphrase or _ask("旧口令（现有密文与新口令不同才能解开它；"
                                          "直接回车＝不合并，用明文整份覆盖）：") or ""
            if old == phrase:
                # 非交互时 args.passphrase 与 phrase 是同一个值（`--passphrase` / 环境变量只有一个来源），
                # 拿同一句口令再试一次只会得到同一个"解不开"，然后卡在下面 return 1 ——
                # 于是 --help 与那句提示里承诺的 `--force-overwrite` **永远走不到**（续293 实测撞出）。
                # 当成"没有另一句旧口令"，让它落到真正认这个旗标的那一档。
                old = ""
            if old:
                back, why2 = keystore.decrypt_blob(dst.read_bytes(), old)
                if back is None:
                    print(f"[!] 旧口令解不开现有密文，已中止（什么都没写）：{why2}")
                    return 1
                merged_from = "旧密文"
            else:
                print(f"[!] 现有密文解不开（{why}），这次**不合并** —— 明文里没有的组会被整份抹掉。"
                      f"要保住它们请带正确的旧口令重跑；要继续就用 --force-overwrite。")
                if not args.force_overwrite:
                    return 1
                merged_from = "没合并（整份覆盖）"
        else:
            base = keystore._parse(back)
            merged_from = "旧密文（同一个口令解开）"
    if base is not None:
        data, rep = keystore.merge_key_dicts(base, plain_new)
        import yaml as _yaml
        text = _yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
        print(f"[i] 合并来源：{merged_from}｜新增组 {rep['added'] or '无'}｜"
              f"保留（明文没有、密文里有）{rep['kept'] or '无'}｜改动字段 {rep['changed'] or '无'}"
              f"（只报组名与字段名，不报任何值）")
        print("    注意：合并后的文件是纯数据，明文里的注释不保留。")
    blob = keystore.encrypt_text(text, phrase)
    # 先解密回读校验，再落盘：确保"写进去的这份一定能被这个口令解开"
    back, why = keystore.decrypt_blob(blob, phrase)
    if back != text:
        print(f"[!] 自校验未通过，未写入任何文件：{why or '内容与原文不一致'}")
        return 1
    keystore.write_encrypted(dst, blob)
    print(f"[+] 已{'换口令并' if change else '用口令加密并'}写出 {keystore.ENC_KEYS_PATH.name}"
          f"（{dst.name}，{len(blob)} 字节，PBKDF2-HMAC-SHA256 {_KDF_HINT} + AES-256-GCM）")
    if src.exists() and dst.exists() and not change:
        if args.shred:
            src.unlink()
            print(f"[+] 已删除明文 {src}（密文自校验通过之后才删的）")
        else:
            print(f"[i] 明文 {src} 仍在。确认无误后手工删它，或本次就带 --shred。")
            print("    在删掉之前，加密只防住了'密文被拷走'，没防住'明文还躺在原地'。")
    print(f"[i] 下次启动 GUI/CLI/节点会要一次口令；无人值守请设 {keystore.ENV_PASSPHRASE}"
          "（只放进程环境，别写进任何入库文件）。")
    return 0


_KDF_HINT = "60 万次迭代"
# 续295：换口令需要**两个**来源。`CTFSCANNER_KEYS_PASSPHRASE` 是**旧**口令（也是新建/加密时的口令），
# 第二个来源只用于 `--change` 的**新**口令 —— 只有一个来源时 `--change` 必然"旧=新"，
# 于是它报着成功却什么都没换（一次静默空操作，正是 `_ask` 注释里警告过的那一档）。
ENV_NEW_PASSPHRASE = "CTFSCANNER_KEYS_PASSPHRASE_NEW"


def main(argv=None):
    ap = argparse.ArgumentParser(description="CTFScanner 凭据文件加解密管理（不打印任何凭据值）")
    ap.add_argument("--status", action="store_true", help="看当前状态（默认动作）")
    ap.add_argument("--encrypt", action="store_true", help="把明文 keys.yaml 加密成 keys.enc.yaml")
    ap.add_argument("--change", action="store_true", help="换口令（以现有密文内容为准）")
    ap.add_argument("--verify", action="store_true", help="验证某个口令能解开密文")
    ap.add_argument("--src", default=str(keystore.PLAIN_KEYS_PATH), help="明文文件路径")
    ap.add_argument("--dst", default=str(keystore.ENC_KEYS_PATH), help="密文文件路径")
    ap.add_argument("--shred", action="store_true", help="加密自校验通过后删掉明文")
    ap.add_argument("--force-overwrite", action="store_true",
                    help="（续162 新增的显式旗标）现有密文解不开时仍用明文整份覆盖")
    ap.add_argument("--passphrase", default=os.environ.get(keystore.ENV_PASSPHRASE, ""),
                    help=f"口令（默认读环境变量 {keystore.ENV_PASSPHRASE}；都没有就交互输入）"
                         "—— `--change` 时它是**旧**口令")
    ap.add_argument("--new-passphrase", default=os.environ.get(ENV_NEW_PASSPHRASE, ""),
                    help=f"（续295，仅 `--change` 用）**新**口令；默认读环境变量 {ENV_NEW_PASSPHRASE}。"
                         "只给一个来源时旧=新，命令会拒绝执行而不是静默空操作")
    args = ap.parse_args(argv)
    if args.encrypt:
        return _do_encrypt(args, change=False)
    if args.change:
        return _do_encrypt(args, change=True)
    if args.verify:
        return _do_verify(args)
    return _do_status(args)


if __name__ == "__main__":
    sys.exit(main())
