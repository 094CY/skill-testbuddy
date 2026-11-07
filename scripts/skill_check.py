#!/usr/bin/env python3
# origin: 094CY/skill-testbuddy
"""
skill_check.py — Agent Skill 静态体检（Skill-TestBuddy 随包脚本，只依赖 python3 标准库）

只读：不修改、不移动、不删除被测目录中的任何文件，也不生成缓存文件。
默认不运行被测脚本；加 --run-help 才会以 --help 试运行（先确认安全检查无 ERROR）。

用法：
  python3 skill_check.py <skill目录> [<skill目录> ...]      # 体检一个或多个 Skill
  python3 skill_check.py --all <skills根目录>                 # 批量巡检根目录下全部 Skill（只出汇总 + 问题）
  选项：
    --json                    输出 JSON（供程序或回归对比使用）
    --save-baseline <file>    保存基线（文件哈希 + 全部发现），用于下次回归
    --compare <file>          与历史基线对比：文件增删改、新增问题、已消失问题
    --portable                把平台绑定词（WorkBuddy、SOUL.md 等）从 INFO 升级为 WARN
    --platform-words a,b,c    自定义平台绑定词
    --run-help                以 --help 试运行脚本（超时 10 秒，临时目录中执行）

输出分级：
  ERROR  ：确定的缺陷（死链、语法错误、围栏不闭合、描述超长、疑似泄露密钥、管道执行远程脚本等）
  WARN   ：大概率有问题，需人工确认（规范不符、孤儿文件、绝对路径、可疑命令、提示注入措辞、跨文件重复段落等）
  INFO   ：线索与统计（平台绑定词、配额式措辞、不可判定措辞、外部网址、体量估算等），由人判断
退出码：存在 ERROR 为 1，否则为 0；参数错误为 2。
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

TEXT_EXT = {".md", ".txt", ".yaml", ".yml", ".json", ".py", ".sh", ".js", ".ts", ".mjs", ".cjs", ".html", ".css", ".toml", ".csv"}
SCRIPT_EXT = {".py", ".sh", ".js", ".mjs", ".cjs", ".ts"}
RES_DIRS = ("references", "scripts", "assets", "templates", "agents", "examples", "evals")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".workbuddy", ".venv", "venv"}
SKIP_FILES = {".DS_Store", "_meta.json", "_skillhub_meta.json"}

SPEC_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
KNOWN_KEYS = SPEC_KEYS | {
    # Claude / Claude Code
    "model", "disable-model-invocation", "user-invocable", "argument-hint", "when_to_use", "version",
    # WorkBuddy 开放平台
    "display_name", "display_name_en", "description_zh", "description_en", "examples_zh", "examples_en", "author",
    # 其他常见
    "title", "homepage", "tags",
}
DEFAULT_PLATFORM_WORDS = ["WorkBuddy", "workbuddy", "CodeBuddy", "SOUL.md", "USER.md", "IDENTITY.md", ".workbuddy/", ".claude/", ".codex/"]

R = {  # 常用正则
    "abs_path": re.compile(r"(?<![\w.])(/Users/[^\s`'\")]+|/home/[^\s`'\")]+|[A-Za-z]:\\\\[^\s`'\")]+|~/[^\s`'\")]+)"),
    "win_path": re.compile(r"\b(?:references|scripts|assets|templates)\\[\w.-]+"),
    "time_mark": re.compile(r"截至目前|截至\s*\d{4}|截止\s*\d{4}|as of \d{4}|before (?:January|February|March|April|May|June|July|August|September|October|November|December) \d{4}"),
    "vague_gate": re.compile(r"适当|合理(?!性)|酌情|视情况|灵活处理|自然(?:地)?|天然|尽量|一定程度"),
    "quota": re.compile(r"每\s*\d+\s*字|至少\s*\d+\s*(?:句|段|处|条|个|次)|≥\s*\d+\s*(?:句|段|处|条|个|次)|不超过\s*\d+\s*(?:句|段|处|个|次)|全文\s*\d+\s*(?:句|处)"),
    "imperative": re.compile(r"必须|禁止|严禁|铁律|一律|绝对不|不可违反|零例外"),
    "tick_table": re.compile(r"\|\s*✅\s*/\s*❌\s*\||回声确认"),
    "todo": re.compile(r"\bTODO\b|\bFIXME\b|\bTBD\b|待补充|待完善"),
    "inject": re.compile(r"ignore (?:all |any )?(?:previous|prior|above) instructions|disregard (?:the )?(?:system|previous)|you are now (?:in )?developer mode|do not (?:tell|inform) the user|忽略(?:之前|以上|上述|所有)(?:的)?(?:指令|规则|要求)|不要(?:告诉|告知)用户|对用户隐瞒|绕过(?:安全|审查|权限)", re.I),
    "hidden_uni": re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"),
    "url": re.compile(r"https?://[^\s)\"'`>\]]+"),
    "xml_tag": re.compile(r"<[A-Za-z/][^>]*>"),
}
SEC_ERROR = [
    (re.compile(r"(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"), "下载内容直接管道给 shell 执行"),
    (re.compile(r"base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba|z)?sh"), "解码后直接执行"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "疑似 AWS Access Key"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{24,}"), "疑似 API 密钥（sk-）"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}"), "疑似 GitHub Token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "私钥内容"),
    (re.compile(r"(?:~|\$HOME|/Users/[^/\s]+|/home/[^/\s]+)/\.ssh/|id_rsa\b|\.aws/credentials"), "读取 SSH 密钥或云凭据"),
]
SEC_WARN = [
    (re.compile(r"\beval\s*\("), "eval 动态执行"),
    (re.compile(r"\bexec\s*\((?!ute)"), "exec 动态执行"),
    (re.compile(r"os\.system\s*\("), "os.system 调用 shell"),
    (re.compile(r"shell\s*=\s*True"), "subprocess shell=True"),
    (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r|shutil\.rmtree"), "递归删除"),
    (re.compile(r"chmod\s+(?:-R\s+)?777"), "chmod 777"),
    (re.compile(r"\bcrontab\b|launchctl\s+load|systemctl\s+enable"), "写入持久化任务"),
    (re.compile(r"\bnc\s+-e\b|/dev/tcp/"), "反弹 shell 特征"),
    (re.compile(r"security\s+find-generic-password|keychain", re.I), "读取钥匙串"),
    (re.compile(r"(?:password|passwd|secret|token|api_key)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", re.I), "疑似硬编码凭据"),
]


def unquote(line):
    """去掉引号、书名号、反引号里的内容：文档里“举例说明某种写法”不应被当成技能本身的写法。"""
    return re.sub(r"“[^”]*”|「[^」]*」|`[^`]*`|\"[^\"\n]*\"", "", line)


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def read_text(p):
    with open(p, "rb") as f:
        raw = f.read()
    return raw, raw.decode("utf-8", errors="replace")


def walk(root):
    out = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for fn in sorted(files):
            if fn in SKIP_FILES:
                continue
            out.append(os.path.relpath(os.path.join(d, fn), root))
    return out


def parse_frontmatter(text):
    """极简 YAML frontmatter 解析：返回 (dict, 正文, 正文起始行号, 错误)。只解析顶层键。"""
    if not text.startswith("---"):
        return None, text, 1, "缺少 YAML frontmatter（文件需以 --- 开头）"
    lines = text.split("\n")
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return None, text, 1, "frontmatter 没有结束标记 ---"
    fm, key = {}, None
    for line in lines[1:end]:
        m = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", line)
        if m and not line.startswith((" ", "\t")):
            key, val = m.group(1), m.group(2).strip()
            if val in ("|", ">", "|-", ">-", ""):
                fm[key] = ""
            else:
                fm[key] = val.strip().strip('"').strip("'")
        elif key is not None and line.startswith((" ", "\t")):
            piece = line.strip()
            fm[key] = (fm[key] + " " + piece).strip() if fm[key] or not piece.startswith("- ") else piece
    return fm, "\n".join(lines[end + 1:]), end + 2, None


class Report:
    def __init__(self, root):
        self.root = root
        self.items = []

    def add(self, level, code, msg, where=""):
        self.items.append({"level": level, "code": code, "msg": msg, "where": where})

    def count(self, level):
        return sum(1 for i in self.items if i["level"] == level)


def strip_code(text):
    return re.sub(r"```[\s\S]*?```", lambda m: "\n" * m.group(0).count("\n"), text)


def ref_targets(text):
    """从 Markdown 文本中提取相对路径引用。"""
    found = set()
    for m in re.finditer(r"\]\(([^)\s#]+)(?:#[^)]*)?\)", text):
        found.add(m.group(1))
    for m in re.finditer(r"[`@\"']((?:\.\./|\./)?(?:" + "|".join(RES_DIRS) + r")/[\w\u4e00-\u9fff./ -]+?\.[A-Za-z0-9]{1,5})\b", text):
        found.add(m.group(1))
    out = set()
    for t in found:
        t = t.strip()
        if re.match(r"^[a-z]+://", t) or t.startswith(("mailto:", "/", "#")):
            continue
        if not re.search(r"\.[A-Za-z0-9]{1,5}$", t) and "/" not in t:
            continue  # url、URL、链接占位等非文件目标
        if re.search(r"(?:^|/)(?:xxx|xx|example|your[-_]|示例|占位)", t, re.I):
            continue
        out.add(t)
    return out


def mentioned_names(text):
    return set(re.findall(r"[\w\u4e00-\u9fff.-]+\.(?:md|py|sh|js|json|yaml|yml|txt|csv|html|ts|mjs|cjs|toml|png|svg|jpg)", text))


def check_skill(root, opts):
    rep = Report(root)
    root = os.path.abspath(root)
    files = walk(root)
    base = {"path": root, "time": now(), "files": {}}

    # ---------- T0 基线 ----------
    total_lines = total_bytes = 0
    texts = {}
    for rel in files:
        p = os.path.join(root, rel)
        raw, txt = read_text(p)
        h = hashlib.sha256(raw).hexdigest()[:16]
        lines = txt.count("\n") + (0 if txt.endswith("\n") or not txt else 1)
        base["files"][rel] = {"sha256_16": h, "md5": hashlib.md5(raw).hexdigest(), "bytes": len(raw), "lines": lines,
                              "mtime": datetime.datetime.fromtimestamp(os.stat(p).st_mtime).strftime("%Y-%m-%d %H:%M")}
        total_bytes += len(raw)
        if os.path.splitext(rel)[1].lower() in TEXT_EXT or rel == "SKILL.md":
            texts[rel] = txt
            total_lines += lines
            if raw.startswith(b"\xef\xbb\xbf"):
                rep.add("WARN", "T1-BOM", "文件带 UTF-8 BOM", rel)
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError as e:
                rep.add("ERROR", "T1-ENC", f"不是合法 UTF-8（第 {e.start} 字节附近），会显示为乱码", rel)
            ctrl = re.findall(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", txt)
            if ctrl:
                rep.add("WARN", "T1-CTRL", f"存在 {len(ctrl)} 个异常控制字符", rel)
        elif os.path.splitext(rel)[1].lower() in {".exe", ".dll", ".so", ".dylib", ".bin", ".jar"}:
            rep.add("WARN", "T8-BIN", "包内含二进制可执行文件，来源与用途需说明", rel)
    base["total_bytes"], base["total_text_lines"] = total_bytes, total_lines

    if "SKILL.md" not in texts:
        rep.add("ERROR", "T1-SKILL", "缺少 SKILL.md（文件名需全大写 SKILL.md）")
        return rep, base

    # ---------- T1 frontmatter 与规范 ----------
    skill = texts["SKILL.md"]
    fm, body, body_start, err = parse_frontmatter(skill)
    if err:
        rep.add("ERROR", "T1-FM", err, "SKILL.md")
        fm = {}
    dirname = os.path.basename(root)
    name = fm.get("name", "")
    desc = fm.get("description", "")
    base["name"], base["description_len"] = name, len(desc)
    if not name:
        rep.add("ERROR", "T1-NAME", "frontmatter 缺少 name", "SKILL.md")
    else:
        if len(name) > 64:
            rep.add("ERROR", "T1-NAME", f"name 超过 64 字符（{len(name)}）", "SKILL.md")
        if "/" in name or R["xml_tag"].search(name):
            rep.add("ERROR", "T1-NAME", f"name 含斜杠或 XML 标签：{name}", "SKILL.md")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):  # 开放规范：默认按此执行
            why = []
            if re.search(r"[A-Z]", name): why.append("含大写")
            if " " in name: why.append("含空格（命令行路径需加引号）")
            if re.search(r"[^\x00-\x7f]", name): why.append("含非 ASCII 字符")
            if "--" in name: why.append("连续连字符")
            if name.startswith("-") or name.endswith("-"): why.append("首尾为连字符")
            if re.search(r"[^A-Za-z0-9 \-\u0080-\uffff]", name): why.append("含其他符号")
            rep.add("WARN", "T1-SPEC", f"name「{name}」不符合 Agent Skills 开放规范（只允许小写字母、数字、单连字符）：{'、'.join(why) or '格式不符'}。"
                    "改为规范名（目录名同步），好记的名字放 display_name", "SKILL.md")
        if re.search(r"anthropic|claude", name, re.I):
            rep.add("WARN", "T1-SPEC", "name 含保留词 anthropic/claude（Claude 平台不允许）", "SKILL.md")
        if name != dirname:
            rep.add("WARN", "T1-DIR", f"name「{name}」与目录名「{dirname}」不一致（开放规范要求一致）", "SKILL.md")
    if not desc:
        rep.add("ERROR", "T1-DESC", "frontmatter 缺少 description（决定能否被正确触发）", "SKILL.md")
    else:
        if len(desc) > 1024:
            rep.add("ERROR", "T1-DESC", f"description {len(desc)} 字符，超过上限 1024（会被截断或拒绝）", "SKILL.md")
        elif len(desc) < 40:
            rep.add("WARN", "T1-DESC", f"description 只有 {len(desc)} 字符，可能说不清做什么、何时用", "SKILL.md")
        if R["xml_tag"].search(desc):
            rep.add("WARN", "T1-DESC", "description 含 XML/HTML 标签（Claude 平台不允许）", "SKILL.md")
        if re.search(r"^\s*(我可以|我能|你可以|I can|You can)", desc):
            rep.add("WARN", "T1-DESC", "description 用第一/第二人称开头，官方建议第三人称陈述", "SKILL.md")
        if not re.search(r"use when|use this|when the user|when (?:working|asked|you)|触发|适用于|当用户|使用场景|场景|时使用|时调用|时加载|之前|用于|Use for|Use to|Triggers", desc, re.I):
            rep.add("WARN", "T1-DESC", "description 没有写“何时使用 / 触发场景”，隐式触发容易失败", "SKILL.md")
        if len(desc) > 600:
            rep.add("INFO", "T1-DESC", f"description {len(desc)} 字符：技能多时宿主可能截断描述，关键用途和触发词放最前面", "SKILL.md")
    if "compatibility" in fm and len(fm["compatibility"]) > 500:
        rep.add("ERROR", "T1-SPEC", "compatibility 超过 500 字符", "SKILL.md")
    unknown = sorted(k for k in fm if k not in KNOWN_KEYS)
    if unknown:
        rep.add("INFO", "T1-KEYS", f"非常见 frontmatter 字段：{', '.join(unknown)}（确认宿主平台支持）", "SKILL.md")
    if "allowed-tools" in fm:
        rep.add("INFO", "T1-TOOLS", "声明了 allowed-tools：确认流程中用到的工具（运行脚本需要 Bash 等）都在列表里", "SKILL.md")

    # ---------- T2 结构与体量 ----------
    body_lines = body.count("\n") + 1
    cjk = len(re.findall(r"[\u4e00-\u9fff]", body))
    words = len(re.findall(r"[A-Za-z]+", body))
    est = cjk + int(words * 1.3)
    base["skill_body_lines"], base["skill_body_tokens_est"] = body_lines, est
    if body_lines > 500:
        rep.add("INFO", "T2-SIZE", f"SKILL.md 正文 {body_lines} 行（官方参考值 500 行，仅作参考）：看是否有能下沉到 references 按需加载的细节，"
                "不以行数本身判对错", "SKILL.md")
    if est > 5000:
        rep.add("INFO", "T2-SIZE", f"SKILL.md 正文粗估约 {est} tokens（开放规范建议 < 5000）", "SKILL.md")
    for rel, txt in texts.items():
        if not rel.endswith(".md"):
            continue
        fences = re.findall(r"^\s*(```|~~~)", txt, flags=re.M)
        if len(fences) % 2:
            rep.add("ERROR", "T2-FENCE", f"代码围栏不闭合（{len(fences)} 个）", rel)
        plain = strip_code(txt)
        last = 0
        for i, line in enumerate(plain.split("\n"), 1):
            m = re.match(r"^(#{1,6})\s", line)
            if m:
                lv = len(m.group(1))
                if last and lv > last + 1:
                    rep.add("WARN", "T2-HEAD", f"标题层级跳级（H{last}→H{lv}）", f"{rel}:{i}")
                last = lv
        # 表格列数
        rows, start = [], 0
        for i, line in enumerate(plain.split("\n") + [""], 1):
            s = line.strip()
            if s.startswith("|") and s.endswith("|") and len(s) > 1:
                if not rows:
                    start = i
                rows.append(s)
            else:
                if len(rows) >= 2 and re.fullmatch(r"\|[\s:|-]+\|", rows[1]):
                    cnt = [len(re.split(r"(?<!\\)\|", r.strip("|"))) for r in rows if not re.fullmatch(r"\|[\s:|-]+\|", r)]
                    if len(set(cnt)) > 1:
                        rep.add("WARN", "T2-TABLE", f"表格列数不一致（{sorted(set(cnt))}）", f"{rel}:{start}")
                rows = []
        n = txt.count("\n") + 1
        if rel != "SKILL.md" and n > 100 and not re.search(r"^#+\s*(目录|Contents|Table of Contents)|^>\s*\*\*?目录", txt, re.M | re.I):
            rep.add("INFO", "T2-TOC", f"{n} 行的参考文件没有目录（官方建议较长文件加目录，行数仅作参考；看文件是否主题多、需要导航）", rel)

    # ---------- T3 引用与自包含 ----------
    body_nc = strip_code(body)
    refs = ref_targets(body)
    for t in sorted(refs):
        clean = t.lstrip("./") if t.startswith("./") else t
        if t.startswith("../"):
            rep.add("WARN", "T3-OUT", f"引用了技能目录之外的文件：{t}（换环境会失效）", "SKILL.md")
            continue
        if "<" in t or "{" in t or "*" in t:
            continue
        if not os.path.exists(os.path.join(root, clean)):
            top = clean.split("/")[0]
            if top in ("references", "scripts"):
                rep.add("ERROR", "T3-DEAD", f"引用的文件不存在：{t}", "SKILL.md")
            else:
                rep.add("WARN", "T3-DEAD", f"引用的文件不存在：{t}（若指用户项目里的文件可忽略；若应随包提供需补上）", "SKILL.md")
    skill_names = mentioned_names(skill)
    others_text = "\n".join(t for r, t in texts.items() if r != "SKILL.md")
    other_names = mentioned_names(others_text)
    for rel in files:
        top = rel.split(os.sep)[0]
        if rel == "SKILL.md" or top not in RES_DIRS or top == "agents":
            continue
        fn = os.path.basename(rel)
        if fn in skill_names or rel in skill:
            continue
        if fn in other_names:
            rep.add("INFO", "T3-NEST", f"只被其他参考文件提到、SKILL.md 未直接引用（官方建议引用只深一层）", rel)
        else:
            rep.add("WARN", "T3-ORPHAN", "孤儿文件：SKILL.md 和其他文件都没有提到它", rel)
    # 参考文件之间的跨文件死链
    for rel, txt in texts.items():
        if rel == "SKILL.md" or not rel.endswith(".md"):
            continue
        for t in ref_targets(strip_code(txt)):
            if t.startswith("../") or "<" in t or "{" in t or "*" in t:
                continue
            if not os.path.isdir(os.path.join(root, t.lstrip("./").split("/")[0])) and "/" in t:
                continue  # 描述别的结构（如其他平台的目录约定），不是本包的引用
            here = os.path.normpath(os.path.join(root, os.path.dirname(rel), t))
            if not (os.path.exists(here) or os.path.exists(os.path.join(root, t.lstrip("./")))):
                rep.add("WARN", "T3-DEAD", f"引用的文件不存在：{t}", rel)
    words_list = [w for w in (opts.platform_words or DEFAULT_PLATFORM_WORDS) if w]
    for rel, txt in texts.items():
        for i, line in enumerate(txt.split("\n"), 1):
            for m in R["abs_path"].finditer(line):
                if re.search(r"\.\.\.|xxx|名字|[\[\]^\\|]", m.group(1)) or "re.compile" in line:
                    continue
                rep.add("WARN", "T3-ABS", f"绝对路径或用户目录路径：{m.group(1)[:60]}（换电脑或平台会失效）", f"{rel}:{i}")
            if R["win_path"].search(line):
                rep.add("WARN", "T3-WIN", "Windows 风格反斜杠路径，统一用 /", f"{rel}:{i}")
            hit = [w for w in words_list if w in line]
            if hit:
                rep.add("WARN" if opts.portable else "INFO", "T3-PLAT", f"平台绑定词：{'、'.join(hit)}", f"{rel}:{i}")

    # ---------- T4 一致性线索 ----------
    paras = {}
    for rel, txt in texts.items():
        if not rel.endswith(".md"):
            continue
        for block in re.split(r"\n\s*\n", strip_code(txt)):
            k = re.sub(r"[\s*`#>|_-]+", "", block)
            if len(k) >= 60:
                paras.setdefault(k, set()).add(rel)
    for k, where in paras.items():
        if len(where) > 1:
            rep.add("WARN", "T4-DUP", f"同一段内容出现在多个文件（改一处容易漏另一处）：「{k[:30]}…」", "、".join(sorted(where)))
    for rel, txt in texts.items():
        if not rel.endswith(".md"):
            continue
        plain = strip_code(txt)
        for i, line in enumerate(plain.split("\n"), 1):
            tm = R["time_mark"].search(line)
            if tm and not re.search(r"[“「`\"'（(]\s*" + re.escape(tm.group(0)) + r"|不写|禁止|不用|避免|不要", line):
                rep.add("INFO", "T4-TIME", f"时间敏感表述：{R['time_mark'].search(line).group(0)}（会过时，官方建议放进“旧模式”段或删除）", f"{rel}:{i}")
            if R["todo"].search(line):
                rep.add("INFO", "T4-TODO", f"未完成标记：{R['todo'].search(line).group(0)}", f"{rel}:{i}")
        q = [(i, m.group(0)) for i, line in enumerate(plain.split("\n"), 1) for m in R["quota"].finditer(unquote(line))]
        if q:
            rep.add("INFO", "T5-QUOTA", f"{len(q)} 处数量配额式措辞（创作类技能里容易逼出凑数和自证）：" + "；".join(f"L{i}「{s}」" for i, s in q[:6]), rel)
        gate_src = body_nc if rel == "SKILL.md" else plain
        g = [(i, m.group(0)) for i, line in enumerate(gate_src.split("\n"), 1)
             if re.match(r"\s*(?:[-*]|\||\d+[.、])", line) and re.search(r"门禁|检查|终检|判定|验收|✅|\[ \]", line)
             for m in R["vague_gate"].finditer(unquote(line))]
        if g:
            rep.add("INFO", "T5-VAGUE", f"{len(g)} 处检查项含难以判定的措辞：" + "；".join(f"L{i}「{s}」" for i, s in g[:6]), rel)
        if R["tick_table"].search(plain):
            rep.add("INFO", "T5-SELF", "存在 ✅/❌ 回声或打勾式自检：模型容易全部打勾，建议改成“写出证据”的交付说明", rel)
    imp = len(R["imperative"].findall(body_nc))
    dens = imp * 1000 / max(1, len(body_nc))
    base["imperative_per_1k_chars"] = round(dens, 2)
    if dens > 8:
        rep.add("INFO", "T4-TONE", f"SKILL.md 强制性措辞密度 {dens:.1f}/千字（必须/禁止/铁律等 {imp} 处）：过多会稀释真正的底线", "SKILL.md")

    # ---------- T5 脚本可执行性 ----------
    stdlib = getattr(sys, "stdlib_module_names", set())
    local_mods = {os.path.splitext(os.path.basename(f))[0] for f in files if f.endswith(".py")}
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext not in SCRIPT_EXT:
            continue
        p = os.path.join(root, rel)
        txt = texts.get(rel, "")
        if ext == ".py":
            try:
                compile(txt, rel, "exec")
            except SyntaxError as e:
                rep.add("ERROR", "T5-SYNTAX", f"Python 语法错误：{e.msg}（第 {e.lineno} 行）", rel)
            mods = set(re.findall(r"^\s*(?:import|from)\s+([A-Za-z_]\w*)", txt, re.M))
            ext_mods = sorted(m for m in mods if stdlib and m not in stdlib and m not in local_mods and m != "__future__")
            if ext_mods:
                declared = [m for m in ext_mods if re.search(rf"pip3? install[^\n]*\b{m}\b|requirements|{m}\s*[>=<]", skill + others_text)]
                miss = [m for m in ext_mods if m not in declared]
                if miss:
                    rep.add("WARN", "T5-DEPS", f"依赖非标准库模块但未在技能文档中声明安装方式：{', '.join(miss)}", rel)
        elif ext == ".sh" and shutil.which("bash"):
            r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
            if r.returncode:
                rep.add("ERROR", "T5-SYNTAX", f"bash 语法错误：{r.stderr.replace(p, rel).strip()[:140]}", rel)
        elif ext in {".js", ".mjs", ".cjs"} and shutil.which("node"):
            r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
            if r.returncode:
                rep.add("ERROR", "T5-SYNTAX", f"JS 语法错误：{r.stderr.replace(p, rel).strip()[:140]}", rel)
        if not re.search(r"usage|用法|argparse|--help|\$1|sys\.argv|process\.argv", txt, re.I):
            rep.add("INFO", "T5-USAGE", "脚本里没有用法说明或参数解析，模型难以正确调用", rel)

    # ---------- T8 安全 ----------
    for rel, txt in texts.items():
        is_script = os.path.splitext(rel)[1].lower() in SCRIPT_EXT
        for i, line in enumerate(txt.split("\n"), 1):
            for k, (rx, why) in enumerate(SEC_ERROR):
                if rx.search(line) and "re.compile" not in line:
                    # 文档里“描述”管道执行、读凭据路径不等于执行：.md 中这三类降为 WARN；密钥内容不论在哪都是 ERROR
                    lv = "WARN" if (not is_script and k in (0, 1, 6)) else "ERROR"
                    rep.add(lv, "T8-SEC", why + ("（出现在文档中，确认只是说明而非要求执行）" if lv == "WARN" else ""), f"{rel}:{i}")
            if is_script:
                for rx, why in SEC_WARN:
                    if rx.search(line) and "re.compile" not in line:
                        rep.add("WARN", "T8-SEC", why + "：确认必要性与输入是否可控", f"{rel}:{i}")
            mi = R["inject"].search(line)
            if mi and "re.compile" not in line:
                quoted = not R["inject"].search(unquote(line))
                rep.add("INFO" if quoted else "WARN", "T8-INJECT",
                        f"{'引号内提到' if quoted else '疑似提示注入或诱导隐瞒的'}措辞：「{mi.group(0)}」" + ("（多为举例说明，确认不是指令）" if quoted else ""), f"{rel}:{i}")
            if R["hidden_uni"].search(line) and not (i == 1 and line.startswith("\ufeff")):
                rep.add("WARN", "T8-HIDDEN", "含零宽或双向控制字符（可能藏指令）", f"{rel}:{i}")
        if is_script:
            urls = sorted(u for u in set(R["url"].findall(txt))
                          if not re.search(r"schemas\.openxmlformats\.org|www\.w3\.org|schemas\.microsoft\.com|purl\.org|example\.(?:com|org)", u))
            if urls:
                rep.add("INFO", "T8-NET", f"脚本访问外部地址（需在 SKILL.md 披露数据去向）：{'、'.join(urls[:5])}", rel)

    # ---------- 可选：试运行 --help ----------
    if opts.run_help:
        if rep.count("ERROR"):
            rep.add("INFO", "T5-RUN", "存在 ERROR，已跳过 --help 试运行")
        else:
            for rel in files:
                ext = os.path.splitext(rel)[1].lower()
                cmd = {".py": [sys.executable, "-B"], ".sh": ["bash"], ".js": ["node"]}.get(ext)
                if not cmd or (ext == ".js" and not shutil.which("node")):
                    continue
                with tempfile.TemporaryDirectory() as tmp:
                    try:
                        r = subprocess.run(cmd + [os.path.join(root, rel), "--help"], cwd=tmp, capture_output=True,
                                           text=True, timeout=10, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                        if r.returncode not in (0, 2) or not (r.stdout or r.stderr).strip():
                            rep.add("WARN", "T5-RUN", f"--help 试运行退出码 {r.returncode}，无可读用法输出", rel)
                    except subprocess.TimeoutExpired:
                        rep.add("WARN", "T5-RUN", "--help 试运行超时（10 秒）", rel)
    return rep, base


def render(rep, base, compact=False):
    out = []
    name = base.get("name") or os.path.basename(rep.root)
    out.append(f"\n######## {name}  ({rep.root})")
    out.append(f"文件 {len(base['files'])} 个 / {base['total_bytes']} 字节；SKILL.md 正文 {base.get('skill_body_lines', '-')} 行，"
               f"粗估 {base.get('skill_body_tokens_est', '-')} tokens；description {base.get('description_len', '-')} 字符")
    if not compact:
        out.append("\n【基线】")
        out.append("| 文件 | sha256(前16) | 行数 | 字节 | 修改时间 |")
        out.append("|---|---|---|---|---|")
        for rel, v in base["files"].items():
            out.append(f"| {rel} | {v['sha256_16']} | {v['lines']} | {v['bytes']} | {v['mtime']} |")
    for lv in ("ERROR", "WARN", "INFO"):
        items = [i for i in rep.items if i["level"] == lv]
        if compact and lv == "INFO":
            out.append(f"== INFO（{len(items)}，批量模式不展开）")
            continue
        out.append(f"== {lv}（{len(items)}）")
        for i in items:
            out.append(f"  - [{i['code']}] {i['msg']}" + (f"  @{i['where']}" if i["where"] else ""))
    out.append("RESULT: " + ("FAIL" if rep.count("ERROR") else "PASS（WARN/INFO 需人工判断）"))
    return "\n".join(out)


def compare(old, new):
    lines = ["\n【回归对比】"]
    of, nf = old.get("files", {}), new.get("files", {})
    add = sorted(set(nf) - set(of)); rem = sorted(set(of) - set(nf))
    chg = sorted(f for f in set(of) & set(nf) if of[f]["sha256_16"] != nf[f]["sha256_16"])
    lines.append(f"新增文件 {len(add)}：{'、'.join(add) or '无'}")
    lines.append(f"删除文件 {len(rem)}：{'、'.join(rem) or '无'}")
    lines.append(f"改动文件 {len(chg)}：" + ("、".join(f"{f}（{of[f]['lines']}→{nf[f]['lines']} 行）" for f in chg) or "无"))
    key = lambda i: (i["level"], i["code"], i["msg"], i["where"].split(":")[0])
    ok, nk = {key(i) for i in old.get("findings", [])}, {key(i) for i in new.get("findings", [])}
    fixed, newf = sorted(ok - nk), sorted(nk - ok)
    lines.append(f"已消失的问题 {len(fixed)}：")
    lines += [f"  - [{c}] {m} @{w}" for l, c, m, w in fixed if l != "INFO"]
    lines.append(f"新出现的问题 {len(newf)}：")
    lines += [f"  - {l} [{c}] {m} @{w}" for l, c, m, w in newf if l != "INFO"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Agent Skill 静态体检（只读）")
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--all", metavar="ROOT")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--save-baseline", metavar="FILE")
    ap.add_argument("--compare", metavar="FILE")
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--platform-words")
    ap.add_argument("--run-help", action="store_true")
    a = ap.parse_args()
    a.platform_words = a.platform_words.split(",") if a.platform_words else None

    targets = list(a.paths)
    if a.all:
        if not os.path.isdir(a.all):
            print(f"目录不存在：{a.all}"); sys.exit(2)
        targets += [os.path.join(a.all, d) for d in sorted(os.listdir(a.all))
                    if os.path.isfile(os.path.join(a.all, d, "SKILL.md"))]
    if not targets:
        ap.print_help(); sys.exit(2)

    results, any_err = [], False
    for t in targets:
        if not os.path.isdir(t):
            print(f"跳过：不是目录 {t}"); continue
        rep, base = check_skill(t, a)
        base["findings"] = rep.items
        results.append((rep, base))
        any_err |= bool(rep.count("ERROR"))

    if a.json:
        print(json.dumps([b for _, b in results], ensure_ascii=False, indent=1))
    else:
        if len(results) > 1:
            print("| Skill | ERROR | WARN | INFO | 正文行数 | description 字符 |")
            print("|---|---|---|---|---|---|")
            for rep, b in results:
                print(f"| {b.get('name') or os.path.basename(rep.root)} | {rep.count('ERROR')} | {rep.count('WARN')} | {rep.count('INFO')} | "
                      f"{b.get('skill_body_lines', '-')} | {b.get('description_len', '-')} |")
        for rep, b in results:
            print(render(rep, b, compact=len(results) > 1))
    if a.compare and len(results) == 1:
        with open(a.compare, encoding="utf-8") as f:
            old = json.load(f)
        cur = results[0][1]
        if isinstance(old, list):
            match = [o for o in old if o.get("path") == cur["path"]] or [o for o in old if o.get("name") == cur.get("name")]
            if not match:
                print(f"\n基线文件里没有找到 {cur.get('name') or cur['path']}，无法对比"); sys.exit(2)
            old = match[0]
        print(compare(old, cur))
    if a.save_baseline:
        with open(a.save_baseline, "w", encoding="utf-8") as f:
            json.dump([b for _, b in results], f, ensure_ascii=False, indent=1)
        print(f"\n基线已保存：{a.save_baseline}")
    sys.exit(1 if any_err else 0)


if __name__ == "__main__":
    main()
