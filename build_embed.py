#!/usr/bin/env python3
# build_embed.py — 由 showcase.src.html 生成完全静态单文件 showcase.html
#
#   python build_embed.py
#
# 做三件事：
#   1. GALLERY 里的 8 张图（3 PNG + 5 SVG）替换为 base64 data URI（内嵌）；
#   2. console_win_round23.txt 以转义文本注入（查看器里等宽原样展示）；
#      report.md / README.md 以 <script type="text/markdown"> 原文注入，
#      页内查看器用内嵌的 marked 渲染成排版后的 HTML；
#   3. 把 marked.min.js（MIT）注入 <!--MARKED--> 挂点。
#
# 源模板 showcase.src.html 保持相对路径（便于仓库内 diff 与维护）；
# 产物 showcase.html 单文件即可双击打开，不依赖任何外部文件。
# 改内容请改 showcase.src.html，然后重跑本脚本。
import base64, html, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC, DST = ROOT / 'showcase.src.html', ROOT / 'showcase.html'
MARKED = ROOT / 'marked.min.js'

IMAGES = {  # GALLERY 中的相对路径 → MIME
    'evidence/POC_ONECLICK_WIN.png': 'image/png',
    'evidence/figs/ARCH-V4.svg':     'image/svg+xml',
    'evidence/figs/RX-ALIAS.svg':    'image/svg+xml',
    'evidence/figs/IAT-RESOLVE.svg': 'image/svg+xml',
    'evidence/figs/WEAPONIZE.svg':   'image/svg+xml',
    'evidence/figs/RACE-78952.svg':  'image/svg+xml',
}
DOCS = [     # (模板 id, 相对路径, 标签, 是否 markdown)
    ('doc-log',    'evidence/console_win_round23.txt', '胜轮控制台日志 · console trail', False),
    ('doc-report', 'report.md',                        '技术报告 v4 · 完整 writeup',     True),
    ('doc-readme', 'README.md',                        '链内导航 · 复现说明',            True),
]

def main() -> int:
    out = SRC.read_text(encoding='utf-8')

    # 1) 图片 → data URI
    for rel, mime in IMAGES.items():
        data = (ROOT / rel).read_bytes()
        uri = f'data:{mime};base64,' + base64.b64encode(data).decode('ascii')
        needle = f"s:'{rel}'"
        if needle not in out:
            print(f'[!] 找不到 {needle}（src 是否已被内嵌污染？）'); return 1
        out = out.replace(needle, f"s:'{uri}'")
        print(f'[img] {rel:<38} {len(data)/1024:8.1f} KB → data URI')

    # 2) 文档注入（md → text/markdown 脚本；txt → 转义 pre）
    tpl = []
    for did, rel, label, is_md in DOCS:
        text = (ROOT / rel).read_text(encoding='utf-8', errors='replace')
        if is_md:
            low = text.lower()
            if '</script' in low or '<script' in low:
                print(f'[!] {rel} 含 <script 标签，不能安全内嵌'); return 1
            tpl.append(
                f'<div class="dtpl" id="{did}"><div class="dsec">{html.escape(rel)} · {label}</div>'
                f'<script type="text/markdown">{text}</script></div>')
        else:
            tpl.append(
                f'<div class="dtpl" id="{did}"><div class="dsec">{html.escape(rel)} · {label}</div>'
                f'<div class="code doc">{html.escape(text)}</div></div>')
        print(f'[doc] {rel:<38} {len(text)/1024:8.1f} KB → {"markdown 渲染" if is_md else "等宽原文"}')
    if '<!--DOCS-->' not in out:
        print('[!] 找不到 <!--DOCS--> 挂点'); return 1
    out = out.replace('<!--DOCS-->', '\n'.join(tpl))

    # 3) marked.min.js 注入
    if '<!--MARKED-->' not in out:
        print('[!] 找不到 <!--MARKED--> 挂点'); return 1
    lib = MARKED.read_text(encoding='utf-8')
    out = out.replace('<!--MARKED-->', '<script>/* marked v12.0.2 (MIT) — markdown 渲染，内嵌以保持单文件 */\n' + lib + '</script>')
    print(f'[lib] marked.min.js {len(lib)/1024:.0f} KB → 内嵌')

    DST.write_text(out, encoding='utf-8')
    print(f'[ok] {DST.name} = {DST.stat().st_size/1024:.0f} KB（单文件，无外部依赖）')
    return 0

if __name__ == '__main__':
    sys.exit(main())
