import sys
F = "/code/app/subscription/share.py"
MARKER = "HY2_INJECT"
# Inject per-user hysteria2 nodes INSIDE generate_v2ray_links so links show up in:
#   - UserResponse.links  -> dashboard user card, HTML subscription page, REST API
#   - v2ray subscription  -> built as "\n".join(generate_v2ray_links(...))
# v3: multiple hysteria2 nodes (Mango + Sauna). Anchor = single-line return unique to generate_v2ray_links.
ANCHOR = "    return process_inbounds_and_tags(inbounds, proxies, format_variables, conf=conf, reverse=reverse)"
REPLACEMENT = '''    _links = process_inbounds_and_tags(inbounds, proxies, format_variables, conf=conf, reverse=reverse)
    try:  # HY2_INJECT per-user hysteria2 nodes
        _hid = None
        for _k, _v in (proxies or {}).items():
            if str(_k).lower().endswith("vless"):
                _hid = getattr(_v, "id", None) or (_v.get("id") if isinstance(_v, dict) else None)
                break
        if _hid:
            for _h, _t in (("legacy-a.example.invalid", "Legacy-A-HY2"), ("legacy-b.example.invalid", "Legacy-B-HY2")):
                _links.append("hysteria2://" + str(_hid) + "@" + _h + ":443/?sni=" + _h + "#" + _t)
    except Exception:
        pass
    return _links'''
try: src = open(F, encoding="utf-8").read()
except Exception as e: print("HY2 patch: cannot read", e); sys.exit(0)
if MARKER in src: print("HY2 patch: already applied"); sys.exit(0)
if ANCHOR not in src: print("HY2 patch: anchor NOT found, skipping"); sys.exit(0)
open(F, "w", encoding="utf-8").write(src.replace(ANCHOR, REPLACEMENT, 1))
print("HY2 patch: applied (generate_v2ray_links, 2 hy2 nodes)")
