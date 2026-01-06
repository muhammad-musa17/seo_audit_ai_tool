import re
import os
import json
import streamlit as st
import pandas as pd

from seo_checks import run_audit, grade_from_score, ai_seo_qa, ai_seo_learning_answer



st.set_page_config(page_title="SEO Audit AI", layout="wide")

# =========================
# SEO Learning Assistant — Chat Sessions (NEW)
# =========================
def init_seo_chat_state():
    if "seo_chats" not in st.session_state:
        # Each chat = {"title": str, "messages": [{"role": "user"/"assistant", "content": str}]}
        st.session_state.seo_chats = [
            {"title": "Chat 1", "messages": []}
        ]
    if "active_seo_chat_idx" not in st.session_state:
        st.session_state.active_seo_chat_idx = 0

def new_seo_chat():
    n = len(st.session_state.seo_chats) + 1
    st.session_state.seo_chats.append({"title": f"Chat {n}", "messages": []})
    st.session_state.active_seo_chat_idx = len(st.session_state.seo_chats) - 1

init_seo_chat_state()


# =========================
# UI Helpers
# =========================
def badge(text: str):
    st.markdown(f"<span style='padding:4px 10px;border-radius:16px;background:#1f6f43;color:white;font-size:12px;'>{text}</span>", unsafe_allow_html=True)

def warn_badge(text: str):
    st.markdown(f"<span style='padding:4px 10px;border-radius:16px;background:#8a6d00;color:white;font-size:12px;'>{text}</span>", unsafe_allow_html=True)

def red_badge(text: str):
    st.markdown(f"<span style='padding:4px 10px;border-radius:16px;background:#7a1b1b;color:white;font-size:12px;'>{text}</span>", unsafe_allow_html=True)

def severity_color(priority: str) -> str:
    p = (priority or "").upper()
    if p == "HIGH":
        return "🔴 HIGH"
    if p == "MEDIUM":
        return "🟠 MEDIUM"
    return "🟢 LOW"

def _render_rich_answer(ans: dict, *, idx: int = 1):
    """
    Render a structured SEO assistant answer nicely in Streamlit.
    Expects `ans` to be a dict with keys like:
    title, short_answer, key_points, step_by_step, checklist, examples, warnings
    """

    # Safety
    if isinstance(ans, str):
        ans = {"scope": "seo", "short_answer": ans}

    title = (ans.get("title") or "").strip()
    short_answer = (ans.get("short_answer") or "").strip()

    key_points = ans.get("key_points") or []
    step_by_step = ans.get("step_by_step") or []
    checklist = ans.get("checklist") or []
    examples = ans.get("examples") or []
    warnings = ans.get("warnings") or []

    # Card container look
    with st.container(border=True):
        # Header
        if title:
            st.markdown(f"### A{idx}. {title}")
        else:
            st.markdown(f"### A{idx}. Answer")

        if short_answer:
            st.write(short_answer)

        # Tabs for structure
        tabs = st.tabs(["Key Points", "Steps", "Checklist", "Examples", "Warnings"])

        with tabs[0]:
            if key_points:
                for p in key_points:
                    st.markdown(f"- {p}")
            else:
                st.caption("No key points provided.")

        with tabs[1]:
            if step_by_step:
                for i, s in enumerate(step_by_step, start=1):
                    st.markdown(f"**Step {i}:** {s}")
            else:
                st.caption("No step-by-step provided.")

        with tabs[2]:
            if checklist:
                for c in checklist:
                    st.checkbox(c, value=False, key=f"chk_{idx}_{hash(c)}")
            else:
                st.caption("No checklist provided.")

        with tabs[3]:
            if examples:
                for ex in examples:
                    if isinstance(ex, dict):
                        ex_title = (ex.get("title") or "").strip()
                        ex_lang = (ex.get("language") or "text").strip()
                        ex_code = ex.get("code") or ""

                        if ex_title:
                            st.markdown(f"**{ex_title}**")

                        if ex_code.strip():
                            st.code(ex_code.strip(), language=ex_lang if ex_lang else "text")
                        else:
                            st.caption("No code provided for this example.")
                    else:
                        st.write(str(ex))
            else:
                st.caption("No examples provided.")


        with tabs[4]:
            if warnings:
                for w in warnings:
                    st.warning(w)
            else:
                st.caption("No warnings provided.")


# =========================
# Sidebar
# =========================
st.sidebar.title("Settings")

timeout = st.sidebar.slider("Request timeout (seconds)", min_value=5, max_value=60, value=15, step=1)
max_pages = st.sidebar.slider("Max pages to crawl", min_value=1, max_value=30, value=8, step=1)

st.sidebar.markdown("### Crawl options")
check_links = st.sidebar.checkbox("Check internal links (slower)", value=True)
links_per_page = st.sidebar.slider("Links to check per page", min_value=0, max_value=30, value=8, step=1)

delay_sec = st.sidebar.slider("Delay between page fetches (sec)", min_value=0.0, max_value=3.0, value=0.0, step=0.1)

st.sidebar.markdown("---")
st.sidebar.markdown("### AI (Real LLM)")

enable_ai = st.sidebar.checkbox("Enable AI suggestions (OpenRouter)", value=False)
site_name = st.sidebar.text_input("Site/Brand name (optional)", value="")

ai_model = st.sidebar.selectbox(
    "OpenRouter model",
    options=[
        "google/gemma-3-27b-it:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "tngtech/deepseek-r1t2-chimera:free",
        "openai/gpt-oss-120b:free",
        "google/gemini-2.0-flash-exp:free",
        "qwen/qwen3-coder:free",
    ],
    index=0
)
ai_temp = st.sidebar.slider("AI creativity (temperature)", min_value=0.0, max_value=1.0, value=0.2, step=0.05)
ai_max_pages = st.sidebar.slider("AI pages to generate suggestions for", min_value=1, max_value=20, value=min(8, max_pages), step=1)

ai_lang = st.sidebar.radio(
    "Implementation code language",
    options=["Laravel (Blade)", "Next.js (React)", "HTML (static)", "WordPress", "Shopify (Liquid)"],
    index=0,
    disabled=not enable_ai
)

ai_include_code = st.sidebar.checkbox(
    "Generate implementation code snippets",
    value=False,
    disabled=not enable_ai
)

st.sidebar.markdown("---")
st.sidebar.markdown("## SEO Learning Assistant")

if st.sidebar.button("➕ New Chat", use_container_width=True):
    new_seo_chat()

chat_titles = [c["title"] for c in st.session_state.seo_chats]
st.session_state.active_seo_chat_idx = st.sidebar.selectbox(
    "Select chat",
    options=list(range(len(chat_titles))),
    format_func=lambda i: chat_titles[i],
    index=st.session_state.active_seo_chat_idx
)

if st.sidebar.button("🗑️ Clear This Chat", use_container_width=True):
    st.session_state.seo_chats[st.session_state.active_seo_chat_idx]["messages"] = []



st.sidebar.info("Set env var OPENROUTER_API_KEY. Never hardcode keys.")


# =========================
# Main
# =========================
st.title("SEO Audit AI — Phase 4 (Action Plan + Reporting)")
st.caption("Homepage SEO + technical SEO + internal crawl + AI action plan + client-ready report.")

url = st.text_input("Website URL", value="")

run = st.button("Run SEO Check", type="primary")

if "result" not in st.session_state:
    st.session_state.result = None

if run:
    with st.spinner("Running audit..."):
        res = run_audit(
            url=url,
            timeout=timeout,
            max_pages=max_pages,
            check_internal_links=check_links,
            links_per_page=links_per_page,
            delay_sec=delay_sec,
            enable_ai=enable_ai,
            ai_model=ai_model,
            ai_temperature=ai_temp,
            ai_max_pages=ai_max_pages,
            site_name=site_name,
            ai_language=ai_lang,
            ai_include_code=ai_include_code
        )

        st.session_state.result = res

res = st.session_state.result
if not res:
    st.stop()

# =========================
# Top KPIs
# =========================
col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("Homepage Score")
    st.markdown(f"## {res['homepage_score']}")
    if res["homepage_grade"] == "Blocked":
        red_badge("Blocked")
    else:
        badge(res["homepage_grade"])

with col2:
    st.subheader("Site Score")
    st.markdown(f"## {res['site_score']}")
    badge(res["site_grade"])

with col3:
    st.subheader("HTTP Status")
    st.markdown(f"## {res['http_status']}")
    if res["http_status"] == 200:
        badge("OK")
    else:
        warn_badge(str(res["http_status"]))

st.markdown(f"**Final URL:** {res['final_url']}")

# If AI failed show a clear error
if enable_ai and isinstance(res.get("ai_suggestions"), dict) and "__error__" in res["ai_suggestions"]:
    st.error(f"AI error: {res['ai_suggestions']['__error__'].get('notes','Unknown error')}")

st.divider()


# =========================
# Technical SEO
# =========================
st.header("Technical SEO (Phase 2)")

tech = res["tech"]
c1, c2, c3 = st.columns(3)

with c1:
    st.write("**robots.txt:**", "Found" if tech.get("robots_found") else ("Not checked (blocked)" if tech.get("robots_blocked") else "Not found"))
    st.write("**Status:**", tech.get("robots_status"))
    st.write("**Checked URL:**", tech.get("robots_url"))

with c2:
    sitemaps = tech.get("sitemaps", [])
    sitemap_found = any((x.get("status") == 200 and not x.get("blocked")) for x in sitemaps)
    st.write("**Sitemap:**", "Found" if sitemap_found else ("Not checked (blocked)" if any(x.get("blocked") for x in sitemaps) else "Not found"))
    if sitemaps:
        st.write("**Checked sitemap URLs**")
        st.code(json.dumps([x.get("sitemap_url") for x in sitemaps], indent=2))

with c3:
    xrt = tech.get("indexability_headers", {}).get("x_robots_tag", "")
    st.write("**Indexability headers**")
    st.write("X-Robots-Tag:", xrt if xrt else "—")

st.divider()


# =========================
# Homepage On-page Overview
# =========================
st.header("Homepage On-page Overview")

pages_df: pd.DataFrame = res["pages_df"]
home = pages_df.iloc[0].to_dict() if not pages_df.empty else {}

left, right = st.columns(2)

with left:
    st.write(f"**Title:** {home.get('title') or '—'}")
    st.write(f"**Meta Description:** {home.get('meta_description') or '—'}")
    st.write(f"**Canonical:** {home.get('canonical') or '—'}")
    st.write(f"**Meta Robots:** {home.get('meta_robots') or '—'}")
    st.write(f"**Viewport:** {home.get('viewport') or '—'}")

    st.write("**Headings (Homepage)**")
    st.write(f"H1 count: {home.get('h1_count',0)}")
    h1s = home.get("h1s") if isinstance(home.get("h1s"), list) else []
    if h1s:
        for h in h1s[:10]:
            st.write(f"- {h}")

    h2s = home.get("top_h2") if isinstance(home.get("top_h2"), list) else []
    if h2s:
        st.write("Top H2:")
        for h in h2s[:8]:
            st.write(f"- {h}")

with right:
    st.write("**Images & Accessibility (Homepage)**")
    total_imgs = int(home.get("total_images") or 0)
    alt_imgs = int(home.get("images_with_alt") or 0)
    st.write(f"Total images: {total_imgs}")
    st.write(f"Images with alt: {alt_imgs}")
    if total_imgs > 0:
        pct = int(round((alt_imgs / total_imgs) * 100))
        st.progress(pct / 100.0)
        st.caption(f"Alt coverage: {pct}%")
    else:
        st.progress(1.0)
        st.caption("Alt coverage: 100% (no images detected)")

    st.write("**Social Preview (Open Graph)**")
    st.write(f"og:title: {home.get('og_title') or '—'}")
    st.write(f"og:description: {home.get('og_description') or '—'}")
    st.write(f"og:image: {home.get('og_image') or '—'}")

st.divider()


# =========================
# Homepage Issues
# =========================
st.header("Homepage Issues & Recommendations")
home_issues = res.get("homepage_issues", [])
if not home_issues:
    st.success("No homepage issues detected.")
else:
    for i, it in enumerate(home_issues, start=1):
        st.markdown(f"### {i}. [{it.get('priority','LOW')}] {it.get('issue','')}")
        st.write("**Why it matters:**", it.get("why", ""))
        st.write("**How to fix:**", it.get("how", ""))

st.divider()


# =========================
# Site Crawl Summary
# =========================
st.header("Site Crawl (Phase 3 Improved)")

site_counts = res.get("site_counts", {})
c1, c2, c3 = st.columns(3)
with c1:
    st.write("Pages crawled")
    st.markdown(f"## {len(pages_df)}")
    st.write("Sitewide issue counts")
    st.write("Pages missing title", site_counts.get("pages_missing_title", 0))
with c2:
    st.write("Site score")
    st.markdown(f"## {res['site_score']}")
    st.write("Pages missing meta", site_counts.get("pages_missing_meta", 0))
with c3:
    st.write("Site grade")
    st.markdown(f"## {res['site_grade']}")
    st.write("Pages missing H1", site_counts.get("pages_missing_h1", 0))

st.write("Duplicate groups")
st.write("Duplicate title groups:", len(site_counts.get("duplicate_title_groups", {})))
st.write("Duplicate meta description groups:", len(site_counts.get("duplicate_meta_groups", {})))

st.subheader("Pages summary")
st.dataframe(
    pages_df[[
        "url","final_url","status_code","blocked","block_reason",
        "title","meta_description","meta_desc_len","h1_count",
        "missing_title","missing_meta","missing_h1"
    ]],
    use_container_width=True
)

st.download_button(
    "Download pages CSV",
    data=pages_df.to_csv(index=False).encode("utf-8"),
    file_name="seo_pages.csv",
    mime="text/csv",
)

dup_titles = site_counts.get("duplicate_title_groups", {})
dup_meta = site_counts.get("duplicate_meta_groups", {})

with st.expander("Duplicate titles (groups)"):
    if dup_titles:
        st.json(dup_titles)
    else:
        st.success("No duplicate titles found in the crawled set.")

with st.expander("Duplicate meta descriptions (groups)"):
    if dup_meta:
        st.json(dup_meta)
    else:
        st.success("No duplicate meta descriptions found in the crawled set.")

st.divider()


# =========================
# Link checks
# =========================
st.header("Link checks (classified)")
links_df: pd.DataFrame = res["links_df"]
if links_df is None or links_df.empty:
    st.info("Link checking is disabled or no link data was collected.")
else:
    st.dataframe(links_df, use_container_width=True)
    st.download_button(
        "Download links CSV",
        data=links_df.to_csv(index=False).encode("utf-8"),
        file_name="seo_links.csv",
        mime="text/csv",
    )

st.divider()


# =========================
# Phase 4 — Action Plan + Client Report
# =========================
st.header("Phase 4 — Action Plan + Client Report")

st.subheader("Executive Summary")
st.write(
    f"Audit completed for {res['final_url']} (HTTP {res['http_status']}). "
    f"Homepage score: {res['homepage_score']} ({res['homepage_grade']}). "
    f"Site score: {res['site_score']} ({res['site_grade']})."
)

st.subheader("Prioritised Fix List")
fix_list = res.get("fix_list", [])
if not fix_list:
    st.success("No fix items detected.")
else:
    fix_df = pd.DataFrame([{
        "priority": it.get("priority"),
        "scope": it.get("scope"),
        "issue": it.get("issue"),
        "why": it.get("why"),
        "how": it.get("how"),
    } for it in fix_list])
    st.dataframe(fix_df, use_container_width=True)

st.subheader("Quick Wins")
if fix_list:
    quick = [it["issue"] for it in fix_list[:5] if it.get("issue")]
    for q in quick:
        st.write("-", q)

# AI action plan (only if enabled)
if enable_ai:
    st.subheader("AI Action Plan (Client-ready)")
    ai_plan = res.get("ai_plan", {})
    if ai_plan.get("error"):
        st.error(ai_plan["error"])
    else:
        if ai_plan.get("executive_summary"):
            st.write(ai_plan["executive_summary"])
        if ai_plan.get("quick_wins"):
            st.write("**AI quick wins**")
            for q in ai_plan["quick_wins"]:
                st.write("-", q)
        if ai_plan.get("roadmap"):
            st.write("**AI roadmap**")
            for step in ai_plan["roadmap"]:
                st.write(step.get("label", ""))
                for item in step.get("items", []):
                    st.write("-", item)

# AI per-page suggestions
if enable_ai:
    st.subheader("AI Suggestions — Titles & Meta Descriptions")

    ai_sug = res.get("ai_suggestions") or {}
    ai_debug = res.get("ai_debug") or {}   # <-- NEW (we will add this in seo_check.py)

    # If the backend returned an explicit error object
    if "__error__" in ai_sug:
        err = ai_sug.get("__error__", {})
        st.error(err.get("notes", "AI error"))

        with st.expander("AI debug details"):
            st.write(ai_debug)

    # If we got suggestions
    elif isinstance(ai_sug, dict) and len(ai_sug) > 0:
        sug_rows = []
        for _, r in pages_df.iterrows():
            u = r.get("final_url") or r.get("url")
            s = ai_sug.get(u, {}) if isinstance(ai_sug, dict) else {}
            sug_rows.append({
                "url": u,
                "current_title": r.get("title"),
                "suggested_title": s.get("title_suggested", ""),
                "current_meta": r.get("meta_description"),
                "suggested_meta": s.get("meta_suggested", ""),
                "suggested_h1": s.get("h1_suggested", ""),
                "notes": s.get("notes", ""),
            })

        sug_df = pd.DataFrame(sug_rows)
        st.dataframe(sug_df, use_container_width=True)

        st.download_button(
            "Download AI suggestions CSV",
            data=sug_df.to_csv(index=False).encode("utf-8"),
            file_name="seo_ai_suggestions.csv",
            mime="text/csv",
        )

    # Otherwise show WHY it's empty (debug)
    else:
        st.warning("No AI suggestions returned.")

        # Show debug so we know if it's: missing key / invalid model / 401 / 429 / timeout / empty pages, etc.
        with st.expander("AI debug details (click to view)"):
            st.write(ai_debug)

        # Optional: quick sanity checks
        with st.expander("Sanity checks"):
            import os
            st.write("OPENROUTER_API_KEY loaded:", bool(os.getenv("OPENROUTER_API_KEY")))
            st.write("Pages rows passed to AI:", len(pages_df))
            st.write(pages_df[["final_url", "title", "meta_description"]].head(5))

if enable_ai and ai_include_code:
    st.subheader("AI Implementation Snippets (Copy/Paste)")
    impl = res.get("ai_implementation", {})

    if "__error__" in impl:
        st.error(impl["__error__"].get("notes", "AI implementation error"))
    else:
        items = impl.get("items", [])
        if not items:
            st.info("No implementation snippets returned.")
        else:
            for i, it in enumerate(items, start=1):
                st.markdown(f"### {i}. {it.get('title','Implementation')}")
                st.write(it.get("why", ""))

                if it.get("files"):
                    for f in it["files"]:
                        st.markdown(f"**File:** `{f.get('path','')}`")
                        st.code(f.get("code",""), language="text")

                if it.get("notes"):
                    st.caption(it["notes"])

            st.download_button(
                "Download implementation JSON",
                data=json.dumps(impl, indent=2).encode("utf-8"),
                file_name="seo_ai_implementation.json",
                mime="application/json",
            )

# =========================

# AI for getting SEO knowledge Q&A

# st.divider()
# st.header("SEO Learning Assistant (Ask Anything SEO)")

# if "seo_chat" not in st.session_state:
#     st.session_state.seo_chat = []

# seo_q = st.text_area(
#     "Ask a question about SEO (technical SEO, on-page, indexing, sitemaps, titles/meta, Core Web Vitals, etc.)",
#     placeholder="Example: Why is my page indexed but not ranking? What should I check first?",
#     height=120
# )

# ask = st.button("Ask SEO Assistant", disabled=not enable_ai)

# if ask:
#     if not enable_ai:
#         st.warning("Enable AI suggestions from the sidebar first.")
#     elif not seo_q.strip():
#         st.warning("Please type a question first.")
#     else:
#         with st.spinner("Thinking..."):
#             ans = ai_seo_qa(
#                 question=seo_q,
#                 site_name=site_name,
#                 model=ai_model,
#                 temperature=ai_temp,
#                 max_tokens=800
#             )

#         if not ans.get("ok"):
#             st.error(ans.get("error", "Unknown error"))
#         else:
#             # store in chat history
#             st.session_state.seo_chat.append({"q": seo_q.strip(), "a": ans["answer"]})

# # show history
# if st.session_state.seo_chat:
#     st.subheader("Conversation")
#     for i, item in enumerate(reversed(st.session_state.seo_chat[-8:]), start=1):
#         st.markdown(f"**Q{i}:** {item['q']}")
#         st.write(item["a"])
#         st.markdown("---")
# else:
#     st.info("No questions asked yet.")
# =========================

# =========================
# SEO Learning Assistant UI (NEW)
# =========================
st.header("SEO Learning Assistant (Ask Anything SEO)")

active_chat = st.session_state.seo_chats[st.session_state.active_seo_chat_idx]
messages = active_chat["messages"]

# Render messages ONCE (this avoids duplicates)
# Render messages ONCE
for m in messages:
    role = m.get("role", "assistant")
    mtype = m.get("type", "text")
    content = m.get("content", "")

    with st.chat_message(role):
        if mtype == "structured" and isinstance(content, dict):
            _render_rich_answer(content, idx=1)  # idx not critical for history
        else:
            st.markdown(str(content))

# Input box (chat style)
user_question = st.chat_input("Ask a question about SEO (technical SEO, on-page, indexing, sitemaps, titles/meta, CWV, etc.)")

def is_seo_question(q: str) -> bool:
    ql = (q or "").lower()
    seo_keywords = [
        "seo", "title tag", "meta description", "robots", "sitemap", "index", "crawl",
        "canonical", "redirect", "schema", "structured data", "core web vitals",
        "lcp", "cls", "inp", "hreflang", "internal link", "backlink", "serp"
    ]
    return any(k in ql for k in seo_keywords)

def build_structured_prompt(question: str) -> str:
    # This forces the AI to answer in the structured style you want
    return f"""
You are an SEO tutor. Answer ONLY about SEO.
If the user asks non-SEO topics, say: "Outside scope. I only answer SEO questions."

Return the answer in this structure (use headings + bullets, and code blocks if needed):
1) Quick answer (2–4 lines)
2) Key points (bullets)
3) Step-by-step (numbered)
4) Example / code (only if relevant)
5) Common mistakes (bullets)
6) Checklist (short)

User question: {question}
""".strip()

# =========================
# Submit flow — structured JSON (NO duplicate full-answer inside)
# =========================
if user_question:
    # 1) Save user message
    active_chat["messages"].append({"role": "user", "type": "text", "content": user_question})

    with st.chat_message("user"):
        st.markdown(user_question)

    # 2) Guardrail: only SEO
    if not is_seo_question(user_question):
        assistant_text = "Outside scope. I only answer questions related to Search Engine Optimization (SEO)."
        active_chat["messages"].append({"role": "assistant", "type": "text", "content": assistant_text})

        with st.chat_message("assistant"):
            st.markdown(assistant_text)

        st.stop()

    # 3) Call your structured assistant (IMPORTANT)
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            ans = ai_seo_learning_answer(
                question=user_question,
                site_name=site_name,
                model=ai_model,
                temperature=ai_temp
            )

            # if backend returned error
            if "__error__" in ans:
                assistant_text = f"AI error: {ans['__error__'].get('notes', 'Unknown error')}"
                st.error(assistant_text)
                active_chat["messages"].append({"role": "assistant", "type": "text", "content": assistant_text})
            else:
                # render nicely
                _render_rich_answer(ans, idx=len([m for m in messages if m["role"] == "assistant"]) + 1)

                # store the structured object, NOT markdown text
                active_chat["messages"].append({"role": "assistant", "type": "structured", "content": ans})

# =========================

# st.subheader("Export")
# report_md = res.get("report_md", "")
# st.download_button(
#     "Download report (Markdown)",
#     data=report_md.encode("utf-8"),
#     file_name="seo_audit_report.md",
#     mime="text/markdown",
# )

# with st.expander("Preview report (Markdown)"):
#     st.markdown(report_md)

# with st.expander("Show raw HTML (first 30k chars) — homepage fetch"):
#     # We do not store full HTML in res intentionally (privacy + memory).
#     # If you want it, we can add it, but for now show a helpful message.
#     st.info("Raw HTML is not stored in memory in this version. If you want raw HTML preview, tell me and I’ll add it safely (homepage only).")
