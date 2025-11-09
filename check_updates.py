#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Software Checker GUI v4.7 (J. Tsakalos)

Run:
  pip install requests packaging beautifulsoup4
  python check_updates.py -c apps.json
  python check_updates.py -c apps.json --timing-csv timings.csv
"""




import argparse, json, sys, threading, webbrowser, shutil, subprocess, csv, time
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog






# ---------------- core ----------------
missing = []
try:
    import requests
except Exception:
    missing.append("requests")
try:
    from packaging.version import Version
except Exception:
    missing.append("packaging")
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None
    missing.append("beautifulsoup4")

if missing:
    sys.stderr.write(
        "Missing dependencies: " + ", ".join(missing) + "\n"
        "Install with:  pip install " + " ".join(missing) + "\n"
    )


def safe_str(s):
    return (s or "").strip()


def normalize_version(v):
    return safe_str(v).lstrip("vV")


def cmp_versions(a, b):
    a, b = normalize_version(a), normalize_version(b)
    try:
        va, vb = Version(a), Version(b)
        return (va > vb) - (va < vb)
    except Exception:
        return (a > b) - (a < b)


_session = None


def session():
    global _session
    if _session is None:
        from requests import Session
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        s = Session()
        s.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.7",
            }
        )
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://", HTTPAdapter(max_retries=retry))
        _session = s
    return _session


def http_get(url, timeout=15, headers=None):
    s = session()
    if headers:
        return s.get(url, timeout=timeout, headers={**s.headers, **headers})
    return s.get(url, timeout=timeout)


import re as _re


def _flags(s):
    if not s:
        return _re.IGNORECASE | _re.MULTILINE | _re.DOTALL
    f = 0
    for t in _re.split(r"[,\s]+", s.strip().upper()):
        if not t:
            continue
        if t in ("I", "IGNORECASE"):
            f |= _re.IGNORECASE
        elif t in ("M", "MULTILINE"):
            f |= _re.MULTILINE
        elif t in ("S", "DOTALL"):
            f |= _re.DOTALL
        elif t in ("X", "VERBOSE"):
            f |= _re.VERBOSE
    return f or (_re.IGNORECASE | _re.MULTILINE | _re.DOTALL)


def get_latest_from_webpage_regex(entry):
    r = http_get(
        entry["url"],
        timeout=int(entry.get("timeout", 15)),
        headers=entry.get("headers"),
    )
    r.raise_for_status()
    rx = _re.compile(entry["regex"], _flags(entry.get("flags")))
    matches = rx.findall(r.text)
    vals = []
    for m in matches:
        if isinstance(m, (tuple, list)):
            m = m[0]
        vals.append(safe_str(str(m)).lstrip("vV"))
    diag = {"match_count": len(vals), "candidates": vals[:5]}
    if not vals:
        return "", diag
    try:
        return str(max(vals, key=lambda v: Version(v))), diag
    except Exception:
        return max(vals), diag


def get_latest_from_webpage_bs4(entry):
    if BeautifulSoup is None:
        raise RuntimeError(
            "BeautifulSoup is not installed. Install with: pip install beautifulsoup4"
        )
    r = http_get(
        entry["url"],
        timeout=int(entry.get("timeout", 15)),
        headers=entry.get("headers"),
    )
    r.raise_for_status()
    html = r.text
    parser = (entry.get("parser") or "").lower()
    if parser == "lxml":
        soup = BeautifulSoup(html, "lxml")
    else:
        soup = BeautifulSoup(html, "html.parser")

    selector = entry.get("selector") or entry.get("css")
    if not selector:
        raise ValueError("Missing 'selector' in entry (type='beautifulsoup').")

    # normalize deprecated :contains() to :-soup-contains()
    # (affects JSON entries like *:contains("..."))
    selector = _re.sub(r":contains\(", ":-soup-contains(", selector)

    nodes = soup.select(selector)
    texts = [safe_str(n.get_text(" ", strip=True)) for n in nodes]
    diag = {"node_count": len(nodes), "candidates": texts[:5]}
    regex = entry.get("regex")
    vals = []
    if regex:
        rx = _re.compile(regex, _flags(entry.get("flags")))
        for t in texts:
            m = rx.search(t)
            if m:
                if m.groups():
                    vals.append(safe_str(m.group(1)).lstrip("vV"))
                else:
                    vals.append(safe_str(m.group(0)).lstrip("vV"))
    else:
        version_re = _re.compile(r"\d+(?:\.\d+)+")
        for t in texts:
            for m in version_re.findall(t):
                vals.append(safe_str(m).lstrip("vV"))
    diag["match_count"] = len(vals)
    diag["candidates"] = vals[:5]
    if not vals:
        return "", diag
    try:
        return str(max(vals, key=lambda v: Version(v))), diag
    except Exception:
        return max(vals), diag


def get_latest_from_github(repo):
    def pick_max(ss):
        vals = []
        for s in ss:
            m = _re.search(r"v?(\d+(?:\.\d+)+)", s or "")
            if m:
                vals.append(m.group(1))
        if not vals:
            return ""
        try:
            return str(max(vals, key=lambda v: Version(v)))
        except Exception:
            return max(vals)

    headers = {}
    import os

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"token {token.strip()}"
    r = http_get(
        f"https://api.github.com/repos/{repo}/releases", timeout=15, headers=headers
    )
    if r.status_code == 200:
        names = []
        for rel in r.json():
            if rel.get("draft"):
                continue
            if rel.get("tag_name"):
                names.append(rel["tag_name"])
            if rel.get("name"):
                names.append(rel["name"])
        v = pick_max(names)
        if v:
            return v
    r2 = http_get(
        f"https://api.github.com/repos/{repo}/tags", timeout=15, headers=headers
    )
    if r2.status_code == 200:
        v = pick_max([t.get("name", "") for t in r2.json()])
        if v:
            return v
    r3 = http_get(
        f"https://api.github.com/repos/{repo}/releases/latest",
        timeout=15,
        headers=headers,
    )
    if r3.status_code == 200:
        s = r3.json().get("tag_name") or r3.json().get("name") or ""
        m = _re.search(r"v?(\d+(?:\.\d+)+)", s or "")
        if m:
            return m.group(1)
    return ""


def extract_json_path(d, path):
    n = d
    for k in path.split("."):
        if isinstance(n, dict) and k in n:
            n = n[k]
        else:
            return ""
    return str(n)


def get_latest_from_json_api(url, jpath, entry=None):
    r = http_get(
        url,
        timeout=int((entry or {}).get("timeout", 15)),
        headers=(entry or {}).get("headers"),
    )
    r.raise_for_status()
    return safe_str(extract_json_path(r.json(), jpath))


def get_latest_from_winget(wid):
    if not shutil.which("winget"):
        return ""
    try:
        p = subprocess.run(
            ["winget", "show", "--id", wid, "--source", "winget"],
            capture_output=True,
            text=True,
            timeout=12,
        )
    except Exception:
        return ""
    for ln in (p.stdout or "").splitlines():
        if ln.lower().startswith("version:"):
            return ln.split(":", 1)[1].strip()
    return ""


def check_entry(entry):
    name = entry.get("name", "?")
    et = safe_str(entry.get("type", "")).lower()
    cur = safe_str(entry.get("current_version", ""))
    diag = {}
    det = ""
    latest = ""
    try:
        if et in ("regex", "webpage_regex", "webpage", "web"):
            latest, diag = get_latest_from_webpage_regex(entry)
            det = f"regex:{entry.get('url', '')}"
        elif et in ("beautifulsoup", "bs4", "webpage_bs4"):
            latest, diag = get_latest_from_webpage_bs4(entry)
            det = f"beautifulsoup:{entry.get('url', '')}"
        elif et == "github_release":
            latest = get_latest_from_github(entry["repo"])
            det = f"github_release:{entry['repo']}"
        elif et == "json_api":
            latest = get_latest_from_json_api(
                entry["url"], entry["json_path"], entry
            )
            det = f"json_api:{entry['url']}#{entry['json_path']}"
        elif et == "winget":
            latest = get_latest_from_winget(entry["winget_id"])
            det = f"winget:{entry['winget_id']}"
        else:
            return {
                "name": name,
                "current": cur,
                "latest": "",
                "status": "error",
                "details": f"Unknown type: {et}",
                "category": entry.get("category", "Uncategorized"),
                "description": entry.get("description", ""),
                "entry": entry,
            }
        latest = normalize_version(latest)
        if not latest:
            return {
                "name": name,
                "current": cur,
                "latest": "",
                "status": "error",
                "details": "Could not determine latest version",
                "category": entry.get("category", "Uncategorized"),
                "description": entry.get("description", ""),
                "diag": diag,
                "entry": entry,
            }
        c = cmp_versions(cur, latest)
        st = "outdated" if c < 0 else ("up_to_date" if c == 0 else "ahead")
        return {
            "name": name,
            "current": cur,
            "latest": latest,
            "status": st,
            "details": det,
            "category": entry.get("category", "Uncategorized"),
            "description": entry.get("description", ""),
            "diag": diag,
            "entry": entry,
        }
    except Exception as e:
        return {
            "name": name,
            "current": cur,
            "latest": "",
            "status": "error",
            "details": f"{e.__class__.__name__}: {e}",
            "category": entry.get("category", "Uncategorized"),
            "description": entry.get("description", ""),
            "entry": entry,
        }


def load_catalog(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"apps": []}
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read {p}\n{e}")
        return {"apps": []}


def save_catalog(p: Path, data):
    try:
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to write {p}\n{e}")







# ---------------- GUI ----------------
class ScrollableFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self.inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_mousewheel(self, e):
        self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")


class App(tk.Tk):
    # Column widths for the lower results table
    COL_WIDTHS = [240, 80, 110, 420, 160]  # SOFTWARE, VERSION, NEW VER., Description, Actions

    def __init__(self, catalog_path: Path, timing_csv: Path | None = None):
        super().__init__()
        self.title("Software Checker GUI v4.7 (J. Tsakalos)")
        self.geometry("1040x700")
        self.minsize(900, 560)

        self.catalog_path = catalog_path
        self.catalog = load_catalog(catalog_path)
        self.results: list[dict] = []

        # For upper filter tree (expand/collapse + checkboxes)
        self.cat_state: dict[str, bool] = {}   # "A / B / C" -> expanded?
        self.cat_vars: dict[str, tk.BooleanVar] = {}   # "A / B / C" -> selected?

        # For lower results view
        self.show_only_outdated = tk.BooleanVar(value=False)

        # Optional timing CSV path
        self.timing_csv = timing_csv

        # --- Top toolbar ---
        top = ttk.Frame(self)
        top.pack(side="top", fill="x", padx=8, pady=(8, 4))

        self.status = ttk.Label(top, text="Ready.")
        self.status.pack(side="left")

        ttk.Button(top, text="Check Now", command=self.run_check).pack(side="right")
        ttk.Button(top, text="ALL", command=self.show_all).pack(side="right", padx=(6, 6))
        ttk.Button(top, text="Outdated", command=self.show_outdated).pack(side="right")

        # --- Upper frame: category filter tree ---
        self.filter_scroller = ScrollableFrame(self)
        self.filter_scroller.pack(side="top", fill="both", expand=False, padx=8, pady=(0, 4), ipady=40)

        # --- Lower frame: results table ---
        self.results_scroller = ScrollableFrame(self)
        self.results_scroller.pack(side="top", fill="both", expand=True, padx=8, pady=(0, 8))

        # Build initial filter UI and empty results
        self.build_filter_ui_from_catalog()
        self.build_results_ui([])

        # Run initial check shortly after startup
        self.after(300, self.run_check)

    # ---- small helpers ----
    def color_for(self, st: str) -> str:
        return {
            "outdated": "#e57373",
            "up_to_date": "#81c784",
            "ahead": "#64b5f6",
            "error": "#b0bec5",
        }.get(st, "#cfd8dc")

    def row_with_status_bar(self, parent, status_color):
        row = tk.Frame(parent)
        tk.Frame(row, bg=status_color, width=6, height=1).pack(side="left", fill="y")
        content = ttk.Frame(row)
        content.pack(side="left", fill="x", expand=True, padx=6)
        for i, px in enumerate(self.COL_WIDTHS):
            content.grid_columnconfigure(i, minsize=px)
        return row, content

    def _apply_header_grid(self, container):
        for i, px in enumerate(self.COL_WIDTHS):
            container.grid_columnconfigure(i, minsize=px)





    # ---------- category selectors (upper frame) ----------
    def _split_category_parts(self, cat: str):
        import re as _re
        parts = [p.strip() for p in _re.split(r"\s*-\s*", safe_str(cat)) if p.strip()]
        return parts or ["Uncategorized"]

    def _build_category_tree_from_catalog(self):
        root = {"__children__": {}}
        for a in self.catalog.get("apps", []):
            parts = self._split_category_parts(a.get("category", "Uncategorized"))
            node = root
            for p in parts:
                node = node["__children__"].setdefault(p, {"__children__": {}})
        return root

    def _on_filter_changed(self, *_):
        # Called whenever any checkbox changes -> re-filter lower results
        self.refresh_view()

    def _render_filter_node(self, container, path_parts, name, node, level):
        # name is None for root
        if name is not None:
            key = " / ".join(path_parts + [name])
            expanded = self.cat_state.get(key, False)

            row = ttk.Frame(container)
            row.pack(fill="x", pady=(2, 0), padx=(level * 16, 0))

            icon = "▼" if expanded else "▶"

            # BooleanVar for checkbox
            var = self.cat_vars.get(key)
            if var is None:
                var = tk.BooleanVar(value=False)
                # IMPORTANT: when this var changes, refresh the results view
                var.trace_add("write", self._on_filter_changed)
                self.cat_vars[key] = var

            # Expand/collapse button
            btn = tk.Button(
                row,
                text=f"{icon}  {name}",
                bd=0,
                relief="flat",
                cursor="hand2",
                anchor="w",
            )
            btn.pack(side="left", fill="x", expand=True)

            # Checkbox at the right
            chk = ttk.Checkbutton(row, variable=var)
            chk.pack(side="right")

            body = ttk.Frame(container)
            if expanded:
                body.pack(fill="x")

            def toggle(k=key, frame=body, button=btn, nm=name):
                self.cat_state[k] = not self.cat_state.get(k, False)
                if self.cat_state[k]:
                    frame.pack(fill="x")
                else:
                    frame.forget()
                button.config(text=("▼  " if self.cat_state[k] else "▶  ") + nm)

            btn.configure(command=toggle)
        else:
            body = container

        # Render children
        for child_name, child_node in sorted(node["__children__"].items(), key=lambda kv: kv[0].lower()):
            self._render_filter_node(body, path_parts + ([name] if name else []), child_name, child_node, level + 1)



    def build_filter_ui_from_catalog(self):
        for w in self.filter_scroller.inner.winfo_children():
            w.destroy()

        # Header row: label + None / All buttons
        header = ttk.Frame(self.filter_scroller.inner)
        header.pack(fill="x", padx=4, pady=(2, 4))

        ttk.Label(
            header,
            text="Category filter (select multiple & expand/collapse):",
            font=("", 10, "bold"),
        ).pack(side="left", anchor="w")

        ttk.Button(
            header,
            text="None",
            command=self._select_no_categories,
        ).pack(side="right", padx=(4, 0))

        ttk.Button(
            header,
            text="All",
            command=self._select_all_categories,
        ).pack(side="right")

        tree = self._build_category_tree_from_catalog()
        self._render_filter_node(self.filter_scroller.inner, [], None, tree, level=0)


    def _selected_category_keys(self):
        return {k for k, var in self.cat_vars.items() if var.get()}

    def _filter_by_category(self, records: list[dict]) -> list[dict]:
        selected = self._selected_category_keys()
        # If nothing is selected, show nothing
        if not selected:
            return []

        out = []
        for r in records:
            cat = r.get("category", "Uncategorized")
            parts = self._split_category_parts(cat)
            path = []
            matched = False
            for p in parts:
                path.append(p)
                key = " / ".join(path)
                if key in selected:
                    matched = True
                    break
            if matched:
                out.append(r)
        return out

    def _select_all_categories(self):
        # Tick all checkboxes; each var.trace triggers refresh_view automatically
        for var in self.cat_vars.values():
            var.set(True)

    def _select_no_categories(self):
        # Untick all checkboxes; will show no records
        for var in self.cat_vars.values():
            var.set(False)






    # ---------- results UI (lower frame, flat records' result list) ----------
    def build_results_ui(self, results: list[dict]):
        for w in self.results_scroller.inner.winfo_children():
            w.destroy()

        header = ttk.Frame(self.results_scroller.inner)
        header.pack(fill="x", padx=4, pady=(0, 6))
        self._apply_header_grid(header)
        ttk.Label(header, text="SOFTWARE").grid(row=0, column=0, sticky="w")
        ttk.Label(header, text="VERSION").grid(row=0, column=1, sticky="w")
        ttk.Label(header, text="NEW VER.").grid(row=0, column=2, sticky="w")
        ttk.Label(header, text="Description").grid(row=0, column=3, sticky="w")
        ttk.Label(header, text="Actions").grid(row=0, column=4, sticky="w")

        for r in sorted(results, key=lambda x: x.get("name", "").lower()):
            status_color = self.color_for(r["status"])
            row, content = self.row_with_status_bar(self.results_scroller.inner, status_color)
            row.pack(fill="x", padx=4, pady=4)

            ttk.Label(content, text=r["name"], font=("", 11)).grid(row=0, column=0, sticky="w")
            ttk.Label(content, text=r["current"]).grid(row=0, column=1, sticky="w")

            new_lbl = ttk.Label(content, text=r.get("latest", "?"))
            if r["status"] == "outdated":
                new_lbl.configure(foreground="#b71c1c")
            elif r["status"] == "up_to_date":
                new_lbl.configure(foreground="#1b5e20")
            elif r["status"] == "ahead":
                new_lbl.configure(foreground="#0d47a1")
            new_lbl.grid(row=0, column=2, sticky="w")

            desc = tk.Message(
                content,
                text=r.get("description", ""),
                width=self.COL_WIDTHS[3] - 10,
                anchor="w",
                justify="left",
            )
            desc.grid(row=0, column=3, rowspan=2, sticky="w")

            right = ttk.Frame(content)
            right.grid(row=0, column=4, rowspan=2, sticky="e")

            dl = r.get("entry", {}).get("direct_dl") or ""
            bdl = ttk.Button(right, text="Direct DL", width=12, command=lambda u=dl: self.open_dl(u))
            if not dl:
                bdl.state(["disabled"])
            bdl.grid(row=0, column=0, padx=4, pady=2)

            ttk.Button(right, text="Ver Upd", width=12, command=lambda rr=r: self.update_version(rr)).grid(
                row=0, column=1, padx=4, pady=2
            )
            ttk.Label(right, text=r["status"]).grid(row=1, column=0, columnspan=2)

            ttk.Separator(self.results_scroller.inner, orient="horizontal").pack(fill="x", padx=4, pady=2)





    # ---------- actions ----------
    def open_dl(self, url: str):
        if url:
            webbrowser.open(url)

    def update_version(self, r: dict):
        app = r["entry"]
        current = app.get("current_version", "")
        ans = simpledialog.askstring(
            "Update Version",
            f"Set installed version for '{app.get('name')}'",
            initialvalue=current,
            parent=self,
        )
        if not ans:
            return
        for a in self.catalog.get("apps", []):
            if a.get("name", "").lower() == app.get("name", "").lower():
                a["current_version"] = ans.strip()
                break
        save_catalog(self.catalog_path, self.catalog)
        self.status.config(text=f"Saved new version for {app.get('name')}: {ans.strip()}")

        def do_one():
            res = check_entry(app | {"current_version": ans.strip()})
            for i, x in enumerate(self.results):
                if x["name"].lower() == res["name"].lower():
                    self.results[i] = res
                    break
            self.after(0, self.refresh_view)

        threading.Thread(target=do_one, daemon=True).start()

    def show_outdated(self):
        self.show_only_outdated.set(True)
        self.refresh_view()

    def show_all(self):
        self.show_only_outdated.set(False)
        self.refresh_view()

    def refresh_view(self):
        # Base data = last check results
        data = self.results
        # Filter by outdated/all
        if self.show_only_outdated.get():
            data = [r for r in data if r["status"] == "outdated"]
        # Filter by selected categories from upper frame
        data = self._filter_by_category(data)
        # Rebuild lower UI
        self.build_results_ui(data)
        n_out = sum(1 for r in self.results if r["status"] == "outdated")
        self.status.config(
            text=f"{len(self.results)} apps — {n_out} outdated — {datetime.now().strftime('%H:%M:%S')}"
        )

    def run_check(self):
        import csv, time
        self.status.config(text="Checking…")
        self.results = []

        def worker():
            from concurrent.futures import ThreadPoolExecutor, as_completed
            apps = self.catalog.get("apps", [])
            res: list[dict] = []
            per_app_times: list[tuple[str, float]] = []

            if apps:
                def timed_check(a: dict):
                    start = time.perf_counter()
                    r = check_entry(a)
                    elapsed = time.perf_counter() - start
                    r["elapsed"] = elapsed
                    return r

                with ThreadPoolExecutor(max_workers=min(8, max(2, len(apps)))) as ex:
                    futs = {ex.submit(timed_check, a): a for a in apps}
                    for f in as_completed(futs):
                        try:
                            r = f.result()
                        except Exception as e:
                            a = futs[f]
                            r = {
                                "name": a.get("name", "?"),
                                "current": a.get("current_version", ""),
                                "latest": "",
                                "status": "error",
                                "details": str(e),
                                "category": a.get("category", "Uncategorized"),
                                "description": a.get("description", ""),
                                "entry": a,
                                "elapsed": 0.0,
                            }
                        res.append(r)
                        per_app_times.append((r["name"], r.get("elapsed", 0.0)))

            self.results = res

            # CSV output if requested
            if self.timing_csv is not None:
                try:
                    self.timing_csv.parent.mkdir(parents=True, exist_ok=True)
                    with self.timing_csv.open("w", newline="", encoding="utf-8") as f:
                        w = csv.writer(f)
                        w.writerow(["name", "seconds"])
                        for name, secs in per_app_times:
                            w.writerow([name, f"{secs:.3f}"])
                except Exception as e:
                    self.after(
                        0,
                        lambda: messagebox.showerror(
                            "Timing CSV error",
                            f"Failed to write timing CSV:\n{e}",
                        ),
                    )

            self.after(0, self.refresh_view)

        threading.Thread(target=worker, daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--catalog", default="apps.json")
    ap.add_argument(
        "--timing-csv",
        help="Write per-app timing CSV after each check (columns: name,seconds).",
        default=None,
    )
    args = ap.parse_args()

    timing_path = Path(args.timing_csv) if args.timing_csv else None
    App(Path(args.catalog), timing_csv=timing_path).mainloop()


if __name__ == "__main__":
    main()
