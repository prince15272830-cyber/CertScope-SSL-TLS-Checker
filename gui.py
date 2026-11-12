import csv
import json
import ssl
import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime, timezone
from pathlib import Path

WARNING_OPTIONS = (7, 14, 30, 60, 90)
SETTINGS_FILE = Path(__file__).with_name("checker_settings.json")


def load_warning_days():
    try:
        with SETTINGS_FILE.open("r", encoding="utf-8") as settings_file:
            days = int(json.load(settings_file).get("warning_days", 30))
        return days if days in WARNING_OPTIONS else 30
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 30


WARNING_DAYS = load_warning_days()
COLORS = {
    "background": "#0b1220",
    "panel": "#111c2e",
    "panel_light": "#17243a",
    "text": "#e5edf8",
    "muted": "#91a2bb",
    "accent": "#45c6a8",
    "blue": "#5a9bff",
    "green": "#36c98f",
    "yellow": "#f2bd4b",
    "red": "#ff6b72",
}

HISTORY_FILE = Path(__file__).with_name("certificate_scan_history.csv")
HISTORY_COLUMNS = [
    "scanned_at", "domain", "status", "issuer", "expiry_date",
    "days_left", "tls_version", "details",
]


def load_history():
    """Restore earlier scans from the CSV kept beside this program."""
    try:
        with HISTORY_FILE.open("r", newline="", encoding="utf-8-sig") as csv_file:
            records = list(csv.DictReader(csv_file))
    except (OSError, csv.Error):
        return []

    for record in records:
        days = record.get("days_left", "")
        try:
            record["days_left"] = int(days)
        except (TypeError, ValueError):
            record["days_left"] = ""
    return records


def save_history():
    """Save all scans so they remain available the next time the app opens."""
    with HISTORY_FILE.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=HISTORY_COLUMNS)
        writer.writeheader()
        writer.writerows(history)


def save_warning_days(_event=None):
    try:
        with SETTINGS_FILE.open("w", encoding="utf-8") as settings_file:
            json.dump({"warning_days": int(warning_threshold.get())}, settings_file, indent=2)
    except OSError as error:
        messagebox.showerror("Setting could not be saved", str(error))


history = load_history()


def normalize_domain(value):
    domain = value.strip()
    domain = domain.removeprefix("https://").removeprefix("http://")
    domain = domain.split("/")[0].split(":")[0].strip()
    if not domain or any(char.isspace() for char in domain):
        return None
    return domain


def scan_certificate(domain):
    """Check a certificate using Python's normal trusted-certificate verification."""
    record = {
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "domain": domain,
        "issuer": "",
        "expiry_date": "",
        "days_left": "",
        "tls_version": "",
        "status": "",
        "details": "",
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                certificate = secure_sock.getpeercert()
                issuer_parts = certificate.get("issuer", ())
                record["issuer"] = ", ".join(
                    f"{key}={value}"
                    for group in issuer_parts
                    for key, value in group
                ) or "Not available"
                record["tls_version"] = secure_sock.version() or "Not available"
                expiry_text = certificate.get("notAfter")
                if expiry_text:
                    expiry = datetime.strptime(
                        expiry_text, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    record["expiry_date"] = expiry.strftime("%Y-%m-%d %H:%M UTC")
                    record["days_left"] = days_left
                    if days_left < 0:
                        record["status"] = "EXPIRED"
                    elif days_left <= WARNING_DAYS:
                        record["status"] = "EXPIRING SOON"
                    else:
                        record["status"] = "VALID"
                else:
                    record["status"] = "UNKNOWN"
                    record["details"] = "Expiry date unavailable"
    except ssl.SSLCertVerificationError as error:
        details = getattr(error, "verify_message", str(error))
        lower = details.lower()
        if "expired" in lower:
            record["status"] = "EXPIRED / UNVERIFIED"
        elif "hostname" in lower or "doesn't match" in lower:
            record["status"] = "HOSTNAME MISMATCH"
        else:
            record["status"] = "VERIFICATION FAILED"
        record["details"] = details
    except socket.gaierror:
        record["status"] = "DOMAIN NOT FOUND"
        record["details"] = "Check the spelling of the website domain."
    except (socket.timeout, TimeoutError):
        record["status"] = "TIMEOUT"
        record["details"] = "The website did not respond in time."
    except ssl.SSLError as error:
        record["status"] = "TLS ERROR"
        record["details"] = str(error)
    except OSError as error:
        record["status"] = "CONNECTION ERROR"
        record["details"] = str(error)
    return record


def status_color(status):
    if status == "VALID":
        return COLORS["green"]
    if status == "EXPIRING SOON":
        return COLORS["yellow"]
    if status.startswith("EXPIRED") or status in ("HOSTNAME MISMATCH", "VERIFICATION FAILED"):
        return COLORS["red"]
    return COLORS["muted"]


def update_overview():
    total = len(history)
    valid = sum(record.get("status") == "VALID" for record in history)
    expiring = sum(record.get("status") == "EXPIRING SOON" for record in history)
    issues = total - valid - expiring
    overview_total.config(text=str(total))
    overview_valid.config(text=str(valid))
    overview_expiring.config(text=str(expiring))
    overview_issues.config(text=str(issues))


def refresh_history(_event=None):
    query = history_search.get().strip().lower()
    selected_status = status_filter.get()
    shown = 0
    for row_id in history_tree.get_children():
        history_tree.delete(row_id)

    for record in reversed(history):
        domain = record.get("domain", "")
        status = record.get("status", "")
        matches_domain = query in domain.lower()
        matches_status = (
            selected_status == "All statuses"
            or (selected_status == "Valid" and status == "VALID")
            or (selected_status == "Expiring soon" and status == "EXPIRING SOON")
            or (selected_status == "Issues" and status not in ("VALID", "EXPIRING SOON"))
        )
        if matches_domain and matches_status:
            history_tree.insert(
                "", "end",
                values=(record.get("scanned_at", ""), domain, status,
                        record.get("days_left", ""), record.get("tls_version", "")),
                tags=(status,),
            )
            shown += 1

    if query or selected_status != "All statuses":
        history_count.config(text=f"{shown} of {len(history)} scans")
    else:
        history_count.config(text=f"{len(history)} scan{'s' if len(history) != 1 else ''}")


def show_selected_history(_event=None):
    selection = history_tree.selection()
    if not selection:
        return
    values = history_tree.item(selection[0], "values")
    scanned_at, domain = values[0], values[1]
    record = next(
        (item for item in reversed(history)
         if item.get("scanned_at") == scanned_at and item.get("domain") == domain),
        None,
    )
    if not record:
        return
    status = record.get("status", "UNKNOWN")
    status_value.config(text=f"HISTORY · {status}", fg=status_color(status))
    domain_value.config(text=domain or "Unavailable")
    issuer_value.config(text=record.get("issuer", "") or "Unavailable")
    expiry_value.config(text=record.get("expiry_date", "") or "Unavailable")
    days = record.get("days_left", "")
    days_value.config(text=f"{days} days" if isinstance(days, int) else "Unknown")
    tls_value.config(text=record.get("tls_version", "") or "Unavailable")
    detail_value.config(text=record.get("details", "") or f"Scanned at {scanned_at}")


def rescan_selected_history():
    selection = history_tree.selection()
    if not selection:
        messagebox.showinfo("Select a scan", "Choose a history row first, then click Rescan selected.")
        return
    values = history_tree.item(selection[0], "values")
    domain_text.delete("1.0", tk.END)
    domain_text.insert("1.0", values[1])
    start_scan()


sort_directions = {}


def sort_history(column):
    column_index = columns.index(column)
    reverse = sort_directions.get(column, False)
    rows = [(row_id, history_tree.item(row_id, "values"))
            for row_id in history_tree.get_children("")]

    def sort_key(row):
        value = row[1][column_index]
        if column == "days":
            try:
                return (0, int(value))
            except (TypeError, ValueError):
                return (1, 0)
        return (0, str(value).lower())

    rows.sort(key=sort_key, reverse=reverse)
    for position, (row_id, _values) in enumerate(rows):
        history_tree.move(row_id, "", position)
    sort_directions[column] = not reverse


def show_record(record):
    status_value.config(text=record["status"], fg=status_color(record["status"]))
    domain_value.config(text=record["domain"])
    issuer_value.config(text=record["issuer"] or "Unavailable")
    expiry_value.config(text=record["expiry_date"] or "Unavailable")
    days = record["days_left"]
    days_value.config(text=f"{days} days" if isinstance(days, int) else "Unknown")
    tls_value.config(text=record["tls_version"] or "Unavailable")
    detail_value.config(text=record["details"])
    history.append(record)
    try:
        save_history()
    except OSError as error:
        messagebox.showerror(
            "History could not be saved",
            f"This scan is visible for now, but could not be saved for next time.\n\n{error}",
        )
    refresh_history()
    update_overview()


def finish_batch(records):
    for record in records:
        show_record(record)
    scan_button.config(state="normal", text="Scan domain list")
    if records:
        status_value.config(text=f"SCAN COMPLETE · {records[-1]['status']}",
                            fg=status_color(records[-1]["status"]))


def update_scan_progress(index, total, domain):
    status_value.config(
        text=f"SCANNING {index} OF {total} · {domain}",
        fg=COLORS["blue"],
    )
    detail_value.config(text=f"Checking {domain} securely…")


def update_progress_bar(completed):
    progress_bar.configure(value=completed)


def load_domain_list():
    path = filedialog.askopenfilename(
        title="Choose a domain list",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not path:
        return
    try:
        with open(path, "r", encoding="utf-8-sig") as list_file:
            contents = list_file.read()
    except OSError as error:
        messagebox.showerror("Could not open domain list", str(error))
        return

    domain_text.delete("1.0", tk.END)
    domain_text.insert("1.0", contents.strip())
    line_count = sum(bool(line.strip()) for line in contents.replace(",", "\n").splitlines())
    detail_value.config(text=f"Loaded a list with {line_count} non-empty line(s). Review it, then scan.")


def start_scan():
    global WARNING_DAYS
    WARNING_DAYS = int(warning_threshold.get())
    domains = []
    for item in domain_text.get("1.0", "end-1c").replace(",", "\n").splitlines():
        domain = normalize_domain(item)
        if domain and domain not in domains:
            domains.append(domain)
    if not domains:
        messagebox.showerror("Input needed", "Enter one or more domains, separated by commas or new lines.")
        return
    scan_button.config(state="disabled", text="Scanning…")
    progress_bar.configure(maximum=len(domains), value=0)
    status_value.config(text=f"SCANNING {len(domains)} DOMAIN{'S' if len(domains) != 1 else ''}…",
                        fg=COLORS["blue"])
    detail_value.config(text="Connecting securely and checking certificate details…")

    def worker():
        records = []
        for index, domain in enumerate(domains, start=1):
            root.after(0, update_scan_progress, index, len(domains), domain)
            records.append(scan_certificate(domain))
            root.after(0, update_progress_bar, index)
        root.after(0, finish_batch, records)

    threading.Thread(target=worker, daemon=True).start()


def export_csv():
    if not history:
        messagebox.showinfo("No scan history", "Run a scan before exporting a CSV report.")
        return
    path = filedialog.asksaveasfilename(
        title="Save scan history", defaultextension=".csv",
        filetypes=[("CSV file", "*.csv")], initialfile="certificate_scan_history.csv",
    )
    if not path:
        return
    try:
        with open(path, "w", newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=HISTORY_COLUMNS)
            writer.writeheader()
            writer.writerows(history)
        messagebox.showinfo("Export complete", f"Saved {len(history)} scan result(s) to:\n{path}")
    except OSError as error:
        messagebox.showerror("Could not save CSV", str(error))


root = tk.Tk()
root.title("SSL/TLS Certificate Checker")
root.geometry("1080x820")
root.minsize(900, 700)
root.configure(bg=COLORS["background"])

page = tk.Frame(root, bg=COLORS["background"])
page.pack(fill="both", expand=True)
page_canvas = tk.Canvas(page, bg=COLORS["background"], highlightthickness=0)
page_scrollbar = ttk.Scrollbar(page, orient="vertical", command=page_canvas.yview)
page_scrollbar.pack(side="right", fill="y")
page_canvas.pack(side="left", fill="both", expand=True)
page_canvas.configure(yscrollcommand=page_scrollbar.set)
content = tk.Frame(page_canvas, bg=COLORS["background"])
content_window = page_canvas.create_window((0, 0), window=content, anchor="nw")


def update_page_scroll_region(_event=None):
    page_canvas.configure(scrollregion=page_canvas.bbox("all"))


def fit_page_width(event):
    page_canvas.itemconfigure(content_window, width=event.width)


def scroll_page(event):
    page_canvas.yview_scroll(int(-event.delta / 120), "units")


content.bind("<Configure>", update_page_scroll_region)
page_canvas.bind("<Configure>", fit_page_width)
root.bind_all("<MouseWheel>", scroll_page)

style = ttk.Style(root)
style.theme_use("clam")
style.configure("Treeview", background=COLORS["panel"], foreground=COLORS["text"],
                fieldbackground=COLORS["panel"], rowheight=25, borderwidth=0)
style.configure("Treeview.Heading", background=COLORS["panel_light"],
                foreground=COLORS["muted"], font=("Segoe UI", 9, "bold"), borderwidth=0)
style.map("Treeview", background=[("selected", "#25456a")])
style.configure(
    "Dark.TCombobox", fieldbackground="#0c1626", background=COLORS["panel_light"],
    foreground=COLORS["text"], arrowcolor=COLORS["text"], bordercolor=COLORS["panel_light"],
)
style.map(
    "Dark.TCombobox",
    fieldbackground=[("readonly", "#0c1626")],
    foreground=[("readonly", COLORS["text"])],
    background=[("readonly", COLORS["panel_light"])],
)
style.configure(
    "Horizontal.TProgressbar", troughcolor=COLORS["panel_light"],
    background=COLORS["accent"], bordercolor=COLORS["panel"],
    lightcolor=COLORS["accent"], darkcolor=COLORS["accent"],
)
style.configure(
    "Vertical.TScrollbar", troughcolor=COLORS["background"],
    background=COLORS["panel_light"], arrowcolor=COLORS["muted"],
    bordercolor=COLORS["background"],
)

header = tk.Frame(content, bg=COLORS["background"])
header.pack(fill="x", padx=30, pady=(16, 10))
tk.Label(header, text="SSL / TLS  CERTIFICATE MONITOR", bg=COLORS["background"],
         fg=COLORS["text"], font=("Segoe UI", 21, "bold")).pack(anchor="w")
tk.Label(header, text="A clear view of certificate health and expiry", bg=COLORS["background"],
         fg=COLORS["muted"], font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))

search_card = tk.Frame(content, bg=COLORS["panel"], padx=18, pady=12)
search_card.pack(fill="x", padx=30, pady=(0, 14))
tk.Label(search_card, text="DOMAINS", bg=COLORS["panel"], fg=COLORS["muted"],
         font=("Segoe UI", 9, "bold")).pack(anchor="w")
input_row = tk.Frame(search_card, bg=COLORS["panel"])
input_row.pack(fill="x", pady=(8, 0))
domain_text = tk.Text(
    input_row, height=2, font=("Segoe UI", 11), bg="#0c1626", fg=COLORS["text"],
    insertbackground=COLORS["text"], relief="flat", bd=0, wrap="none",
)
domain_text.pack(side="left", fill="x", expand=True, padx=(0, 12), pady=2)
domain_text.insert("1.0", "google.com")
domain_text.bind("<Control-Return>", lambda _event: (start_scan(), "break")[1])
scan_button = tk.Button(input_row, text="Scan domain list", command=start_scan,
                        bg=COLORS["accent"], fg="#06221d", activebackground="#63d9bd",
                        activeforeground="#06221d", relief="flat", bd=0,
                        font=("Segoe UI", 10, "bold"), padx=18, pady=10, cursor="hand2")
scan_button.pack(side="right")
load_button = tk.Button(
    input_row, text="Load list", command=load_domain_list,
    bg=COLORS["panel_light"], fg=COLORS["text"], activebackground="#25456a",
    activeforeground=COLORS["text"], relief="flat", bd=0,
    font=("Segoe UI", 9, "bold"), padx=12, pady=10, cursor="hand2",
)
load_button.pack(side="right", padx=(0, 8))
input_help = tk.Frame(search_card, bg=COLORS["panel"])
input_help.pack(fill="x", pady=(8, 0))
tk.Label(input_help, text="Separate multiple domains with commas or new lines.",
         bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(side="left")
warning_threshold = tk.StringVar(value=str(WARNING_DAYS))
tk.Label(input_help, text="days", bg=COLORS["panel"], fg=COLORS["muted"],
         font=("Segoe UI", 9)).pack(side="right", padx=(0, 6))
warning_selector = ttk.Combobox(
    input_help, textvariable=warning_threshold, state="readonly", width=5,
    values=tuple(str(days) for days in WARNING_OPTIONS), style="Dark.TCombobox",
)
warning_selector.pack(side="right")
warning_selector.bind("<<ComboboxSelected>>", save_warning_days)
tk.Label(input_help, text="Warn before expiry:", bg=COLORS["panel"], fg=COLORS["muted"],
         font=("Segoe UI", 9)).pack(side="right", padx=(8, 6))
progress_bar = ttk.Progressbar(search_card, mode="determinate", maximum=100,
                               style="Horizontal.TProgressbar")
progress_bar.pack(fill="x", pady=(12, 0))

summary = tk.Frame(content, bg=COLORS["panel"], padx=20, pady=13)
summary.pack(fill="x", padx=30, pady=(0, 14))
tk.Label(summary, text="CERTIFICATE STATUS", bg=COLORS["panel"], fg=COLORS["muted"],
         font=("Segoe UI", 9, "bold")).pack(anchor="w")
status_value = tk.Label(summary, text="READY TO SCAN", bg=COLORS["panel"], fg=COLORS["blue"],
                        font=("Segoe UI", 18, "bold"))
status_value.pack(anchor="w", pady=(4, 8))
metrics = tk.Frame(summary, bg=COLORS["panel"])
metrics.pack(fill="x")

def metric(parent, title):
    box = tk.Frame(parent, bg=COLORS["panel_light"], padx=12, pady=10)
    box.pack(side="left", fill="both", expand=True, padx=(0, 8))
    tk.Label(box, text=title.upper(), bg=COLORS["panel_light"], fg=COLORS["muted"],
             font=("Segoe UI", 8, "bold")).pack(anchor="w")
    value = tk.Label(box, text="—", bg=COLORS["panel_light"], fg=COLORS["text"],
                     font=("Segoe UI", 10, "bold"), anchor="w", justify="left", wraplength=260)
    value.pack(anchor="w", pady=(5, 0))
    return value

domain_value = metric(metrics, "Domain")
issuer_value = metric(metrics, "Issuer")
expiry_value = metric(metrics, "Expiry date (UTC)")
days_value = metric(metrics, "Time remaining")
tls_value = metric(metrics, "TLS version")
detail_value = tk.Label(summary, text="Enter a domain to begin. Certificates are checked with verification enabled.",
                        bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 9),
                        justify="left", anchor="w", wraplength=940)
detail_value.pack(fill="x", anchor="w", pady=(8, 0))

overview = tk.Frame(content, bg=COLORS["background"])
overview.pack(fill="x", padx=30, pady=(0, 14))


def overview_card(title, color):
    card = tk.Frame(overview, bg=COLORS["panel"], padx=14, pady=8)
    card.pack(side="left", fill="both", expand=True, padx=(0, 8))
    tk.Label(card, text=title, bg=COLORS["panel"], fg=COLORS["muted"],
             font=("Segoe UI", 8, "bold")).pack(anchor="w")
    value = tk.Label(card, text="0", bg=COLORS["panel"], fg=color,
                     font=("Segoe UI", 18, "bold"))
    value.pack(anchor="w", pady=(2, 0))
    return value


overview_total = overview_card("TOTAL SCANS", COLORS["text"])
overview_valid = overview_card("VALID", COLORS["green"])
overview_expiring = overview_card("EXPIRING ≤30 DAYS", COLORS["yellow"])
overview_issues = overview_card("ISSUES", COLORS["red"])

history_panel = tk.Frame(content, bg=COLORS["panel"], padx=18, pady=10)
history_panel.pack(fill="both", expand=True, padx=30, pady=(0, 24))
history_head = tk.Frame(history_panel, bg=COLORS["panel"])
history_head.pack(fill="x", pady=(0, 8))
tk.Label(history_head, text="SCAN HISTORY", bg=COLORS["panel"], fg=COLORS["text"],
         font=("Segoe UI", 11, "bold")).pack(side="left")
history_count = tk.Label(history_head, text="0 scans", bg=COLORS["panel"], fg=COLORS["muted"],
                        font=("Segoe UI", 9))
history_count.pack(side="left", padx=10)
history_search = tk.Entry(
    history_head, width=20, font=("Segoe UI", 9), bg="#0c1626", fg=COLORS["text"],
    insertbackground=COLORS["text"], relief="flat", bd=0,
)
history_search.pack(side="right", padx=(8, 0), ipady=7)
history_search.insert(0, "")
history_search.bind("<KeyRelease>", refresh_history)
status_filter = ttk.Combobox(
    history_head, width=16, state="readonly",
    values=("All statuses", "Valid", "Expiring soon", "Issues"), style="Dark.TCombobox",
)
status_filter.set("All statuses")
status_filter.pack(side="right", padx=(8, 0), ipady=3)
status_filter.bind("<<ComboboxSelected>>", refresh_history)
export_button = tk.Button(history_head, text="Export CSV", command=export_csv,
                          bg=COLORS["panel_light"], fg=COLORS["text"], activebackground="#25456a",
                          activeforeground=COLORS["text"], relief="flat", bd=0,
                          font=("Segoe UI", 9, "bold"), padx=14, pady=7, cursor="hand2")
export_button.pack(side="right")
rescan_button = tk.Button(
    history_head, text="Rescan selected", command=rescan_selected_history,
    bg=COLORS["panel_light"], fg=COLORS["text"], activebackground="#25456a",
    activeforeground=COLORS["text"], relief="flat", bd=0,
    font=("Segoe UI", 9, "bold"), padx=12, pady=7, cursor="hand2",
)
rescan_button.pack(side="right", padx=(0, 8))
columns = ("scanned", "domain", "status", "days", "tls")
table_frame = tk.Frame(history_panel, bg=COLORS["panel"])
table_frame.pack(fill="both", expand=True)
history_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=7)
for column, label, width in (("scanned", "SCANNED (UTC)", 180), ("domain", "DOMAIN", 220),
                             ("status", "STATUS", 180), ("days", "DAYS LEFT", 110),
                             ("tls", "TLS", 100)):
    history_tree.heading(column, text=label, command=lambda key=column: sort_history(key))
    history_tree.column(column, width=width, anchor="w")
history_scrollbar = ttk.Scrollbar(
    table_frame, orient="vertical", command=history_tree.yview, style="Vertical.TScrollbar",
)
history_tree.configure(yscrollcommand=history_scrollbar.set)
history_scrollbar.pack(side="right", fill="y")
history_tree.pack(side="left", fill="both", expand=True)
history_tree.bind("<<TreeviewSelect>>", show_selected_history)
history_tree.tag_configure("VALID", foreground=COLORS["green"])
history_tree.tag_configure("EXPIRING SOON", foreground=COLORS["yellow"])
history_tree.tag_configure("EXPIRED", foreground=COLORS["red"])
history_tree.tag_configure("EXPIRED / UNVERIFIED", foreground=COLORS["red"])
history_tree.tag_configure("HOSTNAME MISMATCH", foreground=COLORS["red"])
history_tree.tag_configure("VERIFICATION FAILED", foreground=COLORS["red"])

# Restore saved rows into the dashboard, newest first.
refresh_history()
update_overview()
if history:
    latest = history[-1]
    status_value.config(
        text=f"SAVED HISTORY · LAST SCAN {latest.get('status', '')}",
        fg=status_color(latest.get("status", "")),
    )
    domain_value.config(text=latest.get("domain", "Unavailable"))
    issuer_value.config(text=latest.get("issuer", "") or "Unavailable")
    expiry_value.config(text=latest.get("expiry_date", "") or "Unavailable")
    days = latest.get("days_left", "")
    days_value.config(text=f"{days} days" if isinstance(days, int) else "Unknown")
    tls_value.config(text=latest.get("tls_version", "") or "Unavailable")
    detail_value.config(text="Saved scan history restored from the last time you used the checker.")

root.mainloop()
