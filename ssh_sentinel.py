"""SSH Sentinel - Tkinter front end for the analyzer module."""
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from analyzer import LogAnalyzer, read_file, read_journal

REFRESH_MS = 10000
POLL_MS = 100

TAG_COLORS = {
    "critical": "#6a1b9a",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#9e7d00",
    "info": "#1565c0",
}


class SentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Sentinel - Brute Force & Login Monitor")
        self.root.geometry("950x700")
        self.root.configure(bg="#eceff1")

        self.analyzer = LogAnalyzer()
        self.alerts = []
        self.logins = []
        self.live_monitor = tk.BooleanVar(value=False)
        self.results = queue.Queue()
        self._busy = False
        self._live_id = None
        self._current_filter = "all"

        self._create_widgets()

    # ------------------------------------------------------------------ UI
    def _create_widgets(self):
        header = tk.Frame(self.root, bg="#263238", pady=18)
        header.pack(fill="x")
        tk.Label(header, text="SSH Sentinel", font=("Helvetica", 22, "bold"),
                 fg="white", bg="#263238").pack()
        tk.Label(header, text="Windowed brute-force detection and login monitor",
                 font=("Helvetica", 11), fg="#cfd8dc", bg="#263238").pack()

        controls = tk.Frame(self.root, bg="#eceff1", pady=15)
        controls.pack()
        tk.Button(controls, text="Analyze Live SSH Logs", bg="#388e3c", fg="white",
                  width=26, command=self.analyze_ssh_logs).grid(row=0, column=0, padx=12)
        tk.Button(controls, text="Load Log File", bg="#1976d2", fg="white",
                  width=26, command=self.load_log_file).grid(row=0, column=1, padx=12)
        tk.Checkbutton(controls, text="Live Monitor", variable=self.live_monitor,
                       bg="#eceff1", command=self._toggle_live_monitor
                       ).grid(row=0, column=2, padx=12)

        filters = tk.Frame(self.root, bg="#eceff1", pady=5)
        filters.pack()
        buttons = [("ALL", "all"), ("CRITICAL", "critical"), ("HIGH", "high"),
                   ("MEDIUM", "medium"), ("LOW", "low"), ("Successful Logins", "info")]
        for col, (label, tag) in enumerate(buttons):
            tk.Button(filters, text=label, width=16 if tag == "info" else 11,
                      command=lambda t=tag: self._apply_filter(t)
                      ).grid(row=0, column=col, padx=4)

        container = tk.LabelFrame(self.root, text=" Detection Output ",
                                  bg="#eceff1", padx=10, pady=10)
        container.pack(fill="both", expand=True, padx=15, pady=10)

        self.output = tk.Text(container, font=("Consolas", 11), bg="#fafafa")
        self.output.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(container, command=self.output.yview)
        scrollbar.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=scrollbar.set)

        for tag, color in TAG_COLORS.items():
            font = ("Consolas", 11, "bold") if tag == "critical" else None
            self.output.tag_config(tag, foreground=color, **({"font": font} if font else {}))

        self.status = tk.Label(self.root, text="Status: Idle", bg="#37474f",
                               fg="white", anchor="w", padx=10)
        self.status.pack(fill="x")

    # ------------------------------------------------------------- actions
    def analyze_ssh_logs(self):
        self._start_analysis(read_journal, "Reading SSH journal")

    def load_log_file(self):
        path = filedialog.askopenfilename(
            title="Select SSH log file",
            filetypes=(("Log files", "*.log *.txt"), ("All files", "*.*")),
        )
        if path:
            self._start_analysis(lambda: read_file(path), "Reading log file")

    def _start_analysis(self, loader, label):
        if self._busy:
            return
        self._busy = True
        self.status.config(text=f"Status: {label}...")

        def work():
            try:
                lines = loader()
                alerts, logins = self.analyzer.analyze_logs_text(lines)
                self.results.put(("ok", alerts, logins, self.analyzer.skipped_lines, len(lines)))
            except Exception as exc:  # report any failure in the UI
                self.results.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()
        self.root.after(POLL_MS, self._poll_results)

    def _poll_results(self):
        try:
            message = self.results.get_nowait()
        except queue.Empty:
            self.root.after(POLL_MS, self._poll_results)
            return

        self._busy = False
        if message[0] == "error":
            self.status.config(text="Status: Error")
            messagebox.showerror("Error", f"Analysis failed:\n{message[1]}")
        else:
            _, self.alerts, self.logins, skipped, total = message
            self._display_results(self._current_filter)
            self.status.config(
                text=(f"Status: {len(self.alerts)} alert(s), {len(self.logins)} login(s), "
                      f"{total} lines read, {skipped} skipped")
            )
        self._schedule_live()

    # ------------------------------------------------------------- display
    def _display_results(self, filter_tag):
        self.output.delete("1.0", tk.END)
        shown = False

        for alert in self.alerts:
            tag = alert.level.lower()
            if filter_tag in ("all", tag):
                self.output.insert(tk.END, alert.render() + "\n", tag)
                shown = True

        if filter_tag in ("all", "info"):
            for login in self.logins:
                self.output.insert(tk.END, login.render() + "\n", "info")
                shown = True

        if not shown:
            message = ("No suspicious activity found.\n" if filter_tag == "all"
                       else "No entries match the selected filter.\n")
            self.output.insert(tk.END, message)

    def _apply_filter(self, tag):
        self._current_filter = tag
        self._display_results(tag)
        self.status.config(text=f"Status: Filter -> {tag.upper()}")

    # ---------------------------------------------------------- live monitor
    def _schedule_live(self):
        self._cancel_live()
        if self.live_monitor.get():
            self._live_id = self.root.after(REFRESH_MS, self.analyze_ssh_logs)

    def _cancel_live(self):
        if self._live_id is not None:
            self.root.after_cancel(self._live_id)
            self._live_id = None

    def _toggle_live_monitor(self):
        if self.live_monitor.get():
            self.status.config(text="Status: Live monitoring active (every 10s)")
            self.analyze_ssh_logs()
        else:
            self._cancel_live()
            self.status.config(text="Status: Live monitoring stopped")


if __name__ == "__main__":
    root = tk.Tk()
    SentinelGUI(root)
    root.mainloop()
