import tkinter as tk
from tkinter import messagebox, filedialog
import re
from collections import defaultdict
import subprocess

# ================= LOG ANALYZER =================
class LogAnalyzer:
    def __init__(self, threshold=1):
        self.threshold = threshold
        self.failed_attempts = defaultdict(int)
        self.failed_timestamps = defaultdict(list)
        self.alerts = []
        self.success_logins = []

    def analyze_logs_text(self, lines):
        self.failed_attempts.clear()
        self.failed_timestamps.clear()
        self.alerts.clear()
        self.success_logins.clear()
        for line in lines:
            self._process_line(line)
        self._generate_alerts()
        return self.alerts, self.success_logins

    def _extract_timestamp(self, line):
        tokens = line.split()
        if len(tokens) >= 3:
            return f"{tokens[0]} {tokens[1]} {tokens[2]}"
        return "Unknown Time"

    def _process_line(self, line):
        timestamp = self._extract_timestamp(line)
        
        if "Failed password" in line or "authentication failure" in line:
            ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
            if ip_match:
                ip = ip_match.group()
                self.failed_attempts[ip] += 1
                self.failed_timestamps[ip].append(timestamp)

        if "Accepted password" in line or "Accepted publickey" in line:
            match = re.search(
                r"Accepted .* for (\w+) from (\d{1,3}(?:\.\d{1,3}){3})",
                line
            )
            if match:
                user, ip = match.groups()
                self.success_logins.append(
                    f"[INFO] Successful SSH Login\n"
                    f"Time: {timestamp}\n"
                    f"User: {user}\n"
                    f"IP Address: {ip}\n"
                    f"{'-'*55}"
                )

    def _generate_alerts(self):
        for ip, count in self.failed_attempts.items():
            if count >= self.threshold:
                if count >= 5:
                    level = "HIGH"
                elif count >= 3:
                    level = "MEDIUM"
                else:
                    level = "LOW"
                
                timestamps = self.failed_timestamps[ip]
                if len(timestamps) > 1:
                    time_str = f"({', '.join(timestamps)})"
                else:
                    time_str = timestamps[0]

                self.alerts.append(
                    f"[{level}] Brute Force Attempt Detected\n"
                    f"IP Address: {ip}\n"
                    f"Failed Attempts: {count}\n"
                    f"Time: {time_str}\n"
                    f"{'-'*55}"
                )

# ================= GUI =================
class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Sentinel – Brute Force & Login Monitor")
        self.root.geometry("950x700")
        self.root.configure(bg="#eceff1")

        self.analyzer = LogAnalyzer()
        self.alerts = []
        self.success_logins = []
        self.live_monitor = tk.BooleanVar(value=False)

        self._create_widgets()

    def _create_widgets(self):
        header = tk.Frame(self.root, bg="#263238", pady=18)
        header.pack(fill="x")
        
        tk.Label(
            header,
            text="SSH Sentinel",
            font=("Helvetica", 22, "bold"),
            fg="white",
            bg="#263238"
        ).pack()
        
        tk.Label(
            header,
            text="Brute Force & SSH Login Monitor",
            font=("Helvetica", 11),
            fg="#cfd8dc",
            bg="#263238"
        ).pack()

        control_frame = tk.Frame(self.root, bg="#eceff1", pady=15)
        control_frame.pack()

        tk.Button(control_frame, text="Analyze Live SSH Logs",
                  bg="#388e3c", fg="white", width=26,
                  command=self.analyze_ssh_logs).grid(row=0, column=0, padx=12)
        
        tk.Button(control_frame, text="Load Log File",
                  bg="#1976d2", fg="white", width=26,
                  command=self.load_log_file).grid(row=0, column=1, padx=12)
        
        tk.Checkbutton(control_frame, text="Live Monitor",
                       variable=self.live_monitor,
                       bg="#eceff1",
                       command=self._toggle_live_monitor).grid(row=0, column=2, padx=12)

        filter_frame = tk.Frame(self.root, bg="#eceff1", pady=5)
        filter_frame.pack()

        tk.Button(filter_frame, text="ALL", width=12, command=lambda: self._apply_filter("all")).grid(row=0, column=0, padx=5)
        tk.Button(filter_frame, text="HIGH", width=12, command=lambda: self._apply_filter("high")).grid(row=0, column=1, padx=5)
        tk.Button(filter_frame, text="MEDIUM", width=12, command=lambda: self._apply_filter("medium")).grid(row=0, column=2, padx=5)
        tk.Button(filter_frame, text="LOW", width=12, command=lambda: self._apply_filter("low")).grid(row=0, column=3, padx=5)
        tk.Button(filter_frame, text="Successful Logins", width=18, command=lambda: self._apply_filter("info")).grid(row=0, column=4, padx=5)

        output_container = tk.LabelFrame(self.root, text=" Detection Output ",
                                        bg="#eceff1", padx=10, pady=10)
        output_container.pack(fill="both", expand=True, padx=15, pady=10)

        self.output = tk.Text(output_container, font=("Consolas", 11), bg="#fafafa")
        self.output.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(output_container, command=self.output.yview)
        scrollbar.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=scrollbar.set)

        # Tag colors
        self.output.tag_config("high", foreground="#c62828")    # red
        self.output.tag_config("medium", foreground="#ef6c00")  # orange
        self.output.tag_config("low", foreground="#fbc02d")     # yellow
        self.output.tag_config("info", foreground="#1565c0")    # blue

        self.status = tk.Label(self.root, text="Status: Idle",
                              bg="#37474f", fg="white", anchor="w", padx=10)
        self.status.pack(fill="x")

    def analyze_ssh_logs(self):
        try:
            result = subprocess.run(
                ["journalctl", "-u", "ssh", "--no-pager", "-n", "1000"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.splitlines()
            self.alerts, self.success_logins = self.analyzer.analyze_logs_text(lines)
            self._display_results("all")
            
            if self.live_monitor.get():
                self.root.after(10000, self.analyze_ssh_logs)  # refresh every 10 seconds
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read journalctl:\n{str(e)}")

    def load_log_file(self):
        path = filedialog.askopenfilename(
            title="Select SSH log file",
            filetypes=(("Text files", "*.log *.txt"), ("All files", "*.*"))
        )
        if path:
            try:
                with open(path, encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                self.alerts, self.success_logins = self.analyzer.analyze_logs_text(lines)
                self._display_results("all")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")

    def _display_results(self, filter_tag):
        self.output.delete(1.0, tk.END)

        shown = False
        for alert in self.alerts:
            if "[HIGH]" in alert and filter_tag in ("all", "high"):
                self.output.insert(tk.END, alert + "\n", "high")
                shown = True
            elif "[MEDIUM]" in alert and filter_tag in ("all", "medium"):
                self.output.insert(tk.END, alert + "\n", "medium")
                shown = True
            elif "[LOW]" in alert and filter_tag in ("all", "low"):
                self.output.insert(tk.END, alert + "\n", "low")
                shown = True

        if filter_tag in ("all", "info"):
            for entry in self.success_logins:
                self.output.insert(tk.END, entry + "\n", "info")
                shown = True

        if not shown and filter_tag != "all":
            self.output.insert(tk.END, "No entries match the selected filter.\n")

    def _apply_filter(self, tag):
        self._display_results(tag)
        self.status.config(text=f"Status: Filter → {tag.upper()}")

    def _toggle_live_monitor(self):
        if self.live_monitor.get():
            self.status.config(text="Status: Live monitoring active (every 10s)")
            self.analyze_ssh_logs()
        else:
            self.status.config(text="Status: Live monitoring stopped")

# ================= MAIN =================
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
