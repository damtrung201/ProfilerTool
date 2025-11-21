import re
import json
import sys
from datetime import datetime

# --- DATA STRUCTURES ---

class TraceNode:
    """Đại diện cho một sự kiện (Event) trong cây Call Stack"""
    def __init__(self, name, start_time, thread_id):
        self.name = name
        self.start_time = start_time  # datetime object
        self.end_time = None
        self.thread_id = thread_id
        self.children = []
        self.parent = None

    def close(self, end_time):
        self.end_time = end_time

    @property
    def duration_ms(self):
        if not self.end_time: return 0
        delta = self.end_time - self.start_time
        return delta.total_seconds() * 1000

    @property
    def self_time_ms(self):
        """Thời gian thực tế chạy logic của hàm này (trừ đi thời gian chờ con)"""
        child_duration = sum(c.duration_ms for c in self.children)
        return max(0, self.duration_ms - child_duration)

    def to_chrome_trace_events(self, pid=1):
        """Chuyển đổi sang format JSON của Perfetto/Chrome Tracing"""
        events = []
        # Event Start
        events.append({
            "name": self.name,
            "cat": "PERF",
            "ph": "B", # Begin
            "ts": self.start_time.timestamp() * 1_000_000, # Microseconds
            "pid": pid,
            "tid": self.thread_id
        })
        
        # Các event con
        for child in self.children:
            events.extend(child.to_chrome_trace_events(pid))

        # Event End
        end_ts = self.end_time.timestamp() * 1_000_000 if self.end_time else (self.start_time.timestamp() * 1_000_000 + 100)
        events.append({
            "name": self.name,
            "cat": "PERF",
            "ph": "E", # End
            "ts": end_ts,
            "pid": pid,
            "tid": self.thread_id
        })
        return events


class LogProfiler:
    def __init__(self, config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
        
        self.log_pattern = re.compile(self.config['log_header_pattern'])
        self.event_defs = []
        
        # Compile regex trước để tối ưu hiệu năng
        for evt in self.config['events']:
            self.event_defs.append({
                'name': evt['name'],
                'start_re': re.compile(evt['start_regex']),
                'end_re': re.compile(evt['end_regex']),
                'threshold': evt.get('threshold_ms', 0)
            })

        # Stack quản lý lồng nhau: Key = ThreadID, Value = List[TraceNode]
        self.thread_stacks = {}
        self.completed_roots = [] # Các cây đã hoàn thành

    def parse_timestamp(self, time_str):
        # Logcat thường không có năm, thêm năm hiện tại vào
        full_str = f"{datetime.now().year}-{time_str}"
        return datetime.strptime(full_str, f"%Y-{self.config['time_format']}")

    def process_file(self, log_file_path):
        print(f"🚀 Analyzing: {log_file_path}...")
        
        with open(log_file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                match = self.log_pattern.match(line)
                
                if not match: continue 
                
                # CẬP NHẬT Ở ĐÂY: Thêm biến uid vào để hứng dữ liệu
                # Regex cũ: time, pid, tid, level, tag, msg
                # Regex mới: time, uid, pid, tid, level, tag, msg
                time_str, uid, pid, tid, level, tag, message = match.groups()
                
                current_time = self.parse_timestamp(time_str)
                
                # Ép kiểu dữ liệu
                pid = int(pid) 
                tid = int(tid)
                
                # (Tùy chọn) Nếu bạn muốn dùng UID để phân tích thì lưu lại, 
                # còn không thì chỉ cần biến này để hứng cho code không lỗi.

                # Truyền tiếp vào hàm xử lý
                self._check_events(pid, tid, current_time, message)

    def _check_events(self, tid, timestamp, message):
        for definition in self.event_defs:
            # 1. Check START
            if definition['start_re'].search(message):
                new_node = TraceNode(definition['name'], timestamp, tid)
                
                # Logic Stack (Lồng nhau)
                if tid not in self.thread_stacks:
                    self.thread_stacks[tid] = []
                
                stack = self.thread_stacks[tid]
                if stack:
                    parent = stack[-1]
                    parent.children.append(new_node)
                    new_node.parent = parent
                
                stack.append(new_node)
                return # Đã khớp start, next line

            # 2. Check END
            if definition['end_re'].search(message):
                if tid in self.thread_stacks and self.thread_stacks[tid]:
                    stack = self.thread_stacks[tid]
                    # Lấy node trên đỉnh stack
                    node = stack[-1]
                    
                    # Nếu tên khớp (hoặc giả định logic đúng), đóng node
                    if node.name == definition['name']:
                        node.close(timestamp)
                        stack.pop()
                        
                        # Nếu stack rỗng, đây là Root Node đã xong
                        if not stack:
                            self.completed_roots.append(node)
                return

    def _close_dangling_events(self):
        """Đóng cưỡng bức các event còn treo trong stack khi hết file"""
        for tid, stack in self.thread_stacks.items():
            while stack:
                node = stack.pop()
                if not node.end_time:
                    # Fake end time bằng start time để không lỗi visualization
                    node.close(node.start_time) 
                if not stack: # Nếu là root
                    self.completed_roots.append(node)

    # --- OUTPUT METHODS ---

    def print_text_report(self):
        print("\n📊 --- PERFORMANCE REPORT (Call Tree) ---")
        for root in self.completed_roots:
            self._print_node_recursive(root, 0)
        print("-----------------------------------------")

    def _print_node_recursive(self, node, level):
        indent = "  " * level
        branch = "└─" if level > 0 else "ROOT:"
        
        # Check threshold
        threshold = next((d['threshold'] for d in self.event_defs if d['name'] == node.name), 0)
        status_icon = "🐢" if node.duration_ms > threshold else "✅"
        
        print(f"{indent}{branch} {status_icon} [{node.name}]")
        print(f"{indent}   Total: {node.duration_ms:.0f}ms | Self: {node.self_time_ms:.0f}ms | Thread: {node.thread_id}")
        
        for child in node.children:
            self._print_node_recursive(child, level + 1)

    def export_chrome_trace(self, output_file="trace_result.json"):
        trace_events = []
        for root in self.completed_roots:
            trace_events.extend(root.to_chrome_trace_events())
        
        with open(output_file, 'w') as f:
            json.dump(trace_events, f)
        print(f"\n💾 Chrome Trace exported to: {output_file}")
        print("👉 Open 'chrome://tracing' or 'ui.perfetto.dev' and load this file.")

# --- MAIN ENTRY POINT ---
if __name__ == "__main__":
    # Sử dụng mặc định dummy_log.txt nếu không truyền tham số
    log_file = sys.argv[1] if len(sys.argv) > 1 else "dummy_log.txt"
    config_file = "config.json"
    
    profiler = LogProfiler(config_file)
    profiler.process_file(log_file)
    
    profiler.print_text_report()
    profiler.export_chrome_trace()
