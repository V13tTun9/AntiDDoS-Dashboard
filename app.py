#!/usr/bin/env python3
"""
CrowdSec Web Dashboard & Management API
Phát triển cho việc quản lý CrowdSec:
1. Tab 1 - Decisions: Hiển thị, Thêm, Xóa IP bị chặn (cscli decisions list/add/delete)
2. Tab 2 - Scenarios: Hiển thị, Thêm, Chỉnh sửa, Bật/Tắt, Xóa kịch bản (cscli scenarios list/install/remove & /etc/crowdsec/scenarios/)
"""

import sys
import os
import json
import re
import socket
import ipaddress
import subprocess
import argparse
import time
import platform
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

# Thư mục gốc chứa file app.py và thư mục static
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Thư mục kịch bản CrowdSec
SCENARIOS_DIR = "/etc/crowdsec/scenarios"
HUB_SCENARIOS_DIR = "/etc/crowdsec/hub/scenarios"

# Biến cờ chế độ Demo
DEMO_MODE = False

# Dữ liệu mẫu Decisions
DEMO_DECISIONS = [
    {
        "id": "467416",
        "source": "crowdsec",
        "scope": "Ip",
        "value": "172.10.10.14",
        "scope_value": "Ip:172.10.10.14",
        "reason": "viettung/suricata-l3-l4-flood",
        "action": "ban",
        "country": "US",
        "as": "7018 ATT-INTERNET4",
        "events": "3",
        "expiration": "3h41m37s",
        "alert_id": "384"
    },
    {
        "id": "467415",
        "source": "crowdsec",
        "scope": "Ip",
        "value": "172.10.10.12",
        "scope_value": "Ip:172.10.10.12",
        "reason": "viettung/suricata-l3-l4-flood",
        "action": "ban",
        "country": "US",
        "as": "7018 ATT-INTERNET4",
        "events": "3",
        "expiration": "3h41m36s",
        "alert_id": "383"
    },
    {
        "id": "467414",
        "source": "crowdsec",
        "scope": "Ip",
        "value": "172.10.10.15",
        "scope_value": "Ip:172.10.10.15",
        "reason": "viettung/suricata-l3-l4-flood",
        "action": "ban",
        "country": "US",
        "as": "7018 ATT-INTERNET4",
        "events": "3",
        "expiration": "3h41m32s",
        "alert_id": "382"
    },
    {
        "id": "467413",
        "source": "crowdsec",
        "scope": "Ip",
        "value": "172.10.10.11",
        "scope_value": "Ip:172.10.10.11",
        "reason": "viettung/suricata-l3-l4-flood",
        "action": "ban",
        "country": "US",
        "as": "7018 ATT-INTERNET4",
        "events": "3",
        "expiration": "3h41m25s",
        "alert_id": "381"
    },
    {
        "id": "467412",
        "source": "crowdsec",
        "scope": "Ip",
        "value": "172.10.10.13",
        "scope_value": "Ip:172.10.10.13",
        "reason": "viettung/suricata-l3-l4-flood",
        "action": "ban",
        "country": "US",
        "as": "7018 ATT-INTERNET4",
        "events": "3",
        "expiration": "3h41m23s",
        "alert_id": "380"
    }
]

# Dữ liệu mẫu Scenarios
DEMO_SCENARIOS = [
    {
        "name": "viettung/suricata-l3-l4-flood",
        "filename": "vt-suricata-l3-l4-flood.yaml",
        "path": "/etc/crowdsec/scenarios/vt-suricata-l3-l4-flood.yaml",
        "status": "enabled",
        "type": "Local",
        "is_custom": True,
        "description": "Detected Volumetric Flood (SYN, ICMP, UDP) from Suricata",
        "version": "local",
        "content": """type: leaky
name: viettung/suricata-l3-l4-flood
description: "Detected Volumetric Flood (SYN, ICMP, UDP) from Suricata"

filter: "evt.Meta.log_type == 'suricata_alert' && evt.Meta.suricata_alert_signature_id in ['1000001', '1000002', '1000003']"
groupby: evt.Meta.source_ip

capacity: 2
leakspeed: 30s
blackhole: 1m

labels:
  service: suricata
  remediation: true
  confidence: 3
  spoofable: 3
  behavior: "network:flood"
  label: "L3/L4 Volumetric DDoS Detected (Do An Tot Nghiep)"
"""
    },
    {
        "name": "viettung/nginx-http-flood",
        "filename": "vt-nginx-http-flood.yaml",
        "path": "/etc/crowdsec/scenarios/vt-nginx-http-flood.yaml",
        "status": "enabled",
        "type": "Local",
        "is_custom": True,
        "description": "Detected HTTP Flood from Nginx error code 429",
        "version": "local",
        "content": """type: leaky
name: viettung/nginx-http-flood
description: "Detected HTTP Flood from Nginx error code 429"
filter: "evt.Meta.log_type == 'nginx_access-log' && evt.Parsed.status == '429'"
groupby: evt.Meta.source_ip
capacity: 10
leakspeed: 10s
blackhole: 5m
labels:
  service: nginx
  remediation: true
  behavior: "http:flood"
"""
    },
    {
        "name": "viettung/nginx-slowloris-attack",
        "filename": "vt-nginx-slowloris.yaml",
        "path": "/etc/crowdsec/scenarios/vt-nginx-slowloris.yaml",
        "status": "enabled",
        "type": "Local",
        "is_custom": True,
        "description": "Detected Slowloris Attack from Nginx access log",
        "version": "local",
        "content": """type: leaky
name: viettung/nginx-slowloris-attack
description: "Detected Slowloris Attack from Nginx access log"
filter: "evt.Meta.log_type == 'nginx_access-log' && evt.Parsed.request_time > 10"
groupby: evt.Meta.source_ip
capacity: 5
leakspeed: 1m
labels:
  service: nginx
  remediation: true
  behavior: "http:slowloris"
"""
    },
    {
        "name": "crowdsecurity/ssh-bf",
        "filename": "ssh-bf.yaml",
        "path": "/etc/crowdsec/scenarios/ssh-bf.yaml",
        "status": "enabled",
        "type": "Hub",
        "is_custom": False,
        "description": "Detect SSH brute force attacks",
        "version": "1.3.0",
        "content": """type: leaky
name: crowdsecurity/ssh-bf
description: "Detect SSH brute force attacks"
filter: "evt.Meta.log_type == 'ssh_failed-auth'"
groupby: evt.Meta.source_ip
capacity: 5
leakspeed: 1m
labels:
  service: ssh
  remediation: true
  behavior: "ssh:bruteforce"
"""
    },
    {
        "name": "crowdsecurity/http-probing",
        "filename": "http-probing.yaml",
        "path": "/etc/crowdsec/scenarios/http-probing.yaml",
        "status": "enabled",
        "type": "Hub",
        "is_custom": False,
        "description": "Detect HTTP probing and vulnerability scanning",
        "version": "2.1.0",
        "content": """type: leaky
name: crowdsecurity/http-probing
description: "Detect HTTP probing and vulnerability scanning"
filter: "evt.Meta.log_type == 'http_access-log'"
groupby: evt.Meta.source_ip
capacity: 10
leakspeed: 10s
labels:
  service: http
  remediation: true
"""
    },
    {
        "name": "crowdsecurity/http-crawl-non_statics",
        "filename": "http-crawl-non_statics.yaml",
        "path": "/etc/crowdsec/scenarios/http-crawl-non_statics.yaml",
        "status": "disabled",
        "type": "Hub",
        "is_custom": False,
        "description": "Detect aggressive web crawling on dynamic pages",
        "version": "0.4.0",
        "content": ""
    }
]

def is_root():
    return os.geteuid() == 0

def run_command(cmd_args, timeout=20):
    """
    Thực thi lệnh an toàn bằng subprocess với danh sách đối số (tránh shell injection).
    Tự động thử gọi trực tiếp hoặc thông qua sudo nếu cần.
    """
    try:
        proc = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if proc.returncode == 0:
            return True, proc.stdout, proc.stderr
        
        # Nếu bị lỗi phân quyền và đang không phải root, thử lại với sudo -n (non-interactive)
        err_msg = (proc.stderr or "").lower()
        if ("permission denied" in err_msg or "operation not permitted" in err_msg) and not is_root():
            sudo_cmd = ["sudo", "-n"] + cmd_args
            proc_sudo = subprocess.run(
                sudo_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if proc_sudo.returncode == 0:
                return True, proc_sudo.stdout, proc_sudo.stderr
            return False, proc_sudo.stdout, proc_sudo.stderr
            
        return False, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Lệnh thực thi quá thời gian cho phép (timeout)"
    except Exception as e:
        return False, "", str(e)

def reload_crowdsec():
    """Reload lại service CrowdSec sau khi thêm/sửa/bật/tắt scenario"""
    run_command(["systemctl", "reload", "crowdsec"])

def is_safe_scenarios_path(fpath):
    """Kiểm tra đường dẫn an toàn để tránh Path Traversal"""
    if not fpath:
        return False
    norm = os.path.normpath(os.path.abspath(fpath))
    return norm.startswith(SCENARIOS_DIR) or norm.startswith(HUB_SCENARIOS_DIR)

# ==========================================
# DECISIONS FUNCTIONS (Tab 1)
# ==========================================

def parse_table_output(text):
    decisions = []
    lines = text.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("╭") or line.startswith("├") or line.startswith("╰") or line.startswith("+"):
            continue
        if "│" in line:
            parts = [p.strip() for p in line.split("│")[1:-1]]
        elif "|" in line:
            parts = [p.strip() for p in line.split("|")[1:-1]]
        else:
            continue

        if len(parts) >= 10:
            if parts[0].upper() == "ID":
                continue

            scope_val = parts[2]
            scope = ""
            val = scope_val
            if ":" in scope_val:
                scope, val = scope_val.split(":", 1)

            decisions.append({
                "id": parts[0],
                "source": parts[1],
                "scope": scope,
                "value": val,
                "scope_value": scope_val,
                "reason": parts[3],
                "action": parts[4],
                "country": parts[5],
                "as": parts[6],
                "events": parts[7],
                "expiration": parts[8],
                "alert_id": parts[9]
            })
    return decisions

def parse_json_decisions(data):
    results = []
    if not isinstance(data, list):
        return results

    for item in data:
        if "decisions" in item and isinstance(item["decisions"], list):
            alert_id = item.get("id", "")
            events_count = item.get("events_count", "")
            source = item.get("source", {}) or {}
            cn = source.get("cn", "") or ""
            as_num = source.get("as_number", "") or ""
            as_name = source.get("as_name", "") or ""
            as_full = f"{as_num} {as_name}".strip()

            for dec in item["decisions"]:
                scope = dec.get("scope", "")
                val = dec.get("value", "")
                results.append({
                    "id": str(dec.get("id", "")),
                    "source": dec.get("origin", "") or dec.get("source", ""),
                    "scope": scope,
                    "value": val,
                    "scope_value": f"{scope}:{val}" if scope and val else (val or scope),
                    "reason": dec.get("scenario", "") or item.get("scenario", ""),
                    "action": dec.get("type", "ban"),
                    "country": cn,
                    "as": as_full,
                    "events": str(events_count),
                    "expiration": dec.get("duration", ""),
                    "alert_id": str(alert_id)
                })
        else:
            scope = item.get("scope", "")
            val = item.get("value", "")
            results.append({
                "id": str(item.get("id", "")),
                "source": item.get("origin", item.get("source", "")),
                "scope": scope,
                "value": val,
                "scope_value": f"{scope}:{val}" if scope and val else (val or scope),
                "reason": item.get("scenario", item.get("reason", "")),
                "action": item.get("type", item.get("action", "ban")),
                "country": item.get("country", item.get("cn", "")),
                "as": item.get("as", ""),
                "events": str(item.get("events_count", item.get("events", ""))),
                "expiration": item.get("duration", item.get("expiration", "")),
                "alert_id": str(item.get("alert_id", ""))
            })
    return results

def get_decisions(include_all=False):
    global DEMO_MODE
    if DEMO_MODE:
        return True, list(DEMO_DECISIONS), ""

    cmd = ["cscli", "decisions", "list"]
    if include_all:
        cmd.append("-a")
    cmd.extend(["-o", "json"])

    success, stdout, stderr = run_command(cmd)
    if success:
        stdout_clean = stdout.strip()
        if not stdout_clean or stdout_clean == "null":
            return True, [], ""
        try:
            data = json.loads(stdout_clean)
            return True, parse_json_decisions(data), ""
        except json.JSONDecodeError:
            pass

    fallback_cmd = ["cscli", "decisions", "list"]
    if include_all:
        fallback_cmd.append("-a")

    f_success, f_stdout, f_stderr = run_command(fallback_cmd)
    if f_success:
        if "no active decisions" in f_stdout.lower():
            return True, [], ""
        decisions = parse_table_output(f_stdout)
        return True, decisions, ""

    raw_err = (stderr or f_stderr or stdout or "").strip()
    if "permission denied" in raw_err.lower():
        err_msg = (
            "Lỗi phân quyền: Không thể đọc cấu hình /etc/crowdsec/config.yaml.\n"
            "Vui lòng chạy web server với quyền root: 'sudo python3 app.py'"
        )
    else:
        err_msg = f"Lỗi khi thực thi lệnh cscli decisions list: {raw_err}"

    return False, [], err_msg

def add_decision(target, duration="4h", reason="manual ban from web", action_type="ban"):
    global DEMO_MODE
    target = target.strip()
    if not target:
        return False, "Địa chỉ IP hoặc dải mạng không được để trống"

    is_range = False
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
            is_range = True
        else:
            ipaddress.ip_address(target)
    except ValueError:
        return False, f"Địa chỉ IP hoặc dải mạng '{target}' không hợp lệ"

    if not re.match(r"^[0-9]+[smhd]$", duration):
        duration = "4h"

    if action_type not in ["ban", "captcha", "throttle"]:
        action_type = "ban"

    clean_reason = re.sub(r"[^a-zA-Z0-9_\-\.\/ ]", "", reason).strip()
    if not clean_reason:
        clean_reason = "manual-ban"

    if DEMO_MODE:
        new_id = str(len(DEMO_DECISIONS) + 467420)
        DEMO_DECISIONS.insert(0, {
            "id": new_id,
            "source": "cscli",
            "scope": "Range" if is_range else "Ip",
            "value": target,
            "scope_value": f"{'Range' if is_range else 'Ip'}:{target}",
            "reason": clean_reason,
            "action": action_type,
            "country": "VN",
            "as": "Manual Entry",
            "events": "1",
            "expiration": duration,
            "alert_id": str(len(DEMO_DECISIONS) + 390)
        })
        return True, f"[Demo Mode] Đã thêm quyết định chặn cho {target}"

    cmd = ["cscli", "decisions", "add"]
    if is_range:
        cmd.extend(["-r", target])
    else:
        cmd.extend(["-i", target])

    cmd.extend(["-d", duration, "-R", clean_reason, "-t", action_type])

    success, stdout, stderr = run_command(cmd)
    if success:
        return True, (stdout or "Đã thêm IP vào danh sách chặn thành công").strip()
    else:
        err_msg = (stderr or stdout or "Thao tác thêm thất bại").strip()
        if "permission denied" in err_msg.lower():
            err_msg = "Lỗi phân quyền: Cần chạy ứng dụng với quyền root (sudo python3 app.py)"
        return False, err_msg

def delete_decision(ip=None, decision_id=None):
    """
    Xóa quyết định chặn khỏi CrowdSec bằng IP/Range hoặc ID.
    Chiến lược ưu tiên:
    1. ƯU TIÊN HÀNG ĐẦU: Xóa theo IP/Range ('cscli decisions delete -i <IP>' hoặc -r <RANGE>):
       Xóa toàn bộ các luật chặn trùng lặp đối với cùng 1 IP (tránh việc 1 IP dính nhiều kịch bản gây chặn lặp).
    2. DỰ PHÒNG 1: Thử thêm 'cscli decisions delete --value <IP>'.
    3. DỰ PHÒNG 2: Nếu xóa theo IP không khớp và có ID -> Thử xóa bằng 'cscli decisions delete --id <ID>'.
    """
    global DEMO_MODE
    target = (ip or "").strip()
    dec_id = str(decision_id or "").strip()
    if dec_id in ["-", "None", "null", "undefined"]:
        dec_id = ""

    # Chuẩn hóa target: loại bỏ tiền tố Ip: hoặc Range: nếu có
    if re.match(r"^(ip|range):", target, re.I):
        target = re.sub(r"^(ip|range):", "", target, flags=re.I).strip()

    if DEMO_MODE:
        global DEMO_DECISIONS
        original_len = len(DEMO_DECISIONS)
        if target:
            # Xóa toàn bộ quyết định trùng IP / Range trong Demo Mode
            DEMO_DECISIONS = [d for d in DEMO_DECISIONS if d.get("value") != target and d.get("scope_value") != target]
        elif dec_id:
            DEMO_DECISIONS = [d for d in DEMO_DECISIONS if str(d.get("id")) != dec_id]
        
        if len(DEMO_DECISIONS) < original_len:
            deleted_count = original_len - len(DEMO_DECISIONS)
            return True, f"[Demo Mode] Đã xóa {deleted_count} quyết định chặn cho {target or ('ID ' + dec_id)}"
        return True, "[Demo Mode] Không tìm thấy bản ghi tương ứng để xóa"

    if not target and not dec_id:
        return False, "Cần cung cấp địa chỉ IP hoặc ID quyết định để xóa"

    errors = []

    # 1. ƯU TIÊN HÀNG ĐẦU: Xóa theo IP hoặc Dải mạng (-i / -r) để xóa sạch các luật trùng lặp
    if target:
        is_range = ("/" in target)
        flag = "-r" if is_range else "-i"
        cmd_ip = ["cscli", "decisions", "delete", flag, target]
        success, stdout, stderr = run_command(cmd_ip)
        combined = f"{stdout}\n{stderr}".strip()
        if success and "0 decision(s) deleted" not in combined.lower():
            clean_msg = stdout.strip() or stderr.strip() or f"Đã xóa thành công quyết định cho {target}"
            return True, clean_msg
        if combined:
            errors.append(combined)

        # 2. Thử xóa theo --value target (dự phòng trường hợp scope đặc thù)
        cmd_val = ["cscli", "decisions", "delete", "--value", target]
        success, stdout, stderr = run_command(cmd_val)
        combined = f"{stdout}\n{stderr}".strip()
        if success and "0 decision(s) deleted" not in combined.lower():
            clean_msg = stdout.strip() or stderr.strip() or f"Đã xóa thành công quyết định cho {target}"
            return True, clean_msg
        if combined:
            errors.append(combined)

    # 3. DỰ PHÒNG: Nếu xóa theo IP không khớp nhưng có ID cụ thể -> Thử xóa theo --id
    if dec_id and dec_id.isdigit():
        cmd_id = ["cscli", "decisions", "delete", "--id", dec_id]
        success, stdout, stderr = run_command(cmd_id)
        combined = f"{stdout}\n{stderr}".strip()
        if success and "0 decision(s) deleted" not in combined.lower():
            clean_msg = stdout.strip() or stderr.strip() or f"Đã xóa thành công quyết định ID {dec_id}"
            return True, clean_msg
        if combined:
            errors.append(combined)

    # Nếu tất cả các cách đều không xóa được
    err_text = " | ".join(errors) if errors else "Không tìm thấy quyết định tương ứng trên CrowdSec để xóa (0 decision deleted)"
    if "permission denied" in err_text.lower():
        err_text = "Lỗi phân quyền: Cần chạy ứng dụng với quyền root (sudo python3 app.py)"
    return False, err_text

# ==========================================
# SCENARIOS FUNCTIONS (Tab 2)
# ==========================================

def get_scenarios_from_fs():
    """Quét trực tiếp thư mục /etc/crowdsec/scenarios/ để lấy danh sách kịch bản (kể cả khi không có cscli root)"""
    if not os.path.exists(SCENARIOS_DIR):
        return []
    items = []
    try:
        filenames = sorted(os.listdir(SCENARIOS_DIR))
    except Exception:
        return []

    for fname in filenames:
        fpath = os.path.join(SCENARIOS_DIR, fname)
        is_disabled = fname.endswith(".disabled")
        is_yaml = fname.endswith(".yaml") or fname.endswith(".yml") or is_disabled
        if not is_yaml:
            continue

        is_link = os.path.islink(fpath)
        name = fname
        desc = ""

        # Đọc tiêu đề name & description trong file
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(30):
                    line = f.readline()
                    if not line: break
                    line = line.strip()
                    if line.startswith("name:"):
                        name = line.split(":", 1)[1].strip().strip("\"'")
                    elif line.startswith("description:"):
                        desc = line.split(":", 1)[1].strip().strip("\"'")
        except Exception:
            pass

        hub_name = ""
        if is_link:
            try:
                target = os.readlink(fpath)
                if "hub/scenarios/" in target:
                    rel = target.split("hub/scenarios/", 1)[1]
                    hub_name = rel.replace(".yaml", "").replace(".yml", "")
            except Exception:
                pass

        items.append({
            "name": hub_name or name,
            "filename": fname,
            "path": fpath,
            "is_link": is_link,
            "is_custom": not is_link,
            "status": "disabled" if is_disabled else "enabled",
            "description": desc or ("Kịch bản tự tạo (Local)" if not is_link else "Kịch bản CrowdSec Hub"),
            "type": "Local" if not is_link else "Hub",
            "version": "local" if not is_link else "hub"
        })
    return items

def get_scenarios(include_all=False):
    """
    Lấy danh sách Scenarios:
    1. Gọi lệnh 'cscli scenarios list [-a] -o json'
    2. Quét thư mục /etc/crowdsec/scenarios/ để bổ sung các kịch bản Local / Tùy chỉnh
    """
    global DEMO_MODE
    if DEMO_MODE:
        return True, list(DEMO_SCENARIOS), ""

    results = []
    seen_names = set()
    seen_paths = set()

    # Thử gọi cscli scenarios list -o json
    cmd = ["cscli", "scenarios", "list"]
    if include_all:
        cmd.append("-a")
    cmd.extend(["-o", "json"])

    success, stdout, stderr = run_command(cmd)
    if success and stdout.strip():
        try:
            data = json.loads(stdout.strip())
            if isinstance(data, list):
                for item in data:
                    name = item.get("name", "")
                    local_path = item.get("local_path", "")
                    status = item.get("status", "disabled")
                    desc = item.get("description", "")
                    version = item.get("version", item.get("local_version", "1.0.0"))
                    is_custom = item.get("local_only", False) or (local_path and not item.get("download_url"))

                    scenario_obj = {
                        "name": name,
                        "filename": os.path.basename(local_path) if local_path else f"{name.replace('/', '_')}.yaml",
                        "path": local_path or os.path.join(SCENARIOS_DIR, f"{os.path.basename(name)}.yaml"),
                        "status": status,
                        "type": "Local" if is_custom else "Hub",
                        "is_custom": bool(is_custom),
                        "description": desc or ("Kịch bản CrowdSec Hub" if not is_custom else "Kịch bản tự tạo"),
                        "version": version or "hub"
                    }
                    results.append(scenario_obj)
                    if name: seen_names.add(name)
                    if local_path: seen_paths.add(local_path)
        except Exception:
            pass

    # Quét thêm từ filesystem /etc/crowdsec/scenarios/
    fs_items = get_scenarios_from_fs()
    for it in fs_items:
        # Nếu chưa có trong danh sách từ cscli
        if it["name"] not in seen_names and it["path"] not in seen_paths:
            results.append(it)
            seen_names.add(it["name"])
            seen_paths.add(it["path"])
        else:
            # Cập nhật thêm nếu là file local
            for r in results:
                if (r.get("path") == it["path"] or r.get("name") == it["name"]) and it.get("is_custom"):
                    r["is_custom"] = True
                    r["type"] = "Local"

    if not results and not success:
        # Nếu cscli thất bại và không quét được gì do phân quyền
        raw_err = (stderr or stdout or "").strip()
        if "permission denied" in raw_err.lower():
            err_msg = "Lỗi phân quyền: Cần chạy ứng dụng với quyền root (sudo python3 app.py)"
        else:
            err_msg = f"Lỗi cscli scenarios list: {raw_err}"
        return False, [], err_msg

    return True, results, ""

def resolve_scenario_filepath(fpath):
    """Tìm file tồn tại thực tế trên đĩa (kể cả có đuôi .disabled hoặc không)"""
    if not fpath:
        return None
    candidate = fpath
    if not os.path.isabs(candidate):
        candidate = os.path.join(SCENARIOS_DIR, candidate)

    if os.path.exists(candidate):
        return candidate
    if not candidate.endswith(".disabled") and os.path.exists(candidate + ".disabled"):
        return candidate + ".disabled"
    if candidate.endswith(".disabled") and os.path.exists(candidate[:-9]):
        return candidate[:-9]
    return candidate

def find_scenario_target(name, fpath=None, is_custom=None):
    """
    Xác định chính xác file và phân loại kịch bản là Local (tự tạo) hay Hub:
    Trả về: (real_path, is_local_custom, is_disabled)
    """
    name = (name or "").strip()
    real_path = resolve_scenario_filepath(fpath) if fpath else None

    # 1. Nếu fpath trỏ tới file tồn tại trên đĩa
    if real_path and os.path.exists(real_path):
        is_link = os.path.islink(real_path)
        is_disabled = real_path.endswith(".disabled")
        # File symlink trỏ vào hub/scenarios -> Hub scenario
        # File thông thường (không phải symlink) trong /etc/crowdsec/scenarios/ -> Local Custom scenario
        is_local = not is_link
        return real_path, is_local, is_disabled

    # 2. Quét thư mục SCENARIOS_DIR để tìm file tương ứng với name
    if os.path.exists(SCENARIOS_DIR):
        try:
            for fname in os.listdir(SCENARIOS_DIR):
                candidate = os.path.join(SCENARIOS_DIR, fname)
                is_disabled = fname.endswith(".disabled")
                base_name = fname[:-9] if is_disabled else fname
                stem = os.path.splitext(base_name)[0]

                matched = False
                if name and (name == base_name or name == stem or os.path.basename(name) == stem):
                    matched = True

                if not matched and name:
                    try:
                        with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                            for _ in range(30):
                                line = f.readline()
                                if not line: break
                                if line.strip().startswith("name:"):
                                    sc_n = line.strip().split(":", 1)[1].strip().strip("\"'")
                                    if sc_n == name:
                                        matched = True
                                        break
                    except Exception:
                        pass

                if matched:
                    is_link = os.path.islink(candidate)
                    return candidate, (not is_link), is_disabled
        except Exception:
            pass

    # 3. Nếu caller truyền is_custom rõ ràng:
    if is_custom is True:
        clean_name = os.path.basename(name or "custom")
        if not clean_name.endswith(".yaml") and not clean_name.endswith(".yml"):
            clean_name += ".yaml"
        suggested = os.path.join(SCENARIOS_DIR, clean_name)
        return suggested, True, False

    # 4. Mặc định: Coi là Hub scenario
    return real_path or fpath, False, False

def get_scenario_content(fpath):
    """Đọc nội dung file YAML kịch bản"""
    global DEMO_MODE
    if DEMO_MODE:
        for sc in DEMO_SCENARIOS:
            if sc.get("path") == fpath or sc.get("filename") == fpath or sc.get("name") == fpath:
                return True, sc.get("content", "# Không có nội dung mẫu"), ""
        return True, "# Demo Scenario Content\ntype: leaky\nname: demo/custom\n", ""

    real_path = resolve_scenario_filepath(fpath)
    if not real_path or not is_safe_scenarios_path(real_path):
        return False, "", "Đường dẫn file không an toàn hoặc nằm ngoài phạm vi CrowdSec"

    if not os.path.exists(real_path):
        return False, "", f"File không tồn tại: {fpath}"

    try:
        with open(real_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return True, content, ""
    except Exception as e:
        return False, "", f"Không thể đọc file {real_path}: {str(e)}"

def add_scenario(filename, content):
    """Thêm kịch bản mới và lưu vào /etc/crowdsec/scenarios/<tên file scenarios>.yml"""
    global DEMO_MODE
    filename = filename.strip()
    if not filename:
        return False, "Tên file scenario không được để trống"

    clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "", filename)
    if not clean_name.endswith(".yml") and not clean_name.endswith(".yaml"):
        clean_name += ".yml"

    target_path = os.path.join(SCENARIOS_DIR, clean_name)
    if not is_safe_scenarios_path(target_path):
        return False, "Đường dẫn file không an toàn"

    # Trích xuất tên kịch bản từ nội dung YAML (nếu có trường name:)
    sc_name = clean_name.replace(".yml", "").replace(".yaml", "")
    for line in content.splitlines():
        if line.strip().startswith("name:"):
            sc_name = line.strip().split(":", 1)[1].strip().strip("\"'")
            break

    if DEMO_MODE:
        DEMO_SCENARIOS.insert(0, {
            "name": sc_name,
            "filename": clean_name,
            "path": target_path,
            "status": "enabled",
            "type": "Local",
            "is_custom": True,
            "description": "Kịch bản tự tạo (Demo)",
            "version": "local",
            "content": content
        })
        return True, f"[Demo Mode] Đã lưu kịch bản vào {target_path}"

    if os.path.exists(target_path):
        return False, f"File kịch bản '{clean_name}' đã tồn tại trên đĩa. Vui lòng chọn tên khác hoặc chỉnh sửa file cũ."

    try:
        os.makedirs(SCENARIOS_DIR, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
        reload_crowdsec()
        return True, f"Đã lưu thành công kịch bản vào {target_path}"
    except Exception as e:
        return False, f"Lỗi khi lưu file: {str(e)}"

def save_scenario(fpath, content):
    """Chỉnh sửa và lưu lại nội dung kịch bản"""
    global DEMO_MODE
    if DEMO_MODE:
        for sc in DEMO_SCENARIOS:
            if sc.get("path") == fpath or sc.get("filename") == os.path.basename(fpath):
                sc["content"] = content
                return True, f"[Demo Mode] Đã lưu thay đổi cho {os.path.basename(fpath)}"
        return True, f"[Demo Mode] Đã lưu thay đổi"

    real_path = resolve_scenario_filepath(fpath)
    if not real_path or not is_safe_scenarios_path(real_path):
        return False, "Đường dẫn file không an toàn"

    if not os.path.exists(real_path):
        return False, f"File không tồn tại: {fpath}"

    try:
        # Tạo file backup .bak đề phòng rủi ro
        try:
            with open(real_path, "r", encoding="utf-8") as orig:
                old = orig.read()
            with open(real_path + ".bak", "w", encoding="utf-8") as bak:
                bak.write(old)
        except Exception:
            pass

        with open(real_path, "w", encoding="utf-8") as f:
            f.write(content)
        reload_crowdsec()
        return True, f"Đã cập nhật thành công kịch bản {os.path.basename(real_path)}"
    except Exception as e:
        return False, f"Lỗi khi ghi file: {str(e)}"

def scenario_action(name, fpath, action, is_custom=None):
    """
    Thực hiện hành động Bật (enable), Tắt (disable), hoặc Xóa (delete) kịch bản
    """
    global DEMO_MODE
    name = (name or "").strip()
    fpath = (fpath or "").strip()
    action = (action or "").lower().strip()

    if action not in ["enable", "disable", "delete"]:
        return False, f"Hành động '{action}' không hợp lệ (hỗ trợ: enable, disable, delete)"

    if DEMO_MODE:
        global DEMO_SCENARIOS
        for sc in DEMO_SCENARIOS:
            if sc.get("name") == name or sc.get("path") == fpath:
                if action == "enable":
                    sc["status"] = "enabled"
                    return True, f"[Demo Mode] Đã bật kịch bản {name}"
                elif action == "disable":
                    sc["status"] = "disabled"
                    return True, f"[Demo Mode] Đã tắt kịch bản {name}"
                elif action == "delete":
                    DEMO_SCENARIOS = [s for s in DEMO_SCENARIOS if s.get("name") != name]
                    return True, f"[Demo Mode] Đã xóa kịch bản {name}"
        return True, f"[Demo Mode] Thao tác thành công"

    real_path, is_local_custom, is_disabled = find_scenario_target(name, fpath, is_custom)

    # 1. Hành động Xóa (DELETE)
    if action == "delete":
        if is_local_custom:
            if not real_path or not is_safe_scenarios_path(real_path):
                return False, "Đường dẫn file không hợp lệ để xóa"
            try:
                deleted_any = False
                candidates = [
                    real_path,
                    real_path + ".disabled",
                    real_path + ".bak",
                ]
                if real_path.endswith(".disabled"):
                    candidates.extend([
                        real_path[:-9],
                        real_path[:-9] + ".bak"
                    ])
                for p in set(candidates):
                    if os.path.exists(p):
                        os.remove(p)
                        deleted_any = True
                reload_crowdsec()
                if deleted_any:
                    return True, f"Đã xóa file kịch bản tự tạo: {os.path.basename(real_path)}"
                return False, f"Không tìm thấy file kịch bản để xóa: {os.path.basename(real_path)}"
            except Exception as e:
                return False, f"Lỗi khi xóa file: {str(e)}"
        else:
            # Hub Scenario -> cscli scenarios remove <name> --purge
            success, stdout, stderr = run_command(["cscli", "scenarios", "remove", name, "--purge"])
            if not success:
                success, stdout, stderr = run_command(["cscli", "scenarios", "remove", name])
            reload_crowdsec()
            if success:
                return True, f"Đã gỡ bỏ kịch bản Hub: {name}"
            return False, f"Lỗi khi xóa kịch bản: {stderr or stdout}"

    # 2. Hành động Tắt (DISABLE)
    elif action == "disable":
        if is_local_custom:
            if not real_path or not is_safe_scenarios_path(real_path):
                return False, "Đường dẫn file không hợp lệ"
            if not real_path.endswith(".disabled"):
                new_path = real_path + ".disabled"
                try:
                    os.rename(real_path, new_path)
                    reload_crowdsec()
                    return True, f"Đã tắt kịch bản tự tạo: {os.path.basename(real_path)}"
                except Exception as e:
                    return False, f"Không thể đổi tên file để tắt kịch bản: {str(e)}"
            return True, f"Kịch bản '{os.path.basename(real_path)}' đã ở trạng thái tắt"
        else:
            # Hub Scenario -> cscli scenarios remove <name>
            success, stdout, stderr = run_command(["cscli", "scenarios", "remove", name])
            reload_crowdsec()
            if success:
                return True, f"Đã tắt kịch bản Hub: {name}"
            return False, f"Lỗi khi tắt kịch bản: {stderr or stdout}"

    # 3. Hành động Bật (ENABLE)
    elif action == "enable":
        if is_local_custom:
            if not real_path or not is_safe_scenarios_path(real_path):
                return False, "Đường dẫn file không hợp lệ"
            if real_path.endswith(".disabled"):
                new_path = real_path[:-9]  # Cắt bỏ đuôi .disabled
                try:
                    os.rename(real_path, new_path)
                    reload_crowdsec()
                    return True, f"Đã kích hoạt kịch bản tự tạo: {os.path.basename(new_path)}"
                except Exception as e:
                    return False, f"Không thể đổi tên file để kích hoạt kịch bản: {str(e)}"
            else:
                reload_crowdsec()
                return True, f"Kịch bản '{os.path.basename(real_path)}' đã ở trạng thái bật"
        else:
            # Hub Scenario -> cscli scenarios install <name>
            success, stdout, stderr = run_command(["cscli", "scenarios", "install", name])
            reload_crowdsec()
            if success:
                return True, f"Đã kích hoạt kịch bản Hub: {name}"
            return False, f"Lỗi khi kích hoạt kịch bản: {stderr or stdout}"

    return False, "Yêu cầu không được hỗ trợ"


# ==========================================
# TAB 3: REAL-TIME SYSTEM MONITORING (CPU, RAM, NETWORK)
# ==========================================

def format_bytes_human(b):
    if b >= 1024 * 1024 * 1024:
        return f"{b / (1024**3):.2f} GB"
    elif b >= 1024 * 1024:
        return f"{b / (1024**2):.2f} MB"
    elif b >= 1024:
        return f"{b / 1024:.2f} KB"
    return f"{int(b)} B"

def format_rate_human(bps):
    if bps >= 1024 * 1024:
        return f"{bps / (1024**2):.2f} MB/s"
    elif bps >= 1024:
        return f"{bps / (1024**2):.2f} MB/s" if bps >= 1024 * 1024 else f"{bps / 1024:.2f} KB/s"
    elif bps >= 1024:
        return f"{bps / 1024:.2f} KB/s"
    return f"{int(bps)} B/s"

def format_uptime_human(seconds):
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    parts = []
    if days > 0:
        parts.append(f"{days} ngày")
    if hours > 0 or days > 0:
        parts.append(f"{hours} giờ")
    parts.append(f"{minutes} phút")
    return ", ".join(parts) if parts else "dưới 1 phút"

def get_interface_ip(ifname):
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915, # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
        s.close()
        return ip
    except Exception:
        return ""

_CPU_MODEL = None
def get_cpu_model():
    global _CPU_MODEL
    if _CPU_MODEL:
        return _CPU_MODEL
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if "model name" in line:
                    _CPU_MODEL = line.split(":", 1)[1].strip()
                    return _CPU_MODEL
    except Exception:
        pass
    _CPU_MODEL = platform.processor() or "Unknown CPU"
    return _CPU_MODEL

def _read_cpu_raw():
    overall = (0.0, 0.0)
    cores = {}
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("cpu"):
                    parts = line.strip().split()
                    name = parts[0]
                    vals = [float(x) for x in parts[1:]]
                    idle = vals[3] + (vals[4] if len(vals) > 4 else 0.0)
                    tot = sum(vals)
                    if name == "cpu":
                        overall = (idle, tot)
                    else:
                        cores[name] = (idle, tot)
    except Exception:
        pass
    return overall, cores

def _read_memory():
    info = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    info[parts[0].strip()] = int(parts[1].strip().split()[0])
    except Exception:
        pass

    total_kb = info.get("MemTotal", 0)
    free_kb = info.get("MemFree", 0)
    avail_kb = info.get("MemAvailable", free_kb)
    used_kb = max(0, total_kb - avail_kb)

    total_mb = round(total_kb / 1024, 1)
    used_mb = round(used_kb / 1024, 1)
    free_mb = round(free_kb / 1024, 1)
    avail_mb = round(avail_kb / 1024, 1)
    pct = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0.0

    swap_total_kb = info.get("SwapTotal", 0)
    swap_free_kb = info.get("SwapFree", 0)
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    swap_total_mb = round(swap_total_kb / 1024, 1)
    swap_used_mb = round(swap_used_kb / 1024, 1)
    swap_pct = round((swap_used_kb / swap_total_kb) * 100, 1) if swap_total_kb > 0 else 0.0

    return {
        "total_mb": total_mb,
        "used_mb": used_mb,
        "free_mb": free_mb,
        "available_mb": avail_mb,
        "percent": pct,
        "swap_total_mb": swap_total_mb,
        "swap_used_mb": swap_used_mb,
        "swap_percent": swap_pct,
        "total_formatted": format_bytes_human(total_kb * 1024),
        "used_formatted": format_bytes_human(used_kb * 1024),
        "available_formatted": format_bytes_human(avail_kb * 1024)
    }

def _read_net_raw():
    net = {}
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines[2:]:
                parts = line.split(":")
                if len(parts) == 2:
                    iface = parts[0].strip()
                    vals = [int(x) for x in parts[1].split()]
                    net[iface] = {
                        "rx_bytes": vals[0],
                        "rx_pkts": vals[1],
                        "rx_errs": vals[2],
                        "rx_drop": vals[3],
                        "tx_bytes": vals[8],
                        "tx_pkts": vals[9],
                        "tx_errs": vals[10],
                        "tx_drop": vals[11]
                    }
    except Exception:
        pass
    return net

_system_metrics_cache = {
    "last_time": 0.0,
    "last_cpu_overall": (0.0, 0.0),
    "last_cpu_cores": {},
    "last_net": {},
    "last_rates": {
        "cpu_percent": 0.0,
        "cores_percent": [],
        "rx_bytes_sec": 0.0,
        "tx_bytes_sec": 0.0,
        "rx_pkts_sec": 0.0,
        "tx_pkts_sec": 0.0,
        "iface_rates": {}
    }
}
_metrics_lock = threading.Lock()

def get_system_metrics():
    with _metrics_lock:
        now = time.time()
        curr_overall, curr_cores = _read_cpu_raw()
        curr_net = _read_net_raw()
        curr_mem = _read_memory()

        if _system_metrics_cache["last_time"] == 0.0:
            time.sleep(0.1)
            now2 = time.time()
            curr2_overall, curr2_cores = _read_cpu_raw()
            curr2_net = _read_net_raw()
            dt = max(0.001, now2 - now)

            d_idle = curr2_overall[0] - curr_overall[0]
            d_tot = curr2_overall[1] - curr_overall[1]
            cpu_pct = max(0.0, min(100.0, round((1.0 - d_idle / d_tot) * 100, 1))) if d_tot > 0 else 0.0

            cores_list = []
            for cname in sorted(curr2_cores.keys()):
                ci_prev = curr_cores.get(cname, (0.0, 0.0))
                ci_curr = curr2_cores[cname]
                cd_idle = ci_curr[0] - ci_prev[0]
                cd_tot = ci_curr[1] - ci_prev[1]
                cpct = max(0.0, min(100.0, round((1.0 - cd_idle / cd_tot) * 100, 1))) if cd_tot > 0 else 0.0
                cores_list.append({"core": cname, "percent": cpct})

            iface_rates = {}
            total_rx_bps = 0.0
            total_tx_bps = 0.0
            total_rx_pps = 0.0
            total_tx_pps = 0.0
            for iface, cur_st in curr2_net.items():
                prev_st = curr_net.get(iface, cur_st)
                rx_rate = max(0.0, (cur_st["rx_bytes"] - prev_st["rx_bytes"]) / dt)
                tx_rate = max(0.0, (cur_st["tx_bytes"] - prev_st["tx_bytes"]) / dt)
                rx_pps = max(0.0, (cur_st["rx_pkts"] - prev_st["rx_pkts"]) / dt)
                tx_pps = max(0.0, (cur_st["tx_pkts"] - prev_st["tx_pkts"]) / dt)

                iface_rates[iface] = {
                    "rx_bytes_sec": rx_rate,
                    "tx_bytes_sec": tx_rate,
                    "rx_pkts_sec": rx_pps,
                    "tx_pkts_sec": tx_pps
                }
                if iface != "lo":
                    total_rx_bps += rx_rate
                    total_tx_bps += tx_rate
                    total_rx_pps += rx_pps
                    total_tx_pps += tx_pps

            _system_metrics_cache["last_time"] = now2
            _system_metrics_cache["last_cpu_overall"] = curr2_overall
            _system_metrics_cache["last_cpu_cores"] = curr2_cores
            _system_metrics_cache["last_net"] = curr2_net
            _system_metrics_cache["last_rates"] = {
                "cpu_percent": cpu_pct,
                "cores_percent": cores_list,
                "rx_bytes_sec": total_rx_bps,
                "tx_bytes_sec": total_tx_bps,
                "rx_pkts_sec": total_rx_pps,
                "tx_pkts_sec": total_tx_pps,
                "iface_rates": iface_rates
            }
            curr_net = curr2_net
        else:
            dt = now - _system_metrics_cache["last_time"]
            if dt >= 0.2:
                d_idle = curr_overall[0] - _system_metrics_cache["last_cpu_overall"][0]
                d_tot = curr_overall[1] - _system_metrics_cache["last_cpu_overall"][1]
                cpu_pct = max(0.0, min(100.0, round((1.0 - d_idle / d_tot) * 100, 1))) if d_tot > 0 else 0.0

                cores_list = []
                for cname in sorted(curr_cores.keys()):
                    ci_prev = _system_metrics_cache["last_cpu_cores"].get(cname, (0.0, 0.0))
                    ci_curr = curr_cores[cname]
                    cd_idle = ci_curr[0] - ci_prev[0]
                    cd_tot = ci_curr[1] - ci_prev[1]
                    cpct = max(0.0, min(100.0, round((1.0 - cd_idle / cd_tot) * 100, 1))) if cd_tot > 0 else 0.0
                    cores_list.append({"core": cname, "percent": cpct})

                iface_rates = {}
                total_rx_bps = 0.0
                total_tx_bps = 0.0
                total_rx_pps = 0.0
                total_tx_pps = 0.0
                for iface, cur_st in curr_net.items():
                    prev_st = _system_metrics_cache["last_net"].get(iface, cur_st)
                    rx_rate = max(0.0, (cur_st["rx_bytes"] - prev_st["rx_bytes"]) / dt)
                    tx_rate = max(0.0, (cur_st["tx_bytes"] - prev_st["tx_bytes"]) / dt)
                    rx_pps = max(0.0, (cur_st["rx_pkts"] - prev_st["rx_pkts"]) / dt)
                    tx_pps = max(0.0, (cur_st["tx_pkts"] - prev_st["tx_pkts"]) / dt)

                    iface_rates[iface] = {
                        "rx_bytes_sec": rx_rate,
                        "tx_bytes_sec": tx_rate,
                        "rx_pkts_sec": rx_pps,
                        "tx_pkts_sec": tx_pps
                    }
                    if iface != "lo":
                        total_rx_bps += rx_rate
                        total_tx_bps += tx_rate
                        total_rx_pps += rx_pps
                        total_tx_pps += tx_pps

                _system_metrics_cache["last_time"] = now
                _system_metrics_cache["last_cpu_overall"] = curr_overall
                _system_metrics_cache["last_cpu_cores"] = curr_cores
                _system_metrics_cache["last_net"] = curr_net
                _system_metrics_cache["last_rates"] = {
                    "cpu_percent": cpu_pct,
                    "cores_percent": cores_list,
                    "rx_bytes_sec": total_rx_bps,
                    "tx_bytes_sec": total_tx_bps,
                    "rx_pkts_sec": total_rx_pps,
                    "tx_pkts_sec": total_tx_pps,
                    "iface_rates": iface_rates
                }

        rates = _system_metrics_cache["last_rates"]

        interfaces_data = []
        total_rx_all_bytes = 0
        total_tx_all_bytes = 0
        for iface, st in curr_net.items():
            if_rate = rates["iface_rates"].get(iface, {
                "rx_bytes_sec": 0.0, "tx_bytes_sec": 0.0, "rx_pkts_sec": 0.0, "tx_pkts_sec": 0.0
            })
            if iface != "lo":
                total_rx_all_bytes += st["rx_bytes"]
                total_tx_all_bytes += st["tx_bytes"]

            if iface == "lo":
                if_type = "Loopback"
            elif iface.startswith("docker") or iface.startswith("br-") or iface.startswith("veth"):
                if_type = "Ảo (Docker/Bridge)"
            elif iface.startswith("wl"):
                if_type = "Không dây (Wi-Fi)"
            elif iface.startswith("en") or iface.startswith("eth"):
                if_type = "Ethernet (Vật lý)"
            else:
                if_type = "Khác"

            interfaces_data.append({
                "name": iface,
                "ip": get_interface_ip(iface),
                "type": if_type,
                "is_loopback": (iface == "lo"),
                "rx_bytes_sec": round(if_rate["rx_bytes_sec"], 1),
                "tx_bytes_sec": round(if_rate["tx_bytes_sec"], 1),
                "rx_rate_formatted": format_rate_human(if_rate["rx_bytes_sec"]),
                "tx_rate_formatted": format_rate_human(if_rate["tx_bytes_sec"]),
                "rx_bytes_total": st["rx_bytes"],
                "tx_bytes_total": st["tx_bytes"],
                "rx_total_formatted": format_bytes_human(st["rx_bytes"]),
                "tx_total_formatted": format_bytes_human(st["tx_bytes"]),
                "rx_packets": st["rx_pkts"],
                "tx_packets": st["tx_pkts"],
                "rx_pkts_sec": round(if_rate["rx_pkts_sec"], 1),
                "tx_pkts_sec": round(if_rate["tx_pkts_sec"], 1),
                "rx_errors": st["rx_errs"],
                "tx_errors": st["tx_errs"],
                "rx_dropped": st["rx_drop"],
                "tx_dropped": st["tx_drop"]
            })

        try:
            load_1, load_5, load_15 = os.getloadavg()
            load_avg = [round(load_1, 2), round(load_5, 2), round(load_15, 2)]
        except Exception:
            load_avg = [0.0, 0.0, 0.0]

        uptime_sec = 0.0
        try:
            with open("/proc/uptime", "r") as f:
                uptime_sec = float(f.readline().split()[0])
        except Exception:
            pass

        return {
            "status": "success",
            "timestamp": now,
            "system": {
                "hostname": platform.node(),
                "os": f"{platform.system()} {platform.release()}",
                "uptime_seconds": int(uptime_sec),
                "uptime_formatted": format_uptime_human(uptime_sec),
                "load_avg": load_avg
            },
            "cpu": {
                "percent": rates["cpu_percent"],
                "model": get_cpu_model(),
                "cores_count": os.cpu_count() or 1,
                "cores": rates["cores_percent"]
            },
            "memory": curr_mem,
            "network": {
                "rx_bytes_sec": round(rates["rx_bytes_sec"], 1),
                "tx_bytes_sec": round(rates["tx_bytes_sec"], 1),
                "rx_rate_formatted": format_rate_human(rates["rx_bytes_sec"]),
                "tx_rate_formatted": format_rate_human(rates["tx_bytes_sec"]),
                "rx_pkts_sec": round(rates["rx_pkts_sec"], 1),
                "tx_pkts_sec": round(rates["tx_pkts_sec"], 1),
                "total_rx_bytes": total_rx_all_bytes,
                "total_tx_bytes": total_tx_all_bytes,
                "total_rx_formatted": format_bytes_human(total_rx_all_bytes),
                "total_tx_formatted": format_bytes_human(total_tx_all_bytes),
                "interfaces": interfaces_data
            }
        }


# ==========================================
# HTTP SERVER & API ROUTING
# ==========================================

class CrowdSecHandler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json_response(self, status_code, data):
        try:
            body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            pass

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        try:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # API Tab 1: Danh sách Decisions
        if path == "/api/decisions":
            include_all = query.get("all", ["false"])[0].lower() in ["1", "true", "yes"]
            force_demo = query.get("demo", ["false"])[0].lower() in ["1", "true", "yes"]
            
            global DEMO_MODE
            original_demo = DEMO_MODE
            if force_demo:
                DEMO_MODE = True

            success, decisions, error = get_decisions(include_all=include_all)
            
            if force_demo and not original_demo:
                DEMO_MODE = original_demo

            if success:
                self.send_json_response(200, {
                    "status": "success",
                    "count": len(decisions),
                    "include_all": include_all,
                    "is_root": is_root(),
                    "demo_mode": DEMO_MODE,
                    "decisions": decisions
                })
            else:
                self.send_json_response(500, {
                    "status": "error",
                    "message": error,
                    "is_root": is_root(),
                    "demo_mode": DEMO_MODE,
                    "decisions": []
                })
            return

        # API Tab 2: Danh sách Scenarios
        if path == "/api/scenarios":
            include_all = query.get("all", ["false"])[0].lower() in ["1", "true", "yes"]
            success, scenarios, error = get_scenarios(include_all=include_all)
            if success:
                self.send_json_response(200, {
                    "status": "success",
                    "count": len(scenarios),
                    "include_all": include_all,
                    "scenarios": scenarios
                })
            else:
                self.send_json_response(500, {
                    "status": "error",
                    "message": error,
                    "scenarios": []
                })
            return

        # API Tab 2: Đọc nội dung file Scenario
        if path == "/api/scenarios/content":
            fpath = query.get("path", [""])[0]
            if not fpath:
                self.send_json_response(400, {"status": "error", "message": "Thiếu tham số 'path'"})
                return
            success, content, error = get_scenario_content(fpath)
            if success:
                self.send_json_response(200, {
                    "status": "success",
                    "path": fpath,
                    "content": content
                })
            else:
                self.send_json_response(500, {
                    "status": "error",
                    "message": error
                })
            return

        # API Tab 3: Giám sát Hệ Thống Realtime (CPU, RAM, Network)
        if path == "/api/system/metrics":
            metrics = get_system_metrics()
            self.send_json_response(200, metrics)
            return

        # API: Bật/Tắt chế độ Demo
        if path == "/api/demo":
            action = query.get("action", ["toggle"])[0]
            if action == "enable":
                DEMO_MODE = True
            elif action == "disable":
                DEMO_MODE = False
            else:
                DEMO_MODE = not DEMO_MODE
            self.send_json_response(200, {"status": "success", "demo_mode": DEMO_MODE})
            return

        # API: Kiểm tra trạng thái hệ thống
        if path == "/api/status":
            cs_success, cs_out, _ = run_command(["cscli", "version"])
            self.send_json_response(200, {
                "status": "success",
                "is_root": is_root(),
                "demo_mode": DEMO_MODE,
                "user": os.getenv("USER", "unknown"),
                "cscli_available": cs_success,
                "cscli_version": cs_out.splitlines()[0] if cs_out else "unknown"
            })
            return

        # Phục vụ static files (HTML, CSS, JS)
        if path == "/" or path == "/index.html":
            file_path = os.path.join(STATIC_DIR, "index.html")
            content_type = "text/html; charset=utf-8"
        elif path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            file_path = os.path.join(STATIC_DIR, rel_path)
            if rel_path.endswith(".css"):
                content_type = "text/css; charset=utf-8"
            elif rel_path.endswith(".js"):
                content_type = "application/javascript; charset=utf-8"
            elif rel_path.endswith(".svg"):
                content_type = "image/svg+xml"
            elif rel_path.endswith(".png"):
                content_type = "image/png"
            elif rel_path.endswith(".ico"):
                content_type = "image/x-icon"
            else:
                content_type = "application/octet-stream"
        else:
            self.send_json_response(404, {"status": "error", "message": "Not Found"})
            return

        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            self.send_json_response(404, {"status": "error", "message": "File not found"})
            return

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            try:
                self.send_json_response(500, {"status": "error", "message": str(e)})
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body) if body else {}
        except Exception as e:
            self.send_json_response(400, {"status": "error", "message": f"Dữ liệu JSON không hợp lệ: {str(e)}"})
            return

        # API Tab 1: Thêm IP / Quyết định chặn (cscli decisions add)
        if path == "/api/decisions":
            ip = payload.get("ip", "")
            duration = payload.get("duration", "4h")
            reason = payload.get("reason", "manual ban from web")
            action_type = payload.get("type", "ban")

            if not ip:
                self.send_json_response(400, {"status": "error", "message": "Vui lòng nhập địa chỉ IP cần chặn"})
                return

            success, message = add_decision(
                target=ip,
                duration=duration,
                reason=reason,
                action_type=action_type
            )
            status_code = 200 if success else 500
            self.send_json_response(status_code, {
                "status": "success" if success else "error",
                "message": message,
                "target": ip
            })
            return

        # API Tab 2: Thêm Scenario mới (/etc/crowdsec/scenarios/<tên file>.yml)
        if path == "/api/scenarios":
            filename = payload.get("filename", "")
            content = payload.get("content", "")

            if not filename:
                self.send_json_response(400, {"status": "error", "message": "Vui lòng nhập tên file scenario"})
                return

            success, message = add_scenario(filename, content)
            status_code = 200 if success else 500
            self.send_json_response(status_code, {
                "status": "success" if success else "error",
                "message": message,
                "filename": filename
            })
            return

        # API Tab 2: Thực hiện hành động Bật / Tắt / Xóa Scenario
        if path == "/api/scenarios/action":
            name = payload.get("name", "")
            fpath = payload.get("path", "")
            action = payload.get("action", "")
            is_custom = payload.get("is_custom")

            if not action:
                self.send_json_response(400, {"status": "error", "message": "Thiếu tham số 'action'"})
                return

            success, message = scenario_action(name, fpath, action, is_custom=is_custom)
            status_code = 200 if success else 500
            self.send_json_response(status_code, {
                "status": "success" if success else "error",
                "message": message,
                "action": action
            })
            return

        self.send_json_response(404, {"status": "error", "message": "Endpoint không tồn tại"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body) if body else {}
        except Exception as e:
            self.send_json_response(400, {"status": "error", "message": f"Dữ liệu JSON không hợp lệ: {str(e)}"})
            return

        # API Tab 2: Chỉnh sửa và lưu lại file Scenario
        if path == "/api/scenarios":
            fpath = payload.get("path", "")
            content = payload.get("content", "")

            if not fpath:
                self.send_json_response(400, {"status": "error", "message": "Thiếu đường dẫn file scenario"})
                return

            success, message = save_scenario(fpath, content)
            status_code = 200 if success else 500
            self.send_json_response(status_code, {
                "status": "success" if success else "error",
                "message": message,
                "path": fpath
            })
            return

        self.send_json_response(404, {"status": "error", "message": "Endpoint không tồn tại"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # API Tab 1: Xóa IP / Quyết định (cscli decisions delete)
        if path == "/api/decisions":
            ip = query.get("ip", [""])[0]
            dec_id = query.get("id", [""])[0]

            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                try:
                    body = self.rfile.read(length).decode("utf-8")
                    payload = json.loads(body)
                    if not ip and "ip" in payload:
                        ip = payload["ip"]
                    if not dec_id and "id" in payload:
                        dec_id = payload["id"]
                except Exception:
                    pass

            if not ip and not dec_id:
                self.send_json_response(400, {
                    "status": "error",
                    "message": "Vui lòng cung cấp tham số 'ip' hoặc 'id' để xóa"
                })
                return

            success, message = delete_decision(ip=ip, decision_id=dec_id)
            status_code = 200 if success else 500
            self.send_json_response(status_code, {
                "status": "success" if success else "error",
                "message": message,
                "ip": ip,
                "id": dec_id
            })
            return

        self.send_json_response(404, {"status": "error", "message": "Endpoint không tồn tại"})

    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Bỏ qua in traceback nếu là BrokenPipeError hoặc ConnectionResetError khi client ngắt kết nối đột ngột"""
        exc_type, _, _ = sys.exc_info()
        if exc_type in (BrokenPipeError, ConnectionResetError):
            return
        super().handle_error(request, client_address)


def main():
    global DEMO_MODE
    parser = argparse.ArgumentParser(description="CrowdSec Decision & Scenario Manager Web Dashboard")
    parser.add_argument("--port", "-p", type=int, default=int(os.getenv("PORT", 5000)), help="Port để web lắng nghe (mặc định: 5000)")
    parser.add_argument("--host", "-H", type=str, default=os.getenv("HOST", "0.0.0.0"), help="Host IP lắng nghe (mặc định: 0.0.0.0)")
    parser.add_argument("--demo", action="store_true", help="Chạy chế độ Demo (không gọi trực tiếp cscli)")
    args = parser.parse_args()

    host = args.host
    port = args.port
    if args.demo or os.getenv("DEMO_MODE", "0") in ["1", "true", "yes"]:
        DEMO_MODE = True

    if DEMO_MODE:
        print("[*] Đang khởi động ở CHẾ ĐỘ DEMO (Dữ liệu mẫu, không gọi cscli trực tiếp)")
    elif not is_root():
        print("=" * 65)
        print(" CẢNH BÁO: Ứng dụng hiện KHÔNG chạy bằng quyền root (UID != 0).")
        print(" Lệnh 'cscli' cần quyền root để truy cập /etc/crowdsec/config.yaml.")
        print(" Khuyến nghị chạy bằng lệnh:")
        print(f"     sudo python3 {os.path.abspath(__file__)} --port {port}")
        print(" Hoặc thêm tham số --demo để chạy thử nghiệm giao diện:")
        print(f"     python3 {os.path.abspath(__file__)} --port {port} --demo")
        print("=" * 65)

    server = ThreadedHTTPServer((host, port), CrowdSecHandler)
    print(f"[*] CrowdSec Dashboard đang chạy tại:")
    print(f"    -> Local:   http://127.0.0.1:{port}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"    -> Network: http://{local_ip}:{port}")
    except Exception:
        pass
    print(f"[*] Nhấn Ctrl+C để dừng server.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Đang tắt server...")
        server.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()
