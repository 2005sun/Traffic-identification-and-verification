#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata 告警驱动 PoCsuite 自动验证脚本（文件版）
功能：
- 实时监控 Suricata 的 eve.json 日志文件
- 解析 alert 事件，提取目标 IP、端口、URL 等信息
- 从告警中提取搜索词（优先 CVE，其次 SSVID，再次 tag/关键词）
- 调用 PoCsuite 从 Seebug 自动搜索并执行对应 Poc（verify 模式）
- 将验证结果以 JSON Lines 格式写入结果文件
- 使用文件记录已处理告警 ID，避免重复处理
"""

import json
import os
import re
import subprocess
import time
from pathlib import Path

# ==================== 配置区域 ====================
# Suricata eve.json 日志路径
EVE_JSON_PATH = "/var/log/suricata/eve.json"

# 记录已处理告警 ID 的文件（每行一个告警唯一标识）
PROCESSED_KEYS_FILE = "processed_keys.txt"

# 验证结果输出文件（JSON Lines 格式）
RESULTS_FILE = "results.jsonl"

# 记录日志文件读取位置的偏移量文件
POSITION_FILE = "/tmp/suricata_eve_position.txt"

# PoCsuite 执行模式（verify 为无损验证，attack 为攻击模式，请勿随意修改）
POCSUITE_MODE = "verify"

# 是否使用 PoCsuite 的 API 方式（True 使用 API，False 使用命令行）
USE_API = True

# PoCsuite 可执行文件路径（仅当 USE_API=False 时需要）
POCSUITE_CMD = "pocsuite"

# 验证超时时间（秒）
TIMEOUT = 60

# 扫描间隔（秒）
POLL_INTERVAL = 2

# ==================== 已处理告警管理 ====================
class ProcessedKeys:
    """管理已处理告警的 key，持久化到文件"""
    def __init__(self, filename):
        self.filename = filename
        self.keys = set()
        self._load()

    def _load(self):
        """从文件加载已存在的 key"""
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                for line in f:
                    key = line.strip()
                    if key:
                        self.keys.add(key)

    def add(self, key):
        """添加新 key 并立即追加到文件"""
        if key not in self.keys:
            self.keys.add(key)
            with open(self.filename, 'a') as f:
                f.write(key + '\n')

    def __contains__(self, key):
        return key in self.keys

# ==================== 日志读取器 ====================
class EveLogReader:
    """增量读取 eve.json 文件，支持文件轮转"""
    def __init__(self, path, pos_file):
        self.path = path
        self.pos_file = pos_file
        self.last_pos = self._load_position()
        self.file = None

    def _load_position(self):
        if os.path.exists(self.pos_file):
            with open(self.pos_file, 'r') as f:
                try:
                    return int(f.read().strip())
                except:
                    return 0
        return 0

    def _save_position(self, pos):
        with open(self.pos_file, 'w') as f:
            f.write(str(pos))

    def open(self):
        if self.file:
            self.file.close()
        self.file = open(self.path, 'r')
        self.file.seek(self.last_pos)

    def read_new_lines(self):
        """读取新增的行，返回 JSON 对象列表"""
        if not self.file:
            self.open()
        lines = []
        while True:
            pos = self.file.tell()
            line = self.file.readline()
            if not line:
                self._save_position(pos)
                break
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    lines.append(obj)
                except json.JSONDecodeError:
                    continue
        return lines

    def close(self):
        if self.file:
            self.file.close()

# ==================== 搜索词提取 ====================
def extract_search_term(alert):
    """
    从 Suricata 告警中提取最适合用于 Seebug 搜索的关键词。
    返回 (search_term, confidence) 置信度越高越好。
    """
    alert_data = alert.get('alert', {})
    metadata = alert_data.get('metadata', {})

    # 1. 优先使用 metadata 中的 CVE
    cves = metadata.get('cve', [])
    if cves:
        return cves[0], 100

    # 2. 其次使用 metadata 中的 SSVID（Seebug 自己的编号）
    ssvids = metadata.get('ssvid', [])
    if ssvids:
        return ssvids[0], 90

    # 3. 使用 metadata 中的 tag（如 SQL_Injection）
    tags = metadata.get('tag', [])
    if tags:
        return tags[0], 80

    # 4. 从 signature 中提取关键词
    signature = alert_data.get('signature', '')
    type_map = {
        'sql injection': 'SQL_Injection',
        'xss': 'XSS',
        'rce': 'RCE',
        'command injection': 'Command_Injection',
        'file include': 'File_Include',
        'upload': 'File_Upload',
        'ssrf': 'SSRF',
        'xxe': 'XXE',
    }
    sig_lower = signature.lower()
    for key, value in type_map.items():
        if key in sig_lower:
            return value, 70

    # 5. 兜底：取第一个单词
    words = re.findall(r'\b[a-zA-Z_]{3,}\b', signature)
    if words:
        return words[0], 50

    return None, 0

# ==================== 构建目标 URL ====================
def build_target_url(alert):
    """从告警中构建完整的目标 URL（用于 PoCsuite）"""
    dest_ip = alert.get('dest_ip')
    dest_port = alert.get('dest_port', 80)
    http = alert.get('http', {})
    host = http.get('hostname', dest_ip)
    url_path = http.get('url', '/')
    protocol = 'https' if dest_port in (443, 8443) else 'http'
    if ':' in host:
        url = f"{protocol}://{host}{url_path}"
    else:
        url = f"{protocol}://{host}:{dest_port}{url_path}"
    return url

# ==================== 生成告警唯一标识 ====================
def make_alert_key(alert):
    """根据告警生成唯一键，用于去重"""
    ts = alert.get('timestamp', '')
    sig_id = alert.get('alert', {}).get('signature_id', 0)
    src_ip = alert.get('src_ip', '')
    dest_ip = alert.get('dest_ip', '')
    return f"{ts}|{sig_id}|{src_ip}|{dest_ip}"

# ==================== 调用 PoCsuite（API方式）====================
def run_pocsuite_api(url, search_term, mode='verify', timeout=60):
    """使用 PoCsuite 的 Python API 执行搜索并验证。返回 (success, poc_name, detail)"""
    try:
        from pocsuite3.api import init_pocsuite, start_pocsuite
        from pocsuite3.api import get_results
    except ImportError:
        return False, None, "PoCsuite3 not installed or API not available"

    config = {
        'url': url,
        'search': search_term,
        'mode': mode,
        'plugins': ['poc_from_seebug'],
        'verbose': 0,
        'timeout': timeout,
    }
    try:
        init_pocsuite(config)
        start_pocsuite()
        results = get_results()
        if results:
            result = results[0]
            status = result.get('status', '')
            poc_name = result.get('poc', '')
            detail = result.get('result', '')
            if status == 'success':
                return True, poc_name, detail
            else:
                return False, poc_name, detail
        else:
            return False, None, "No result returned"
    except Exception as e:
        return False, None, str(e)

# ==================== 调用 PoCsuite（命令行方式）====================
def run_pocsuite_cmd(url, search_term, mode='verify', timeout=60):
    """使用命令行调用 PoCsuite，返回结果"""
    cmd = [
        POCSUITE_CMD,
        '-u', url,
        '--search', search_term,
        '--plugins', 'poc_from_seebug',
        f'--{mode}',
        '--quiet'
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout
        stderr = proc.stderr
        if '[SUCCESS]' in stdout:
            poc_match = re.search(r'Using PoC: (\S+)', stdout)
            poc_name = poc_match.group(1) if poc_match else 'unknown'
            return True, poc_name, stdout
        else:
            return False, None, stdout + stderr
    except subprocess.TimeoutExpired:
        return False, None, "Timeout"
    except Exception as e:
        return False, None, str(e)

# ==================== 写入结果文件 ====================
def write_result(alert, alert_key, search_term, poc_name, success, detail):
    """将验证结果以 JSON 格式追加到结果文件"""
    result_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'alert_key': alert_key,
        'src_ip': alert.get('src_ip'),
        'dest_ip': alert.get('dest_ip'),
        'dest_port': alert.get('dest_port'),
        'signature': alert.get('alert', {}).get('signature'),
        'signature_id': alert.get('alert', {}).get('signature_id'),
        'search_term': search_term,
        'poc_name': poc_name,
        'result': 'success' if success else 'failed',
        'detail': detail[:200] + '...' if len(detail) > 200 else detail  # 截断过长详情
    }
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result_entry) + '\n')

# ==================== 主处理循环 ====================
def main():
    # 初始化已处理 key 管理器
    processed = ProcessedKeys(PROCESSED_KEYS_FILE)

    # 初始化日志读取器
    reader = EveLogReader(EVE_JSON_PATH, POSITION_FILE)

    print(f"[*] 开始监控 {EVE_JSON_PATH}")
    print(f"[*] 已处理记录文件: {PROCESSED_KEYS_FILE}")
    print(f"[*] 结果输出文件: {RESULTS_FILE}")
    print("[*] 按 Ctrl+C 停止")

    while True:
        try:
            alerts = reader.read_new_lines()
            for alert in alerts:
                if alert.get('event_type') != 'alert':
                    continue

                alert_key = make_alert_key(alert)
                if alert_key in processed:
                    continue   # 已处理

                target_url = build_target_url(alert)
                if not target_url:
                    continue

                search_term, conf = extract_search_term(alert)
                if not search_term:
                    # 无法提取搜索词，记录但不验证
                    write_result(alert, alert_key, None, None, False, "No search term extracted")
                    processed.add(alert_key)
                    continue

                print(f"[*] 处理告警 {alert_key} 搜索词: {search_term} (置信度: {conf})")

                if USE_API:
                    success, poc_name, detail = run_pocsuite_api(target_url, search_term, POCSUITE_MODE, TIMEOUT)
                else:
                    success, poc_name, detail = run_pocsuite_cmd(target_url, search_term, POCSUITE_MODE, TIMEOUT)

                write_result(alert, alert_key, search_term, poc_name, success, detail)
                processed.add(alert_key)

                print(f"[+] 验证完成: {'成功' if success else '失败'}")

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\n[!] 用户中断")
            break
        except Exception as e:
            print(f"[-] 发生错误: {e}")
            time.sleep(POLL_INTERVAL)

    reader.close()

if __name__ == "__main__":
    main()