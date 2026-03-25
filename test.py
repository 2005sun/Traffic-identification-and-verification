import json
import subprocess


class Console:
    # 解析告警信息,提取出url和漏洞类型
    def parse_alert_message(self, alert_message):
        data = json.loads(alert_message)
        ip = data['dest_ip']
        port = data['dest_port']
        path = data['http']['url']
        url = f'http://{ip}:{port}{path}'
        vul_name = data['alert']['signature']
        return url, vul_name

    # 调用pocsuite验证poc是否存在
    def poc_verify(self,url,vul_name):
        poc_file = f'./pocs/{vul_name}.py'
        cookie = "PHPSESSID=emv65tvumg737i6nv669ftmjs6; security=low"
        cmd = ["pocsuite", "-r", str(poc_file), "-u", url, "--verify", "--cookie", cookie]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result


message = '{"timestamp":"2014-12-22T16:19:41.368129+0800","flow_id":1559158446813734,"pcap_cnt":58,"event_type":"alert","src_ip":"10.0.2.15","src_port":1025,"dest_ip":"127.0.0.1","dest_port":80,"proto":"TCP","ip_v":4,"pkt_src":"wire/pcap","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"sql_injection","category":"","severity":3},"ts_progress":"request_complete","tc_progress":"response_complete","http":{"hostname":"127.0.0.1","url":"/vulnerabilities/sqli/?id=1%27+or++1%3D1%23&Submit=Submit#","http_user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:33.0) Gecko/20100101 Firefox/33.0","http_content_type":"text/html","http_method":"GET","protocol":"HTTP/1.1","status":200,"length":780},"app_proto":"http","direction":"to_server","flow":{"pkts_toserver":4,"pkts_toclient":4,"bytes_toserver":617,"bytes_toclient":1207,"start":"2014-12-22T16:19:41.363019+0800","src_ip":"10.0.2.15","dest_ip":"172.16.80.11","src_port":1025,"dest_port":80}}'
test = Console()
url,vul_name = test.parse_alert_message(message)
print(url,vul_name,sep='\n')
result = test.poc_verify(url,vul_name)
print(result)