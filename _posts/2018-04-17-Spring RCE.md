---
layout: post
title: "Spring 远程命令执行漏洞"
date: 2018-03-22
description: "Spring 远程命令执行漏洞"
tag: 应用安全
---

------
## 前言
近期Spring框架爆出多个远程命令执行漏洞，包括CVE-2018-1270&CVE-2018-1275（同一漏洞）和CVE-2018-1273，因漏洞特征难以使用统一手段检测，需要相关业务负责人根据使用漏洞版本jar包情况（可参考漏洞场景示例）自行判断是否存在漏洞。可使用[漏洞示例代码](/images/extra/Spring_rce_demo.zip)搭建环境，漏洞详情如下
## CVE-2018-1270&CVE-2018-1275  
### 漏洞危害
远程命令执行漏洞，允许恶意用户远程执行恶意代码
### 漏洞影响版本
spring框架5.0-5.0.4，4.3-4.3.15
### 漏洞触发条件
spring-messaging + websocket + STOM
### 漏洞场景示例
* 使用漏洞影响版本jar包
![](/images/posts/app_sec/spring_messging_vuln_jar.png)
* 后端配置websocket，注册STOMP协议，同时指定使用SockJs协议
![](/images/posts/app_sec/spring_messging_websocket.png)
* 前端js使用STOMP创建websocket客户端
![](/images/posts/app_sec/spring_messging_js.png)
* 修改前端js，添加header执行selector以达到spel表达式执行
![](/images/posts/app_sec/spring_messging_modefy_js.png)
* 漏洞证明
![](/images/posts/app_sec/spring_messging_verify.png)
### 修复方案
```
5.0.x版本用户升级至5.0.5
4.3.x版本用户升级至4.3.16
```

## CVE-2018-1273
### 漏洞危害
远程命令执行漏洞，允许恶意用户远程执行恶意代码
### 漏洞影响版本
Spring Data Commons 1.13 - 1.13.10 (Ingalls SR10)  
Spring Data REST 2.6 - 2.6.10 (Ingalls SR10)  
Spring Data Commons 2.0 to 2.0.5 (Kay SR5)  
Spring Data REST 3.0 - 3.0.5 (Kay SR5)  
更早的版本也会受到影响  
### 漏洞触发条件
1. 使用Spring Data Rest项目（包含漏洞影响版本）
2. 前端使用表单提交数据
3. 后端使用投射接口获取对象数据

### 漏洞场景示例
1. 使用漏洞版本jar包  
![](/images/posts/app_sec/spring_data_vuln_jar1.png)
![](/images/posts/app_sec/spring_data_vuln_jar2.png)
2. 前端用户可提交数据
![](/images/posts/app_sec/spring_data_form.png)
3. 后端使用投射接口获取数据
![](/images/posts/app_sec/spring_data_interface.png)
4. 漏洞复现，拦截请求，修改username，执行spel表达式
![](/images/posts/app_sec/spring_data_verify.png)

### 漏洞修复
升级代码框架  
**Spring Data Commons**  
2.0.x的用户升级到2.0.6  
1.13.x的用户升级到1.13.11  
**Spring Data REST**  
2.x用户升级到2.6.11  
3.x用户升级到3.0.6  
**Spring Boot**  
1.5.x用户升级到1.5.11  
2.x用户升级到2.0.1  
## 参考链接
[https://github.com/CaledoniaProject/CVE-2018-1270/](https://github.com/CaledoniaProject/CVE-2018-1270/)  
[http://blog.nsfocus.net/spring-messaging-analysis/](http://blog.nsfocus.net/spring-messaging-analysis/)  
[http://www.icnws.com/2017/spring-data-jpa-Projection/](http://www.icnws.com/2017/spring-data-jpa-Projection/)  
[https://blog.csdn.net/u012702547/article/details/53816326](https://blog.csdn.net/u012702547/article/details/53816326)