---
layout: post
title: "Sqlmap源码分析（一）"
date: 2018-04-04
description: "Sqlmap源码分析之目录结构"
tag: WEB安全
---
## 前言
sqlmap这款sql注入神器想必不用过多介绍，互联网安全从业者大多都有了解。最近在使用sqlmap作为 web漏洞扫描系统的sql注入扫描模块时碰到了几次误报问题，于是决定看下源码。首先看下sqlmap的目录结构，了解它的工程结构。还未深入源码，后续会不断优化此文章，对各目录甚至文件作出它的功能判断。
## 目录结构详解
```
sqlmap
|	README.md 说明文件
|	.travis.yml 标记python版本及设置sqlmap的脚本
|	sqlmap.conf 配置文件
|	sqlmap.py 的主程序
|	sqlmapapi.py api文件，可以将sqlmap集成到其他平台
|
└───doc 使用说明文档
|
└───extra 额外功能
|	|
|	└───beep 警报声音
|	└───cloak webshell加密
|	└───dbgtool ASCII文本转化到便携式的exe文件
|	└───icmpsh win32 icmp反弹shell
|	└───mssqlsig 更新mssql xml文件
|	└───runcmd cmd命令辅助工具
|	└───safe2bin 文本文件转化到bin文件
|	└───shellcodeexec 可安装在目标机上的shellcode
|	└───shutils python的文件操作工具
|	└───sqlharvest 利用google进行搜索爬取文件
|
└───lib 核心库，涉及到探测注入等等
|	└───controller 检测储备
|	└───core 参数调用
|	└───parse 页面参数payload等解析工作
|	└───request 请求处理
|	└───takeover 接管目标机器
|	└───techniques 注入技巧
|	└───utils 辅助功能，爆破爬虫等
|
└───plugins 插件库
|	└───dbms 各类型数据库的连接，枚举，接管等功能
|	└───generic 通用的连接，枚举等功能
|	
└───procs 各数据库进一步利用
|	└───mssqlserver
|	└───mysql
|	└───oracle
|	└───postgresql
|
└───shell 加密后门
|	└───backdoors
|	└───stagers
|
└───tamper 绕过防火墙的脚本
|
└───thirdparty 第三方库
|	└───beautifulsoup
|	└───fcrypt
|	└───socks
|	└───...
|
└───txt 字典
|	
└───udf udf提权
|	└───mysql
|	└───postgresql
|
└───waf 识别个类型waf
|
└───xml 指纹和payload记录
	└───banner 各数据库指纹识别
	└───payloads 六种类型的注入payload

```
## 参考
https://blog.csdn.net/qq_29277155/article/details/51646932  
https://blog.donot.me/sqlmap-1/