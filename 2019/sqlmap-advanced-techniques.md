---
layout: default
title: "【实战技巧】sqlmap不为人知的骚操作"
tags:
- blog-comments
---

# 【实战技巧】sqlmap不为人知的骚操作

前言

如果有不知道这个漏洞，可以先看看下面的文章  
<https://xz.aliyun.com/t/6531>

0x01 注入前知识补充

sqlmap参数：–prefix,–suffix  
在有些环境中，需要在注入的payload的前面或者后面加一些字符，来保证payload的正常执行。  
例如，代码中是这样调用数据库的：  
$query = “SELECT \* FROM users WHERE id…

作者：sun1318578251 发表于 2019/10/22 18:57:58 [原文链接](https://blog.csdn.net/sun1318578251/article/details/102524100) <https://blog.csdn.net/sun1318578251/article/details/102524100>

  

阅读：3161 评论：3 [查看评论](https://blog.csdn.net/sun1318578251/article/details/102524100#comments)
