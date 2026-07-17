---
layout: default
title: "从翻邮箱发现钓鱼站到钓鱼系统通杀注入"
tags:
- blog-comments
- 翻译
---

# 从翻邮箱发现钓鱼站到钓鱼系统通杀注入

@[TOC]

# 前言

故事纯属虚构！请不要相信我瞎白话。

![Q6ojsS.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6ojsS.jpg)

主要事情：日钓鱼网站

主要人物：

- 丞相

  - 丞相大表哥有传言我丞相表哥是个富二代，高富帅，简直是黑阔界的担当。U1S1 丞相表哥是挺帅，有没有钱我就不知道了。
- 05

  - 05是一个传说中的黑阔，相传黑阔界年龄最小的表哥。
- 我本人

  - 相对前两位表哥，我简直就是个弟弟存在。

---

# 故事起源

群里有小哥哥发了一个截图，这明眼人一看就是钓鱼网站呀！

![Q6TFzV.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6TFzV.png)  
![Q67jEQ.md.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q67jEQ.md.png)  
![](https://imgse.com/i/Q6HEE4)  
![Q6H1bD.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6H1bD.png)  
![Q6H8Ve.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6H8Ve.png)  
![Q6HQKK.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6HQKK.png)

---

# 故事开始

上述步骤是之前丞相和05表哥们在群里聊天记录，当天晚上奈何我在看追韩剧电视剧《辅助官2》。

![Q6beeS.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6beeS.jpg)

嗯哼，澄清一下大家别以为是那种女生爱看的韩剧，情情爱爱的，我这里看的烧脑剧丫丫！！！（有点扯远了，大家关心不是我追剧事情，请忽略掉这段。）

---

当我第二天睡醒，然后看见群里聊天记录的时候。我当时居然一笔带过的撩了一眼，摸不在意的忽略掉了。现在想想。。。。。。

![Q6H22q.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6H22q.png)

观众：我靠，你这个作者戏真多，说了这么多，正菜还没上*￥\*\*@*-/-/@#232

![Q6HgGn.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6HgGn.jpg)

各位看好了下面就是表演时刻！

---

看这个网站，看看只有这个登录框能测，其他都功能点都会跳转到腾讯的正品网站上。

![在这里插入图片描述](https://i.loli.net/2019/12/12/7IuPWi1sHCLgcAj.png)

啧啧，居然禁止访问，但是你为啥你不直接banIP？sqlmap还在跑你，小破站都不用脑子想想？

![15.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/mnZs8Tqfxdt1NuO.png)

![05.gif](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/b8Z7Soqi34KR5Lp.gif)

---

# 故事高潮

开始对User-Agent尝试注入，一顿乱七八糟的操作之后发现没过。

![24.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/k1sj9afIwVhTezq.png)

![011.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/6sUfZtz4C9NDaFJ.jpg)

尝试`X-Forwarded-For` 注入，

在请求头里面加一行`X-Forwarded-For:*` 并构造

`X-Forwarded-For:'AND(SELECT 05 FROM (SELECT(5)))sqlpayload) -- +`

[![Q6O3QI.md.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6O3QI.md.png)](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/Q6O3QI.md.png)

然后就使用sqlmap跑就行了，`sqlmap.py -r 1.txt --level 4 -v 4 --batch`

![27.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/M2xfwSDLVC9ZONr.png)

随便一提kali最新版是真的香，为何这么说呢！？直接上图

![18.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/mRJZlWSNLHYACr8.png)

接下去就是常规操作，大佬们也都懂，查看数据库，表，字段最终获取账号密码。

![13.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/3tA9W7eopsNnQ4R.png)

数据量有点吓人，我靠居然有这么多傻子！

![06.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/yhumqxi369BeOvE.jpg)  
![在这里插入图片描述](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/OUFGDxy3RvsXLeI.png)

后台登录框存在POST注入 ，且用户名处 ‘ 报路径配合DBA可以getshell。  
PS: 可惜 站点都不是DBA。

![image.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/LY5aMzDf7ZuWbVv.png)

![T5QB\_`R\_\_NV\_9UEWDYZ~WSH.png](<https://i.loli.net/2019/12/12/Z3QzBTtKqYfRpGs.png>)

---

# 意外剧情

![07.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/PcXoCTv3mNpRGKM.png)

你不会真的以为故事就这么简单的结束了吧？  
![](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/h3ZLBq9XJjwHTIN.jpg)

在注入成功之后，另一个激情满满的群友，发来另一种图。是另一个使用相同模板的站点，经过测试发现这个漏洞是通杀。

![26.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/LP8ZQkOEo4zmIbF.png)

---

# 番外篇

意外的是我今天看了一眼土司论坛，发现一篇文章[文章链接](https://www.t00ls.net/viewthread.php?tid=54187&extra=&page=1)也是日钓鱼网站的，打开一看页面完全一样呀。  
![09.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/mtBKsHrQ9xzCgXp.jpg)  
我看完之后，我又发现新的操作。

主要大概意思如下：

1. 找到后台地址，注入登录框。
2. 使用长注释绕过云锁waf。

![28.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/jEBOnMgyulp2Ttk.png)

---

# 测试中小技巧

使用分块传输解码插件。  
![16.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/vT87oa2VPhnYHQM.png)

使用sqlmap插件

![22.png](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/hUy4W7bdQBMiulJ.png)

![07.jpg](./pic/从翻邮箱发现钓鱼站到钓鱼系统通杀注入-1/PcXoCTv3mNpRGKM.png)
