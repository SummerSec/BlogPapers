## CodeQL与AST之间联系

### 前言

为什么要学习Java抽象语法树呢？

在计算机科学中，抽象语法树（`abstract syntax tree` 或者缩写为 `AST`），或者语法树（`syntax tree`），是源代码的抽象语法结构的树状表现形式，这里特指编程语言的源代码。树上的每个节点都表示源代码中的一种结构。

先用一个示例来看看AST作用

```java
package com.github.javaparser;

import java.time.LocalTime;

public class TimePrinter {
    public static void main(String[] args) {
        System.out.println(LocalTime.now());
    }
}
```

![image-20211227104045005](https://cdn.jsdelivr.net/gh/SummerSec/Images//52u4052ec52u4052ec.png)

可以看到导入包

![image-20211227105053110](https://cdn.jsdelivr.net/gh/SummerSec/Images//53u5053ec53u5053ec.png)

方法声明主体



![time](https://cdn.jsdelivr.net/gh/SummerSec/Images//25u2525ec25u2525ec.png)

整个类全部信息

可以看出来用树状结构表示一个类的结构是方便的，但即使是这样子，学习AST对安全来说貌似也没啥关系。那我们再来看一个示例

```java
    class Comparator implements java.util.Comparator<PropertySource>, Serializable {
        private static final long serialVersionUID = 1L;
        @Override
        public int compare(final PropertySource o1, final PropertySource o2) {
            return Integer.compare(Objects.requireNonNull(o1).getPriority(), Objects.requireNonNull(o2).getPriority());
        }
    }
```

如果用ql形式去找上面这个类**Comparator**，那我们需要的用到**ClassOrInterface**。首先可以判断实现了Comparator和Serializable接口，那么可以用ClassOrInterface简单判断一下名字是否一致即可。

```ql
import java

class MySerializableImpl extends ClassOrInterface{
    MySerializableImpl(){
        this.getName() = "Comparator"
    }
}
predicate isMyClass(Class m){
    m.getASourceSupertype() instanceof MySerializableImpl
    and m.getASourceSupertype() instanceof TypeSerializable

}


from Class c
where isMyClass(c)
select c 
```

如果ql大部分查询是基于AST语法之上的，通过查看AST语法树的图不难发现所有的实现类都是一个类型**ClassOrInterfaceType**。

![image-20211228101944016](https://cdn.jsdelivr.net/gh/SummerSec/Images//51u1951ec51u1951ec.png)



学习AST可以更好的知道ql的规则，不至于不知道调用啥类型的去查询。并且学习AST可以大大将复杂冗杂且抽象的代码使用树状形式表现更加直观易懂的形式。学习AST适合做代码审计、代码分析、漏洞分析、安全研究等之类人群。

---

### AST--Java导出的几种格式的方法

直接新建一个maven项目，将下面三个依赖导入。

```xml
<dependencies>
    <dependency>
        <groupId>com.github.javaparser</groupId>
        <artifactId>javaparser-core</artifactId>
        <version>3.23.1</version>
    </dependency>
    <dependency>
        <groupId>com.github.javaparser</groupId>
        <artifactId>javaparser-core-serialization</artifactId>
        <version>3.23.1</version>
    </dependency>
    <dependency>
        <groupId>com.github.javaparser</groupId>
        <artifactId>javaparser-symbol-solver-core</artifactId>
        <version>3.23.1</version>
    </dependency>
</dependencies>
```

#### JSON

```java
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.serialization.JavaParserJsonSerializer;

import javax.json.Json;
import javax.json.stream.JsonGenerator;
import javax.json.stream.JsonGeneratorFactory;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import static com.github.javaparser.StaticJavaParser.parse;

public class JSONSERDEMO {
    public static void main(String[] args) {

        CompilationUnit cu = parse("class X{java.util.Y y;}");
        JavaParserJsonSerializer jsonSerializer = new JavaParserJsonSerializer();
        Map<String, ?> config = new HashMap<>();
        config.put(JsonGenerator.PRETTY_PRINTING, null);
        StringWriter  writer = new StringWriter();
        JsonGeneratorFactory generatorFactory = Json.createGeneratorFactory(config);
        JsonGenerator jsonGenerator = generatorFactory.createGenerator(writer);
        jsonSerializer.serialize(cu,jsonGenerator);
        System.out.println(writer);
        
    }
}
```

![image-20211228110649571](https://cdn.jsdelivr.net/gh/SummerSec/Images//49u649ec49u649ec.png)

#### DOT

dot可以使用转化工具转化成png图片，首先运行下面代码会生成X.dot文件。然后我们需要下载[Graphviz](http://graphviz.org/download/)，配置环境变量后到生成的X.dot文件夹下执行命令**dot X.dot -Tpng >X.png**。

```java
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.printer.DotPrinter;

import java.io.FileWriter;
import java.io.PrintWriter;

import static com.github.javaparser.StaticJavaParser.parse;


public class DotSerDemo {
    public static void main(String[] args) {
        CompilationUnit cu = parse("class X{java.util.Y y;}");
        DotPrinter dotPrinter =  new DotPrinter(true);
        dotPrinter.output(cu);
        try {
            FileWriter fileWriter = new FileWriter("X.dot");
            PrintWriter printWriter = new PrintWriter(fileWriter, true);
            printWriter.println(dotPrinter.output(cu));

        }catch (Exception e){

        }
    }
}
```

![image-20211228111241967](https://cdn.jsdelivr.net/gh/SummerSec/Images//42u1242ec42u1242ec.png)

#### YAML

```java
import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.printer.YamlPrinter;
import static com.github.javaparser.StaticJavaParser.parse;

public class YamlSerDEMO {
    public static void main(String[] args) {
        CompilationUnit cu = parse("class X{java.util.Y y;}");
        YamlPrinter yamlPrinter = new YamlPrinter(true);
        System.out.println(yamlPrinter.output(cu));
    }
}

```



![image-20211228111647854](https://cdn.jsdelivr.net/gh/SummerSec/Images//48u1648ec48u1648ec.png)

#### XML

```java
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.printer.XmlPrinter;
import static com.github.javaparser.StaticJavaParser.parse;

public class XmlSerDemo {
    public static void main(String[] args) {
        CompilationUnit cu = parse("class X{java.util.Y y;}");
        XmlPrinter printer = new XmlPrinter(true);
        System.out.println(printer.output(cu));
    }
}

```

![image-20211228111817441](https://cdn.jsdelivr.net/gh/SummerSec/Images//17u1817ec17u1817ec.png)



---

### AST 语法树分析

前面我们对下面一段源码生成AST语法树图，下面分析一下AST语法树有那些内容。

    package com.sumsec.sources.UserDemo;
    
    import java.time.LocalTime;
    
    public class TimePrinter {
        public static void main(String[] args) {
            System.out.println(LocalTime.now());
        }
    }

首先是有一个根节点，根节点下面有三个叶子节点，分别是**packageDeclaration**、**imports**、**types**。

![image-20211228143811027](https://cdn.jsdelivr.net/gh/SummerSec/Images//11u3811ec11u3811ec.png)



#### packageDeclaration

**packageDeclaration**是对应着TimePrinter的包名称，对应ql规则中谓词的hasQualifiedName或者是getQualifiedName

![image-20211228144236650](https://cdn.jsdelivr.net/gh/SummerSec/Images//36u4236ec36u4236ec.png)

举例说明

```ql
import java

from Class c
select c.getQualifiedName()
```

![image-20211228145616981](https://cdn.jsdelivr.net/gh/SummerSec/Images//17u5617ec17u5617ec.png)

---



#### imports

**imports**是对应着导入的包名，示例中导入的包名java.time.LocalTime。对应ql文件中的ImportType模块。



![image-20211228145720020](https://cdn.jsdelivr.net/gh/SummerSec/Images//21u5721ec21u5721ec.png)

举例查看哪里导入**org.apache.commons.lang3.compare**下的任意类，编写ql规则就能很快找到。

```ql
import java

from ImportType i, Class c
where c.getPackage().getName() = "org.apache.commons.lang3.compare"
and i.getImportedType() = c
select i
```

![image-20211228152327119](https://cdn.jsdelivr.net/gh/SummerSec/Images//27u2327ec27u2327ec.png)

![image-20211228152318395](https://cdn.jsdelivr.net/gh/SummerSec/Images//18u2318ec18u2318ec.png)



---

#### Type

![image-20211228152811903](https://cdn.jsdelivr.net/gh/SummerSec/Images//12u2812ec12u2812ec.png)

Type是一个大的模块，除了packageDeclaration和import模块其他所有的内容都属于Types。换一句话说，除了包名和导入的包其他所有的都是属于Type，像Javadoc、method、类名、字段等等。。。

Type模块也是ql重点模块，首先可以type下面的节点是类型是**ClassOrInterface**，对应是类或者接口主体**class f{}**。

AST的ClassOrInterface是有判断是否是接口，但在ql模块里是没有这个谓词的，将接口和类统一归为Class模块。









---

### 总结

学习AST语法树可以更好程度上了解ql的规则编写与ql开发者对应的编写规则的依据来源，不然有时候确实是有些地方可以无从下手。

虽然ql的语法远不止这些，但学习AST语法树能够让我们从根本上理解为什么ql的规则是这么编写。之前笔者在这块就走了不少弯路，大多数代码审计工具其实多多少少会涉及到AST的知识，另外程序分析里面也有涉及了AST知识。总的来说AST对于有代码分析的需求的研究人员应该是必须的学习之路。

DOT格式导出之后转化成图片，比较直观更加方便、容易获取关键信息。

---

### Update 

为了更好的分析AST和CFG，本人写了一款工具。工具官方网站[静态程序分析工具 主要生成方法的CFG和.java文件的AST](https://spat.sumsec.me/)，使用教程也在网站的。是一款开源工具，欢迎大家使用，提交issue和pr。



---



### 参考



https://houbb.github.io/2020/05/29/java-ast-04-javaparser-ast

https://javaparser.org/inspecting-an-ast/

https://github.com/javaparser/javaparser/blob/master/javaparser-core-serialization/src/test/java/com/github/javaparser/serialization/JavaParserJsonSerializerTest.java