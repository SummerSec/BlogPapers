# CodeQL workshop for Java: Unsafe deserialization in Apache Struts

 - Analyzed language: Java
 - Difficulty level: 200

## Overview

 - [Problem statement](#problemstatement) 问题描述
 - [Setup instructions](#setupinstructions) 安装说明
 - [Documentation links](#documentationlinks) 文件链接
 - [Workshop](#workshop)
   - [Section 1: Finding XML deserialization](#section1)
   - [Section 2: Find the implementations of the `toObject` method from ContentTypeHandler](#section2)
   - [Section 3: Unsafe XML deserialization](#section3)

## Problem statement <a id="problemstatement"></a>

_Serialization_ is the process of converting in memory objects to text or binary output formats, usually for the purpose of sharing or saving program state. This serialized data can then be loaded back into memory at a future point through the process of _deserialization_.

> 序列化_是将内存中的对象转换为文本或二进制输出格式的过程，通常是为了共享或保存程序状态。这种序列化的数据可以在未来的某一时刻通过_解序列化_过程加载回内存。

In languages such as Java, Python and Ruby, deserialization provides the ability to restore not only primitive data, but also complex types such as library and user defined classes. This provides great power and flexibility, but introduces a signficant attack vector if the deserialization happens on untrusted user data without restriction.

> 在Java、Python和Ruby等语言中，反序列化不仅提供了还原原始数据的能力，还提供了还原库和用户定义类等复杂类型的能力。这提供了强大的功能和灵活性，但如果反序列化发生在无限制的不受信任的用户数据上，则引入了一个重要的攻击向量。

[Apache Struts](https://struts.apache.org/) is a popular open-source MVC framework for creating web applications in Java. In 2017, a researcher from the predecessor of the [GitHub Security Lab](https://securitylab.github.com/) found [CVE-2017-9805](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9805), an XML deserialization vulnerability in Apache Struts that would allow remote code execution.

> [Apache Struts](https://struts.apache.org/)是一个流行的开源MVC框架，用于用Java创建Web应用。2017年，[GitHub安全实验室](https://securitylab.github.com/)前身的研究人员发现[CVE-2017-9805](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9805)，Apache Struts中存在一个XML反序列化漏洞，将允许远程代码执行。

The problem occurred because included as part of the Apache Struts framework is the ability to accept requests in multiple different formats, or _content types_. It provides a pluggable system for supporting these content types through the [`ContentTypeHandler`](https://struts.apache.org/maven/struts2-plugins/struts2-rest-plugin/apidocs/org/apache/struts2/rest/handler/ContentTypeHandler.html) interface, which provides the following interface method:

> 问题发生的原因是，作为Apache Struts框架的一部分，包含了接受多种不同格式或_内容类型_的请求的能力。它通过[`ContentTypeHandler`](https://struts.apache.org/maven/struts2-plugins/struts2-rest-plugin/apidocs/org/apache/struts2/rest/handler/ContentTypeHandler.html)接口提供了一个可插拔的系统来支持这些内容类型，它提供了以下接口方法:

```java
    /**
     * Populates an object using data from the input stream
     * @param in The input stream, usually the body of the request
     * @param target The target, usually the action class
     * @throws IOException If unable to write to the output stream
     */
    void toObject(Reader in, Object target) throws IOException;
```

New content type handlers are defined by implementing the interface and defining a `toObject` method which takes data in the specified content type (in the form of a `Reader`) and uses it to populate the Java object `target`, often via a deserialization routine. However, the `in` parameter is typically populated from the body of a request without sanitization or safety checks. This means it should be treated as "untrusted" user data, and only deserialized under certain safe conditions.

> 新的内容类型处理程序是通过实现接口和定义 "toObject "方法来定义的，该方法接受指定内容类型的数据（以 "Reader "的形式），并使用它来填充Java对象 "target"，通常是通过反序列化例程。然而，"in "参数通常是从请求的主体中填充的，没有经过净化或安全检查。这意味着它应该被视为 "不受信任 "的用户数据，只有在某些安全条件下才会被反序列化。

In this workshop, we will write a query to find CVE-2017-9805 in a database built from the known vulnerable version of Apache Struts.

> 在本工作坊中，我们将编写一个查询，在一个由已知的Apache Struts脆弱版本构建的数据库中找到CVE-2017-9805。

## Setup instructions for Visual Studio Code <a id="setupinstructions"></a>

To take part in the workshop you will need to follow these steps to get the CodeQL development environment setup:

> 要参加研讨会，你需要按照以下步骤来设置CodeQL开发环境。

1. Install the Visual Studio Code IDE.  安装Visual Studio Code IDE。
2. Download and install the [CodeQL extension for Visual Studio Code](https://help.semmle.com/codeql/codeql-for-vscode.html). Full setup instructions are [here](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html). 下载并安装[Visual Studio Code的CodeQL扩展](https://help.semmle.com/codeql/codeql-for-vscode.html)。完整的安装说明在[这里](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html)
3. [Set up the starter workspace](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html#using-the-starter-workspace).
    - ****Important****: Don't forget to `git clone --recursive` or `git submodule update --init --remote`, so that you obtain the standard query libraries.
4. Open the starter workspace: File > Open Workspace > Browse to `vscode-codeql-starter/vscode-codeql-starter.code-workspace`.
5. Download and unzip the [apache_struts_cve_2017_9805.zip database](https://github.com/githubsatelliteworkshops/codeql/releases/download/v1.0/apache_struts_cve_2017_9805.zip).
6. Choose this database in CodeQL (using `Ctrl + Shift + P` to open the command palette, then selecting "CodeQL: Choose Database").
7. Create a new file in the `codeql-custom-queries-java` directory called `UnsafeDeserialization.ql`.

## Documentation links <a id="documentationlinks"></a>
If you get stuck, try searching our documentation and blog posts for help and ideas. Below are a few links to help you get started:

> 如果你被卡住了，请尝试搜索我们的文档和博客文章以获得帮助和想法。以下是一些帮助你入门的链接:

- [Learning CodeQL](https://help.semmle.com/QL/learn-ql)
- [Learning CodeQL for Java](https://help.semmle.com/QL/learn-ql/cpp/ql-for-java.html)
- [Using the CodeQL extension for VS Code](https://help.semmle.com/codeql/codeql-for-vscode.html)

## Workshop <a id="workshop"></a>

The workshop is split into several steps. You can write one query per step, or work with a single query that you refine at each step. Each step has a **hint** that describes useful classes and predicates in the CodeQL standard libraries for Java. You can explore these in your IDE using the autocomplete suggestions (`Ctrl + Space`) and the jump-to-definition command (`F12`).

> 该研讨会分为几个步骤。你可以在每个步骤中编写一个查询，或者在每个步骤中完善一个查询。每个步骤都有一个**提示**，描述了Java的CodeQL标准库中有用的类和谓词。你可以在IDE中使用自动完成建议(`Ctrl + Space`)和跳转到定义命令(`F12`)来探索这些。

### Section 1: Finding XML deserialization <a id="section1"></a>

[XStream](https://x-stream.github.io/index.html) is a Java framework for serializing Java objects to XML used by Apache Struts. It provides a method `XStream.fromXML` for deserializing XML to a Java object. By default, the input is not validated in any way, and is vulnerable to remote code execution exploits. In this section, we will identify calls to `fromXML` in the codebase.

> [XStream](https://x-stream.github.io/index.html)是一个Java框架，用于将Java对象序列化为Apache Struts使用的XML。它提供了一个方法`XStream.fromXML`，用于将XML反序列化为一个Java对象。默认情况下，输入的内容不会以任何方式进行验证，并且容易受到远程代码执行的攻击。在本节中，我们将识别代码库中对`fromXML`的调用。

 1. Find all method calls in the program. 
    
    >  1. 查找程序中的所有方法调用。

    <details>
    <summary>Hint</summary>
    
    - A method call is represented by the `MethodAccess` type in the CodeQL Java library.
    
    > 在CodeQL Java库中，方法调用由`MethodAccess`类型表示。
    
    </details>

    <details>
    <summary>Solution</summary>
    
    ```ql
    import java
    
    from MethodAccess call
    select call
    ```
    
    
    ![image-20210329212430433](https://img.sumsec.me/51u24er51ec/51u24er51ec.png)
    
    ![image-20210329212439289](https://img.sumsec.me/29u40er29ec/29u40er29ec.png)
    
    
    
    </details>
    
    
    
    
    
 1. Update your query to report the method being called by each method call.
    
    > 更新你的查询，报告每个方法调用的方法。

    <details>
    <summary>Hints</summary>
    
    - Add a CodeQL variable called `method` with type `Method`.
    >   添加一个名为 "method "的CodeQL变量，类型为 "Method"。
    - `MethodAccess` has a predicate called `getMethod()` for returning the method.
    > `MethodAccess`有一个叫做`getMethod()`的谓词用于返回方法。
    - Add a `where` clause.
    >  添加一个`where`子句。
    
    </details>
    
    <details>
    <summary>Solution</summary>
    
    ```
    import java
    from MethodAccess call, Method method
    where call.getMethod() = method
    select call, method
    ```
    
    ![image-20210329212627120](https://img.sumsec.me/27u26er27ec/27u26er27ec.png)
    ![image-20210329212644844](https://img.sumsec.me/44u26er44ec/44u26er44ec.png)
    
    </details>
    
    
    ​    

 1. Find all calls in the program to methods called `fromXML`.<a id="question1"></a>

    >  找出程式中所有调用`fromXML`的方法。

    <details>
    <summary>Hint</summary>

    - `Method.getName()` returns a string representing the name of the method.

        > `Method.getName()`返回一个代表方法名称的字符串。

    </details>
    
    <details>
    <summary>Solution</summary>

    ```ql
    import java
    
    from MethodAccess fromXML, Method method
    where
        fromXML.getMethod() = method and
        method.getName() = "fromXML"
    select fromXML
    ```

    ![image-20210329212821422](https://img.sumsec.me/21u28er21ec/21u28er21ec.png)
    
    ![image-20210329212833431](https://img.sumsec.me/33u28er33ec/33u28er33ec.png)
    
    However, as we now want to report only the call itself, we can inline the temporary `method` variable like so:
    
    >  然而，由于我们现在只想报告调用本身，我们可以像这样内联临时`method`变量。
    
    ```ql
    import java
    
    from MethodAccess fromXML
    where fromXML.getMethod().getName() = "fromXML"
    select fromXML
    ```
    </details>

 1. The `XStream.fromXML` method deserializes the first argument (i.e. the argument at index `0`). Update your query to report the deserialized argument.

    > `XStream.fromXML`方法反序列化第一个参数（即索引`0`的参数）。更新你的查询以报告反序列化的参数。

    <details>
    <summary>Hint</summary>

    - `MethodCall.getArgument(int i)` returns the argument at the i-th index.

        > `MethodCall.getArgument(int i)`返回第i个索引的参数。

    - The arguments are _expressions_ in the program, represented by the CodeQL class `Expr`. Introduce a new variable to hold the argument expression.

        > 参数是程序中的_表达式，由CodeQL类`Expr`表示。引入一个新的变量来存放参数表达式。

    </details>
    <details>
    <summary>Solution</summary>

    ```ql
    import java
    
    from MethodAccess fromXML, Expr arg
    where
      fromXML.getMethod().getName() = "fromXML" and
      arg = fromXML.getArgument(0)
    select fromXML, arg
    ```
    ![image-20210329213437656](https://img.sumsec.me/37u34er37ec/37u34er37ec.png)

    ![image-20210329213507450](https://img.sumsec.me/7u35er7ec/7u35er7ec.png)

    ![image-20210329213522528](https://img.sumsec.me/22u35er22ec/22u35er22ec.png)
    
    
    
    </details>

   

 1. Recall that _predicates_ allow you to encapsulate logical conditions in a reusable format. Convert your previous query to a predicate which identifies the set of expressions in the program which are deserialized directly by `fromXML`. You can use the following template:
    
    > 回顾一下，_predicate_允许你以可重复使用的格式封装逻辑条件。将你之前的查询转换为一个谓词，该谓词标识了程序中直接由`fromXML`反序列化的表达式集。你可以使用下面的模板:
    
    ```ql
    predicate isXMLDeserialized(Expr arg) {
      exists(MethodAccess fromXML |
        // TODO fill me in
      )
    }
    ```
    [`exists`](https://help.semmle.com/QL/ql-handbook/formulas.html#exists) is a mechanism for introducing temporary variables with a restricted scope. You can think of them as their own `from`-`where`-`select`. In this case, we use it to introduce the `fromXML` temporary variable, with type `MethodAccess`.

    > [`exists`](https://help.semmle.com/QL/ql-handbook/formulas.html#exists)是一种引入范围有限的临时变量的机制。你可以把它们看作是自己的`from`-`where`-`select`。在本例中，我们使用它来引入类型为 "MethodAccess "的 "fromXML "临时变量。
    
    <details>
    <summary>Hint</summary>

    - Copy the `where` clause of the previous query
	>  复制上一个查询的 "where "子

	</details>
	
	<details>
    <summary>Solution</summary>
    
    ````
    import java
    
    predicate isXMLDeserialized(Expr arg) {
        exists(MethodAccess fromXML |
            fromXML.getMethod().getName() = "fromXML" and
            arg = fromXML.getArgument(0)
        )
    }
    
    from Expr ar
    where isXMLDeserialized(arg)
    select arg
    ````
    ![image-20210329213914825](https://img.sumsec.me/14u39er14ec/14u39er14ec.png)
    
    ![image-20210329213924749](https://img.sumsec.me/24u39er24ec/24u39er24ec.png)
    
    ![image-20210329213933795](https://img.sumsec.me/33u39er33ec/33u39er33ec.png)
    
    
    
    </details>


### Section 2: Find the implementations of the toObject method from ContentTypeHandler <a id="section2"></a>

Like predicates, _classes_ in CodeQL can be used to encapsulate reusable portions of logic. Classes represent single sets of values, and they can also include operations (known as _member predicates_) specific to that set of values. You have already seen numerous instances of CodeQL classes (`MethodAccess`, `Method` etc.) and associated member predicates (`MethodAccess.getMethod()`, `Method.getName()`, etc.).

> 像谓词一样，CodeQL中的_类_可以用来封装逻辑的可重用部分。类代表单一的值集，它们也可以包含特定于该值集的操作（称为_成员谓词_）。你已经看到了许多CodeQL类的实例（`MethodAccess`、`Method`等）和相关的成员谓词（`MethodAccess.getMethod()`、`Method.getName()`等）。

 1. Create a CodeQL class called `ContentTypeHandler` to find the interface `org.apache.struts2.rest.handler.ContentTypeHandler`. You can use this template:
    
    > 创建一个名为`ContentTypeHandler`的CodeQL类，找到接口`org.apache.struts2.rest.handler.ContentTypeHandler`。可以使用这个模板。
    
    ```ql
    class ContentTypeHandler extends RefType {
      ContentTypeHandler() {
          // TODO Fill me in
    }
    }
    ```

    <details>
    <summary>Hint</summary>
    
    - Use `RefType.hasQualifiedName(string packageName, string className)` to identify classes with the given package name and class name. For example:
      
        > 使用`RefType.hasQualifiedName(string packageName, string className)`来识别具有给定包名和类名的类:
        
    ```ql
    from RefType r
    where r.hasQualifiedName("java.lang", "String")
    select r
    ```
    
    - Within the characteristic predicate you can use the magic variable `this` to refer to the RefType

        > 在特性谓词中，你可以使用神奇的变量`this`来引用RefType。
    
    </details>
    <details>
    <summary>Solution</summary>
    
    ```ql
    import java
    
    /** The interface `org.apache.struts2.rest.handler.ContentTypeHandler`. */
    class ContentTypeHandler extends RefType {
      ContentTypeHandler() {
        this.hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler")
      }
    }
    ```
    </details>
    
 2. Create a CodeQL class called `ContentTypeHandlerToObject` for identfying `Method`s called `toObject` on classes whose direct super-types include `ContentTypeHandler`.

    > 创建一个名为 "ContentTypeHandlerToObject "的CodeQL类，用于识别直接超类型包括 "ContentTypeHandler "的类上调用 "toObject "的 "Method"。

    <details>
    <summary>Hint</summary>

    - Use `Method.getName()` to identify the name of the method.

        >  使用`Method.getName()`来识别方法的名称。

    - To identify whether the method is declared on a class whose direct super-type includes `ContentTypeHandler`, you will need to:
      
      > 要识别该方法是否在直接超级类型包括`ContentTypeHandler`的类上声明，你需要:
      
      - Identify the declaring type of the method using `Method.getDeclaringType()`.
      
          > 使用`Method.getDeclaringType()`识别方法的声明类型。
      
      - Identify the super-types of that type using `RefType.getASuperType()`
      
          > 使用`RefType.getASuperType()`识别该类型的超级类型。
      
      - Use `instanceof` to assert that one of the super-types is a `ContentTypeHandler`
      
          > 使用 "instanceof "断言其中一个超级类型是 "ContentTypeHandler"。

    </details>
    <details>
    <summary>Solution</summary>

    ```ql
    /** A `toObject` method on a subtype of `org.apache.struts2.rest.handler.ContentTypeHandler`. */
    class ContentTypeHandlerToObject extends Method {
      ContentTypeHandlerToObject() {
        this.getDeclaringType().getASupertype() instanceof ContentTypeHandler and
        this.hasName("toObject")
      }
    }
    ```
    </details>

 3. `toObject` methods should consider the first parameter as untrusted user input. Write a query to find the first (i.e. index 0) parameter for `toObject` methods.

    > `toObject`方法应将第一个参数视为不受信任的用户输入。写一个查询来查找`toObject`方法的第一个（即索引0）参数。

    <details>
    <summary>Hint</summary>

    - Use `Method.getParameter(int index)` to get the i-th index parameter.

        > 使用`Method.getParameter(int index)`来获取第i个索引参数。

    - Create a query with a single CodeQL variable of type `ContentTypeHandlerToObject`.

        > 用类型为`ContentTypeHandlerToObject`的单个CodeQL变量创建一个查询。

    </details>
    
    <details>
    <summary>Solution</summary>
    
    ```ql
    from ContentTypeHandlerToObject toObjectMethod
    select toObjectMethod.getParameter(0)
    ```
    ![image-20210330140358683](https://img.sumsec.me/58u03er58ec/58u03er58ec.png)
    
    ![image-20210330140435655](https://img.sumsec.me/35u04er35ec/35u04er35ec.png)
    
    ![image-20210330140447854](https://img.sumsec.me/47u04er47ec/47u04er47ec.png)
    
    
    
    </details>

### Section 3: Unsafe XML deserialization <a id="section3"></a>

We have now identified (a) places in the program which receive untrusted data and (b) places in the program which potentially perform unsafe XML deserialization. We now want to tie these two together to ask: does the untrusted data ever _flow_ to the potentially unsafe XML deserialization call?

> 我们现在已经确定了(a)程序中接收不受信任数据的地方和(b)程序中可能执行不安全的XML反序列化的地方。我们现在想把这两个地方联系起来问：未受信任的数据是否曾经_流向潜在的不安全的XML反序列化调用？

In program analysis we call this a _data flow_ problem. Data flow helps us answer questions like: does this expression ever hold a value that originates from a particular other place in the program?

> 在程序分析中，我们称之为_数据流_问题。数据流帮助我们回答这样的问题：这个表达式是否曾经持有一个源自程序中其他特定地方的值？

We can visualize the data flow problem as one of finding paths through a directed graph, where the nodes of the graph are elements in program, and the edges represent the flow of data between those elements. If a path exists, then the data flows between those two nodes.

> 我们可以把数据流问题想象成一个通过有向图寻找路径的问题，图中的节点是程序中的元素，而边则代表这些元素之间的数据流。如果存在一条路径，那么数据就在这两个节点之间流动。

Consider this example Java method:

> 考虑这个Java方法的例子:

```c
int func(int tainted) {
   int x = tainted;
   if (someCondition) {
     int y = x;
     callFoo(y);
   } else {
     return x;
   }
   return -1;
}
```
The data flow graph for this method will look something like this:

> 这个方法的数据流图会是这样的:

<img src="https://img.sumsec.me/20u06er20ec/20u06er20ec.png" alt="drawing" width="260"/>

This graph represents the flow of data from the tainted parameter. The nodes of graph represent program elements that have a value, such as function parameters and expressions. The edges of this graph represent flow through these nodes.

> 这个图表示污点参数的数据流。图的节点代表有值的程序元素，如函数参数和表达式。该图的边代表流经这些节点的流量。

CodeQL for Java provides data flow analysis as part of the standard library. You can import it using `semmle.code.java.dataflow.DataFlow`. The library models nodes using the `DataFlow::Node` CodeQL class. These nodes are separate and distinct from the AST (Abstract Syntax Tree, which represents the basic structure of the program) nodes, to allow for flexibility in how data flow is modeled.

> CodeQL for Java提供的数据流分析是标准库的一部分。你可以使用`semmle.code.java.dataflow.DataFlow`导入它。该库使用`DataFlow::Node`CodeQL类对节点进行建模。这些节点与AST（Abstract Syntax Tree，表示程序的基本结构）节点是分开的，有别于AST节点，以便灵活地对数据流进行建模。

There are a small number of data flow node types – expression nodes and parameter nodes are most common.

> 有少量的数据流节点类型--表达式节点和参数节点是最常见的。

In this section we will create a data flow query by populating this template:

> 在本节中，我们将通过填充这个模板来创建一个数据流查询:

```ql
/**
 * @name Unsafe XML deserialization
 * @kind problem
 * @id java/unsafe-deserialization
 */
import java
import semmle.code.java.dataflow.DataFlow

// TODO add previous class and predicate definitions here

class StrutsUnsafeDeserializationConfig extends DataFlow::Configuration {
  StrutsUnsafeDeserializationConfig() { this = "StrutsUnsafeDeserializationConfig" }
  override predicate isSource(DataFlow::Node source) {
    exists(/** TODO fill me in **/ |
      source.asParameter() = /** TODO fill me in **/
    )
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(/** TODO fill me in **/ |
      /** TODO fill me in **/
      sink.asExpr() = /** TODO fill me in **/
    )
  }
}

from StrutsUnsafeDeserializationConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "Unsafe XML deserialization"
```

 1. Complete the `isSource` predicate using the query you wrote for [Section 2](#section2).

    > 使用你为[第2节](#section2)写的查询完成 "isSource "谓词。

    <details>
    <summary>Hint</summary>

    - You can translate from a query clause to a predicate by:
      
       > 你可以通过以下方式从查询子句翻译成谓词: 
       
       - Converting the variable declarations in the `from` part to the variable declarations of an `exists`
       
           > 将 "from "部分的变量声明转换为 "exists "部分的变量声明。
       
       - Placing the `where` clause conditions (if any) in the body of the exists
       
           > 将 "where "子句条件(如果有的话)放在existence的正文中。
       
       - Adding a condition which equates the `select` to one of the parameters of the predicate.
       
           > 添加一个条件，将`select`等同于谓词的一个参数。
       
    - Remember to include the `ContentTypeHandlerToObject` class you defined earlier.

       > 记住要包含你之前定义的`ContentTypeHandlerToObject`类。

    </details>
    <details>
    <summary>Solution</summary>

    ```ql
      override predicate isSource(Node source) {
        exists(ContentTypeHandlerToObject toObjectMethod |
          source.asParameter() = toObjectMethod.getParameter(0)
        )
      }
    ```
    </details>

 1. Complete the `isSink` predicate by using the final query you wrote for [Section 1](#section1). Remember to use the `isXMLDeserialized` predicate!
    
    > 使用你为[Section1](#section1)写的最后一个查询来完成`isSink`谓词。记得使用`isXMLDeserialized`谓词!

    <details>
    <summary>Hint</summary>
    
    - Complete the same process as above.
    
    > 完成与上述相同的过程。
    
    </details>
    <details>
    <summary>Solution</summary>
    
    ```ql
      override predicate isSink(Node sink) {
        exists(Expr arg |
          isXMLDeserialized(arg) and
          sink.asExpr() = arg
        )
      }
    ```
    </details>

You can now run the completed query. You should find exactly one result, which is the CVE reported by our security researchers in 2017!

> 您现在可以运行完成的查询。你应该会发现正好有一个结果，这就是我们的安全研究人员在2017年报告的CVE!

For this result, it is easy to verify that it is correct, because both the source and sink are in the same method. However, for many data flow problems this is not the case.

> 对于这个结果，很容易验证它是正确的，因为源和汇都在同一个方法中。然而，对于很多数据流问题来说，情况并非如此。

We can update the query so that it not only reports the sink, but it also reports the source and the path to that source. We can do this by making these changes:

> 我们可以更新查询，使其不仅报告汇，而且还报告源和通往该源的路径。我们可以通过做这些改变来实现。

The answer to this is to convert the query to a _path problem_ query. There are five parts we will need to change:

> 答案是将查询转换为_路径问题查询。我们需要改变的有五个部分:

 - Convert the `@kind` from `problem` to `path-problem`. This tells the CodeQL toolchain to interpret the results of this query as path results.

    > 将"@kind "从 "problem "转换为 "path -problem"。这告诉CodeQL工具链将这个查询的结果解释为路径结果。

 - Add a new import `DataFlow::PathGraph`, which will report the path data alongside the query results.

    > 增加一个新的导入`DataFlow::PathGraph`，它将在查询结果的同时报告路径数据。

 - Change `source` and `sink` variables from `DataFlow::Node` to `DataFlow::PathNode`, to ensure that the nodes retain path information.

    > 将`source`和`sink`变量由`DataFlow::Node`改为`DataFlow::PathNode`，以保证节点保留路径信息。

 - Use `hasFlowPath` instead of `hasFlow`.

    > 使用`hasFlowPath`代替`hasFlow`。

 - Change the select to report the `source` and `sink` as the second and third columns. The toolchain combines this data with the path information from `PathGraph` to build the paths.

    > 改变选择，将`source`和`sink`报成第二列和第三列。工具链将这些数据与`PathGraph`中的路径信息结合起来，建立路径。

 3. Convert your previous query to a path-problem query.
    
    >  将之前的查询转换为路径问题查询。

    <details>
    <summary>Solution</summary>
    
    ```ql
    /**
    * @name Unsafe XML deserialization
    * @kind path-problem
    * @id java/unsafe-deserialization
    */
    import java
    import semmle.code.java.dataflow.DataFlow
    import DataFlow::PathGraph
    
    predicate isXMLDeserialized(Expr arg) {
      exists(MethodAccess fromXML |
        fromXML.getMethod().getName() = "fromXML" and
    arg = fromXML.getArgument(0)
      )
    }
    
    /** The interface `org.apache.struts2.rest.handler.ContentTypeHandler`. */
    class ContentTypeHandler extends RefType {
      ContentTypeHandler() {
    this.hasQualifiedName("org.apache.struts2.rest.handler", "ContentTypeHandler")
      }
    }
    
    /** A `toObject` method on a subtype of `org.apache.struts2.rest.handler.ContentTypeHandler`. */
    class ContentTypeHandlerToObject extends Method {
      ContentTypeHandlerToObject() {
        this.getDeclaringType().getASupertype() instanceof ContentTypeHandler and
    this.hasName("toObject")
      }
    }
    
    class StrutsUnsafeDeserializationConfig extends DataFlow::Configuration {
      StrutsUnsafeDeserializationConfig() { this = "StrutsUnsafeDeserializationConfig" }
      override predicate isSource(DataFlow::Node source) {
        exists(ContentTypeHandlerToObject toObjectMethod |
          source.asParameter() = toObjectMethod.getParameter(0)
        )
      }
      override predicate isSink(DataFlow::Node sink) {
        exists(Expr arg |
          isXMLDeserialized(arg) and
          sink.asExpr() = arg
    )
      }
    }
    
    from StrutsUnsafeDeserializationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
    where config.hasFlowPath(source, sink)
    select sink, source, sink, "Unsafe XML deserialization"
    ```
    ![image-20210330204553733](https://img.sumsec.me/53u45er53ec/53u45er53ec.png)
    
    ![image-20210330204604285](https://img.sumsec.me/4u46er4ec/4u46er4ec.png)
    
    ![image-20210330204613764](https://img.sumsec.me/13u46er13ec/13u46er13ec.png)
    
    
    
    </details>

For more information on how the vulnerability was identified, you can read the [blog disclosing the original problem](https://securitylab.github.com/research/apache-struts-vulnerability-cve-2017-9805).

> 关于如何发现该漏洞的更多信息，你可以阅读[披露原始问题的博客](https://securitylab.github.com/research/apache-struts-vulnerability-cve-2017-9805)。

Although we have created a query from scratch to find this problem, it can also be found with one of our default security queries, [UnsafeDeserialization.ql](https://github.com/github/codeql/blob/master/java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql). You can see this on a [vulnerable copy of Apache Struts](https://github.com/m-y-mo/struts_9805) that has been [analyzed on LGTM.com](https://lgtm.com/projects/g/m-y-mo/struts_9805/snapshot/31a8d6be58033679a83402b022bb89dad6c6e330/files/plugins/rest/src/main/java/org/apache/struts2/rest/handler/XStreamHandler.java?sort=name&dir=ASC&mode=heatmap#x121788d71061ed86:1), our free open source analysis platform.

> 虽然我们从头开始创建了一个查询来发现这个问题，但也可以通过我们的一个默认安全查询，[UnsafeDeserialization.ql](https://github.com/github/codeql/blob/master/java/ql/src/Security/CWE/CWE-502/UnsafeDeserialization.ql)来发现。你可以在[Apache Struts的脆弱副本](https://github.com/m-y-mo/struts_9805)上看到这个问题，这个漏洞已经被[在LGTM.com](https://lgtm.com/projects/g/m-y-mo/struts_9805/snapshot/31a8d6be58033679a83402b022bb89dad6c6e330/files/plugins/rest/src/main/java/org/apache/struts2/rest/handler/XStreamHandler.java?sort=name&dir=ASC&mode=heatmap#x121788d71061ed86:1)上分析过了，LGTM.com是我们免费的开源分析平台。
>

## What's next?
- Read the [tutorial on analyzing data flow in Java](https://help.semmle.com/QL/learn-ql/java/dataflow.html).

    > 阅读[用Java分析数据流教程](https://help.semmle.com/QL/learn-ql/java/dataflow.html)。

- Go through more [CodeQL training materials for Java](https://help.semmle.com/QL/learn-ql/ql-training.html#codeql-and-variant-analysis-for-java).

    >  浏览更多[CodeQL Java培训资料](https://help.semmle.com/QL/learn-ql/ql-training.html#codeql-and-variant-analysis-for-java)。

- Try out the latest CodeQL Java Capture-the-Flag challenge on the [GitHub Security Lab website](https://securitylab.github.com/ctf) for a chance to win a prize! Or try one of the older Capture-the-Flag challenges to improve your CodeQL skills.

    > 在[GitHub安全实验室网站](https://securitylab.github.com/ctf)上尝试最新的CodeQL Java Capture-the-Flag挑战，有机会获得奖品! 或者试试以前的Capture-the-Flag挑战，以提高您的CodeQL技能。

- Try out a CodeQL course on [GitHub Learning Lab](https://lab.github.com/githubtraining/codeql-u-boot-challenge-(cc++)).

    > 在[GitHub学习实验室](https://lab.github.com/githubtraining/codeql-u-boot-challenge-(cc++))上尝试一下CodeQL课程。

- Read about more vulnerabilities found using CodeQL on the [GitHub Security Lab research blog](https://securitylab.github.com/research).

    > 在[GitHub安全实验室研究博客](https://securitylab.github.com/research)上阅读更多使用CodeQL发现的漏洞。

- Explore the [open-source CodeQL queries and libraries](https://github.com/github/codeql), and [learn how to contribute a new query](https://github.com/github/codeql/blob/master/CONTRIBUTING.md).

    > 探索[开源CodeQL查询和库](https://github.com/github/codeql)，以及[学习如何贡献一个新的查询](https://github.com/github/codeql/blob/master/CONTRIBUTING.md)。