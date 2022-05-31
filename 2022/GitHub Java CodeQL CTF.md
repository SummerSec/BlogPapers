# GitHub Java CodeQL CTF

GitHub Security Lab CTF 4: CodeQL and Chill - The Java Edition  

CVE-2020-9297

https://securitylab.github.com/advisories/GHSL-2020-028-netflix-titus/

[CTF 地址](https://securitylab.github.com/ctf/codeql-and-chill/) 

[CodeQL database 下载地址](https://drive.google.com/open?id=10ju0t2QZjsKI8qrAqwzsPA3K-lBgqPVF)

---

## 简介

题目介绍：用户控制的数据被传入支持Java EL表达式的Bean Validation库函数`ConstraintValidatorContext.buildConstraintViolationWithTemplate`，但问题是如何获取RCE。因此，远程代码执行。这似乎问题已经结束，但事实并非如此。想要RCE并不像仅仅传递一个EL表达式那么简单。一些问题，如用户输入的小写字母，使我们无法获得利用。解释如何使用CodeQL找到流向目标函数的特定用户控制数据的，了解远程代码成功执行有哪些要求。

官方给的漏洞成因代码：

```java
@Override
public boolean isValid(Container container, ConstraintValidatorContext context) {
    if (container == null) {
        return true;
    }
    Set<String> common = new HashSet<>(container.getSoftConstraints().keySet());
    common.retainAll(container.getHardConstraints().keySet());
    if (common.isEmpty()) {
        return true;
    }
    context.buildConstraintViolationWithTemplate(
            "Soft and hard constraints not unique. Shared constraints: " + common
    ).addConstraintViolation().disableDefaultConstraintViolation();
    return false;
}
```

大致逻辑如下图，关键点在`buildConstraintViolationWithTemplate`方法调用上。

![image-20210424151151578](https://raw.githubusercontent.com/SummerSec/Images/main/56u11er56ec/56u11er56ec.png)

---

## 数据流和污点跟踪分析

### 1.1 Source

找到漏洞的一个重要部分是找到所有用户控制的数据从哪里来。在挑战页面本身就有提示--函数`isValid`的第一个参数。

因此，`isSource`谓词:

```
/**
 *@name Source
 *@derscription 
 */
import java
import semmle.code.java.dataflow.DataFlow

/*
Map overrides of isValid method from ConstraintValidator
*/
class ConstraintValidator extends RefType {
	ConstraintValidator() {
		this.hasQualifiedName("javax.validation", "ConstraintValidator") 
	}
}

class ConstraintValidatorIsValid extends Method {
	ConstraintValidatorIsValid() {
		this.getName() = "isValid" and
		this.getDeclaringType().getASourceSupertype() instanceof ConstraintValidator
        
	}
}

predicate isSource(DataFlow::Node source) {
	exists(ConstraintValidatorIsValid isValidMethod |
		source.asParameter() = isValidMethod.getParameter(0)
	)
}

//There has to be a query in scope even when you use Quick Evaluation
select "Quick-eval isSource" 
```

第一个`container`是符合要求，但要求只有6个结果也就是说有两个不符合要求。

![image-20210422165129982](https://raw.githubusercontent.com/SummerSec/Images/main/56u35er56ec/56u35er56ec.png)

根据提示：*Map overrides of isValid method from ConstraintValidator*，所以排除不是重写的方法即可。

![image-20210422164940185](https://raw.githubusercontent.com/SummerSec/Images/main/40u49er40ec/40u49er40ec.png)

只需要在加一行`and this.isOverridable()`判断即可，或者注释掉第四、五行再去掉第六行注释也可以。`getASourceOverriddenMethod`首先会判断是否是重写的方法。

```
class ConstraintValidatorIsValid extends Method {
	ConstraintValidatorIsValid() {
		this.getName() = "isValid" and
		this.getDeclaringType().getASourceSupertype() instanceof ConstraintValidator
        and this.isOverridable()
        // this.getASourceOverriddenMethod().getDeclaringType() instanceof ConstraintValidator
        
	}
}

```







---

### 1.2 Sink

根据提示`Sink`是`ConstraintValidatorContext.buildConstraintViolationWithTemplate(...)`**调用**的第一个参数，要求5个结果。

```
/**
 *@name Sink
 *@derscription
 */

import java
import semmle.code.java.dataflow.DataFlow

class TypeConstraintValidatorContext extends RefType {
    TypeConstraintValidatorContext() { 
        this.hasQualifiedName("javax.validation", "ConstraintValidatorContext") 
    }
}


predicate isBuildConstraintViolationWithTemplate(MethodAccess ma){
    ma.getMethod().hasName("buildConstraintViolationWithTemplate") 
    and
    ma.getMethod().getDeclaringType() instanceof TypeConstraintValidatorContext
}

predicate isSink(DataFlow::Node sink){
    exists(MethodAccess ma| 
        isBuildConstraintViolationWithTemplate(ma) 
        and 
        ma.getArgument(0) = sink.asExpr()
    )
}



select "Quick-eval isSink" 
```

![image-20210422173829545](https://raw.githubusercontent.com/SummerSec/Images/main/29u38er29ec/29u38er29ec.png)



----

### 1.3 TaintTracking configuration

题目给了**TaintTracking configuration模板**，如果前面`isSource`和`isSink`谓词都是正确的话，可以得到正确的路径。

```
/** @kind path-problem */
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class MyTaintTrackingConfig extends TaintTracking::Configuration {
    MyTaintTrackingConfig() { this = "MyTaintTrackingConfig" }

    override predicate isSource(DataFlow::Node source) {
        // TODO 
    }

    override predicate isSink(DataFlow::Node sink) {
        // TODO 
    }
}

from MyTaintTrackingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
```

没有任何结果，和出题人意料一样。

![image-20210422200354218](https://raw.githubusercontent.com/SummerSec/Images/main/54u03er54ec/54u03er54ec.png)



---

### 1.4 Partial Flow to the rescue

没有任何结果查询刚学的CodeQL新手小白估计此时都会束手无策了，我们确定了`source`和`sink`，这表明我们的分析在从源到汇的路径上缺少一个步骤。，但CodeQL也考虑到了这种情况，故内置`Partial Data Flow`来debug。`Partial Data Flow`允许寻找从一个给定的`source`到任何可能的`sink`的流动，让`sink`不受限制，同时限制从`source`到`sink`的搜索步骤的数量。因此，可以使用这个来跟踪污点数据从源头到所有可能的汇的流动，并查看流动在哪里停止被进一步`track`。

*About:*

> 参考：[Predicate hasPartialFlow](https://github.com/github/codeql/blob/main/java/ql/src/semmle/code/java/dataflow/internal/DataFlowImpl.qll#L124)
>
> 中文对照翻译：
>
> 如果存在从`source`到`node`的部分数据流路径，则保留。`node`和最近的源之间的近似距离是`dist`，并被限制为小于或等于`explorationLimit()`。这个谓词完全不考虑`sink`的定义。
>
> 该谓词用于数据流探索和调试，如果源的数量太大，和/或探索限制设置得太高而没有使用障碍，则可能表现不佳。
> 这个谓词默认是禁用的（没有结果）。用一个合适的数字覆盖`explorationLimit()`来启用这个谓词。
> 在 "路径问题 "查询中使用，请导入 "PartialPathGraph "模块。

**Partial Flow 模板**

```
/** @kind path-problem */
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PartialPathGraph // this is different!

class MyTaintTrackingConfig extends TaintTracking::Configuration {
    MyTaintTrackingConfig() { ... } // same as before
    override predicate isSource(DataFlow::Node source) { ... } // same as before
    override predicate isSink(DataFlow::Node sink) { ... } // same as before
    override int explorationLimit() { result =  10} // this is different!
}
from MyTaintTrackingConfig cfg, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
where
  cfg.hasPartialFlow(source, sink, _) and
  source.getNode() = ... // TODO restrict to the one source we are interested in, for ease of debugging
select sink, source, sink, "Partial flow from unsanitized user data"

predicate partial_flow(PartialPathNode n, Node src, int dist) {
  exists(MyTaintTrackingConfig conf, PartialPathNode source |
    conf.hasPartialFlow(source, n, dist) and
    src = source.getNode() and
    source =  // TODO - restrict to THE source we are interested in
  )
}
```

在76行和83行都是`source.getNode().asParameter().getName() = "container"`，在题目开头描述了`container`很可能是不安全的。这里也可以这么写`source.getNode().getLocation().getFile().getBaseName() = "SchedulingConstraintValidator.java"`对`source`文件来限制。

```
/**
 *@name Partial Flow to the rescue
 *@kind path-problem
 *@derscription 
 */

import java
import semmle.code.java.dataflow.TaintTracking
// import DataFlow::PathGraph
import DataFlow::PartialPathGraph

/*
source
Map overrides of isValid method from ConstraintValidator
*/
class ConstraintValidator extends RefType {
	ConstraintValidator() {
		this.hasQualifiedName("javax.validation", "ConstraintValidator") 
	}
}

class ConstraintValidatorIsValid extends Method {
	ConstraintValidatorIsValid() {
		this.getName() = "isValid" and
		this.getDeclaringType().getASourceSupertype() instanceof ConstraintValidator
        and this.isOverridable()
        // this.getASourceOverriddenMethod().getDeclaringType() instanceof ConstraintValidator
        
	}
}

/*
sink 
 */
class TypeConstraintValidatorContext extends RefType {
    TypeConstraintValidatorContext() { 
        this.hasQualifiedName("javax.validation", "ConstraintValidatorContext") 
    }
}


predicate isBuildConstraintViolationWithTemplate(MethodAccess ma){
    ma.getMethod().hasName("buildConstraintViolationWithTemplate") 
    and
    ma.getMethod().getDeclaringType() instanceof TypeConstraintValidatorContext
}

class MyTraintTrackConfig extends TaintTracking::Configuration{
    MyTraintTrackConfig(){
        this = "MyTraintTrackConfig"
    }

    override predicate isSource(DataFlow::Node source){
        exists(ConstraintValidatorIsValid isValidMethod |
		source.asParameter() = isValidMethod.getParameter(0)
	)
    }

    override predicate isSink(DataFlow::Node sink){
        exists(MethodAccess ma| 
        isBuildConstraintViolationWithTemplate(ma) 
        and 
        ma.getArgument(0) = sink.asExpr()
    )
    }

    override int explorationLimit(){
        result = 10
    }

}

from MyTraintTrackConfig config, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
where 
    config.hasPartialFlow(source, sink, _) and
    source.getNode().asParameter().getName() = "container"
select sink, source, sink, "Partial flow from unsanitized user data"

predicate partial_flow(DataFlow::PartialPathNode n, DataFlow::Node src, int dist) {
    exists(MyTraintTrackConfig conf, DataFlow::PartialPathNode source |
    conf.hasPartialFlow(source, n, dist) and
    src = source.getNode() and
    source.getNode().asParameter().getName() = "container"
    )
}
```

![image-20210422212855935](https://raw.githubusercontent.com/SummerSec/Images/main/56u28er56ec/56u28er56ec.png)



---

### 1.5 Identifying a missing taint step

You must have found that CodeQL does not propagate taint through getters like `container.getHardConstraints` and `container.getSoftConstraints`. Can you guess why this default behaviour was implemented?

> 你一定发现，CodeQL不会通过getters传播污点，比如`container.getHardConstraints`和`container.getSoftConstraints`。你能猜到为什么要实施这种默认行为吗？

答案：

默认步骤是小心翼翼地避免假阳性，特别是对于生产级别的查询。追踪漏洞可以让我们看到流程在哪里停止了。猜测是，getters/setters方法经常会覆盖有污点的数据，而让它不受约束也可能会返回非常多的结果。当一个写得不好的查询消耗会所有的内存时，分析部分流量时，需要限制来源的数量。

例如：

```
public class SomeThingObject {
    private String tainted;
    private int something;

    public SomeThingObject(String tainted, int something) {
        this.tainted = tainted;
        this.something = something;
    }

    public String getTainted() {
        return tainted;
    }

    public String getSomething() {
        return something;
    }
}

SomeThingObject stb = new SomeThingObject("tainted", 123);
int notTainted = someObject.getSomething()
dangerousSink(notTainted);
```

如果我们认为字符串 "tainted "是一个危险的用户输入，那么stb实例也会被污染。正因为如此，假设该实例上的每个getter都会返回一个有污点的值，就会导致dangerousSink调用中出现假阳性。这可能就是为什么CodeQL默认情况下不会将污点传播给有污点的对象实例上的getter。



---

### 1.6 Adding additional taint steps

分析1.4的结果，可以发现在停止`getSoftConstraints`和`getHardConstraints`被进一步`track`。

![image-20210424151919760](https://raw.githubusercontent.com/SummerSec/Images/main/19u19er19ec/19u19er19ec.png)

CodeQL允许在在`TaintTracking::Configuration`中声明额外的污点步骤，也就是谓词`isAdditionalTaintStep`。

![image-20210424155832451](https://raw.githubusercontent.com/SummerSec/Images/main/32u58er32ec/32u58er32ec.png)

但这里官方推荐另一种更通用的方法，使用[TaintTracking::AdditionalTaintStep](https://github.com/github/codeql/blob/bc7163aa68017f93c25ec7423044727a5d785142/java/ql/src/semmle/code/java/dataflow/internal/TaintTrackingUtil.qll#L67)类。

```
class MyAdditionalTaintStep extends TaintTracking::AdditionalTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {// pred 先前 Previously  succ 先后 Successively
    exists( | | )
  }
}
```

根据提示：在步骤谓词中，你应该指出这2个`nodes`是MethodAccess的2个元素：一个是它的`qualifier `，一个是在调用发现的`返回值`。利用模板进行进一步`track`

```

predicate flowMethodCallable(Callable m) {
    exists(string s |
    s = m.getName() and
    (
        s = "getSoftConstraints" or
        s = "getHardConstraints" or
        s = "keySet"
    )
    )
}

class StepThroughMemberMethodCallable extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess ma |
        n1.asExpr() = ma.getQualifier() and // `qualifier `
        n2.asExpr() = ma and // retrun vlaue
        flowMethodCallable(ma.getMethod())
    )
    } 
}
```

![image-20210424173435717](https://raw.githubusercontent.com/SummerSec/Images/main/35u34er35ec/35u34er35ec.png)



----

### 1.7 Adding taint steps through a constructor

要求为`HashSet`构造函数加`AdditionalTaintStep`

```
/*
HashSet Contructor 
*/
predicate flowContructorCallable(Callable cc) {
    exists(string s |
    s = cc.getName()
    and s.matches("HashSet%")
    )
}

class StepThroughConstructor extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
        exists(ConstructorCall cc |
        pred.asExpr() = cc.getAnArgument() and
        succ.asExpr() = cc and  
        flowContructorCallable(cc.getConstructor())
        )
    }
}
```

![image-20210424173454759](https://raw.githubusercontent.com/SummerSec/Images/main/54u34er54ec/54u34er54ec.png)



---

### 1.8 Finish 

最终的QL结果：

```
/**
 * @name finis the ql
 * @kind path-problem
 * @derscription 
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph
// import DataFlow::PartialPathGraph

/*
MethodCallable additional Taint Step
*/ 
predicate flowMethodCallable(Callable m) {
    exists(string s |
    s = m.getName() and
    (
        s = "getSoftConstraints" or
        s = "getHardConstraints" or
        s = "keySet" 
    )
    )
}


class StepThroughMemberMethodCallable extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess ma |
        n1.asExpr() = ma.getQualifier() and // `qualifier `
        n2.asExpr() = ma and // retrun vlaue
        flowMethodCallable(ma.getMethod())
    )
    } 
}

/*
HashSet Contructor 
*/
predicate flowContructorCallable(Callable cc) {
    exists(string s |
    s = cc.getName()
    and s.matches("HashSet%")
    )
}

class StepThroughConstructor extends TaintTracking::AdditionalTaintStep {
    override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
        exists(ConstructorCall cc |
        pred.asExpr() = cc.getAnArgument() and
        succ.asExpr() = cc and  
        flowContructorCallable(cc.getConstructor())
        )
    }
}


/*
source
Map overrides of isValid method from ConstraintValidator
*/
class ConstraintValidator extends RefType {
	ConstraintValidator() {
		this.hasQualifiedName("javax.validation", "ConstraintValidator") 
	}
}

class ConstraintValidatorIsValid extends Method {
	ConstraintValidatorIsValid() {
		this.getName() = "isValid" and
		this.getDeclaringType().getASourceSupertype() instanceof ConstraintValidator
        and this.isOverridable()
        // this.getASourceOverriddenMethod().getDeclaringType() instanceof ConstraintValidator
        
	}
}

/*
sink 
 */
class TypeConstraintValidatorContext extends RefType {
    TypeConstraintValidatorContext() { 
        this.hasQualifiedName("javax.validation", "ConstraintValidatorContext") 
    }
}


predicate isBuildConstraintViolationWithTemplate(MethodAccess ma){
    ma.getMethod().hasName("buildConstraintViolationWithTemplate") 
    and
    ma.getMethod().getDeclaringType() instanceof TypeConstraintValidatorContext
}

class MyTraintTrackConfig extends TaintTracking::Configuration{
    MyTraintTrackConfig(){
        this = "MyTraintTrackConfig"
    }

    override predicate isSource(DataFlow::Node source){
        exists(ConstraintValidatorIsValid isValidMethod |
		source.asParameter() = isValidMethod.getParameter(0)
	)
    }

    override predicate isSink(DataFlow::Node sink){
        exists(MethodAccess ma| 
        isBuildConstraintViolationWithTemplate(ma) 
        and 
        ma.getArgument(0) = sink.asExpr()
    )
    }

    override int explorationLimit(){
        result = 10
    }

}

from MyTraintTrackConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where 
    config.hasFlowPath(source, sink)
select sink, source, sink, "Custom constraint error message contains unsanitized user data"
```



![image-20210424173533177](https://raw.githubusercontent.com/SummerSec/Images/main/33u35er33ec/33u35er33ec.png)





----



## 参考

https://github.com/atorralba/GHSL_CTF_4

https://securitylab.github.com/ctf/codeql-and-chill/

https://github.com/github/securitylab/discussions/141

https://xz.aliyun.com/t/7979#toc-6