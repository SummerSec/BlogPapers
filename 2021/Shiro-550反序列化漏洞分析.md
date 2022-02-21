
# 概述

&emsp;&emsp; Shiro反序列化漏洞目前为止有两个，Shiro-550``(Apache  Shiro < 1.2.5)``和Shiro-721``( Apache  Shiro < 1.4.2 )``。这两个漏洞主要区别在于Shiro550使用已知密钥撞，后者Shiro721是使用``登录后rememberMe={value}去爆破正确的key值``进而反序列化，对比Shiro550条件只要有``足够密钥库``（条件比较低）、Shiro721需要登录（要求比较高~~鸡肋~~）。
* ``Apache Shiro < 1.4.2``默认使用``AES/CBC/PKCS5Padding ``模式
* `` Apache Shiro >= 1.4.2``默认使用``AES/GCM/PKCS5Padding``模式

---
# 环境搭建
&emsp;&emsp; 采用Maven仓库的形式，源码放在[GitHub](https://github.com/SummerSec/JavaLearnVulnerability)上，直接用Idea打开即可。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.5.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <groupId>org.example</groupId>
    <artifactId>shiro-deser</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
            <version>1.2.4</version>
        </dependency>
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-web</artifactId>
            <version>1.2.4</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
            <exclusions>
                <exclusion>
                    <groupId>org.junit.vintage</groupId>
                    <artifactId>junit-vintage-engine</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
<!--        hutool是一款十分强大工具库-->
<!--        官网地址 https://www.hutool.cn/-->
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>5.5.7</version>
        </dependency>
<!--         添加commons-collections依赖作为 payload-->
<!--        <dependency>-->
<!--            <groupId>commons-collections</groupId>-->
<!--            <artifactId>commons-collections</artifactId>-->
<!--            <version>4.0</version>-->
<!--        </dependency>-->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
    </dependencies>

    <build>
    <plugins>
    <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <configuration>
        // debug参数
            <jvmArguments>
                -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=5005
            </jvmArguments>
        </configuration>
    </plugin>
    </plugins>
    </build>
</project>
````

-----

# 流程分析
*  调用org\apache\shiro\mgt\DefaultSecurityManager.class#resolvePrincipals方法``获取remember凭证``
 
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210120170900332.png)
 
* DefaultSecurityManager.class#getRememberedIdentity调用方法``获取rememberMe认证的序列化数据``
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210120170957673.png)

* 接着调用父类org\apache\shiro\mgt\AbstractRememberMeManager.class#getRememberedPrincipals方法在122行调用``getRememberedSerializedIdentity``方法获取cookie中的值
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210120171218140.png)

* 然后来到org\apache\shiro\web\mgt\CookieRememberMeManager.class#getRememberedSerializedIdentity获取cookie值之后，先判断一下是否为空和``deleteMe``，解之Base64解码最后在95行处返回byte[]值
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122145845874.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122150020874.png)

* org\apache\shiro\mgt\AbstractRememberMeManager.class#getRememberedPrincipals方法的124行进行类型转化，类型转化的过程中会进行AES解密操作，进而作为反序列化的数据
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122150415517.png)
* AbstractRememberMeManager.class#convertBytesToPrincipals进行AES解密操作，最后调用反序列化方法，将数据反序列化，导致反序列化漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122150613761.png)

* AbstractRememberMeManager#decrypt方法
```java
protected byte[] decrypt(byte[] encrypted) {
        byte[] serialized = encrypted;
        CipherService cipherService = this.getCipherService();
        if (cipherService != null) {
            ByteSource byteSource = cipherService.decrypt(encrypted, this.getDecryptionCipherKey());
            serialized = byteSource.getBytes();
        }

        return serialized;
    }
```
* 查看bytes数据值，可以看到解密后是生成的恶意payload
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122151026506.png)
* 完整的payload演示效果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122191831440.gif)


----
# Shiro‘s key爆破方式
## 基于原生shiro框架检测方式
l1nk3r师傅的检测思路地址: https://mp.weixin.qq.com/s/do88_4Td1CSeKLmFqhGCuQ
关键代码：

```java

 SimplePrincipalCollection simplePrincipalCollection = new SimplePrincipalCollection();
        ObjectOutputStream obj = new ObjectOutputStream(new FileOutputStream("payload"));
        obj.writeObject(simplePrincipalCollection);
        obj.close();
```
实现具体代码

```java
public static void main(String[] args) throws IOException {
        // 正确key
        String realkey = "kPH+bIxk5D2deZiIxcaaaA==";
        // 错误key
        String errorkey = "2AvVhdsgUs0FSA3SDFAdag==";
        // 序列化文件路径
        String filepath = "E:\\Soures\\JavaLearnVulnerability\\shiro\\shiro-deser\\key";

        SimplePrincipalCollection simplePrincipalCollection = new SimplePrincipalCollection();
        ObjectOutputStream obj = new ObjectOutputStream(new FileOutputStream(filepath));
        try {
            // 写入序列化数据
            obj.writeObject(simplePrincipalCollection);
            obj.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        FileReader fileReader = new FileReader(filepath);

        CbcEncrypt cbcEncrypt = new CbcEncrypt();
        String realcookie = "rememberMe=" + cbcEncrypt.encrypt(realkey,fileReader.readBytes());
        String errorcookie = "rememberMe=" + cbcEncrypt.encrypt(errorkey,fileReader.readBytes());
        System.out.println("realcookie --> " + realcookie);
        System.out.println("errorcookie --> " + errorcookie);
        String url = "http://127.0.0.1:8001/index";
        // 发送请求包，获取返回包
        HttpResponse realresponse = HttpRequest.get(url).cookie(realcookie).execute();
        HttpResponse errorresponse = HttpRequest.get(url).cookie(errorcookie).execute();
        String result1 = realresponse.header(Header.SET_COOKIE);
        String result2 = errorresponse.header(Header.SET_COOKIE);
        // 输出结果
        System.out.println("realkey ---> " + result1);
        System.out.println("errorkey ---> " + result2);
    }
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122190937627.png)



# 总结
&emsp;&emsp; Gadget Chian 如下。简单来说流程就是将生成恶意Payload进行AES加密，然后Base64编码，然后以``rememberMe={value}``形式发送给服务器。服务器将``value``Base64解码，然后将解码后数据进行AES解密，最后反序列化执行命令。
&emsp;&emsp; Shiro721在登录之后，用登录后服务器生成rememberMe的值进行Base64解码之后，用解码数据，再通过``Padding Oracle Attack``进行爆破得到key具体参考[Shiro 组件漏洞与攻击链分析](https://paper.seebug.org/1378/#412-apache-shiro-padding-oracle-attack)。

````
 *                  Gadget chian:
 *                      DefaultSecurityManager.resolvePrincipals()
 *                          DefaultSecurityManager.getRememberedIdentity()
 *                              AbstractRememberMeManager.getRememberedPrincipals()
 *                                  CookieRememberMeManager#getRememberedSerializedIdentity()
 *                                      AbstractRememberMeManager#getRememberedPrincipals()
 *                                          AbstractRememberMeManager.convertBytesToPrincipals()
 *                                              AbstractRememberMeManager.decrypt()
 *                                                  AbstractRememberMeManager.deserialize()
 *                                                      .....................
 *                                                               ..........
 *  
 *
````



----
## Shiro实用工具推荐
* [shiro_attack](https://github.com/j1anFen/shiro_attack) 推荐理由：javafx写的UI，支持tomcat全版本回显和Spring Boot回显。使用``SimplePrincipalCollection ``爆破key，支持高版本加密方式爆破（GCM模式）项目还在维护。
![](https://img-blog.csdnimg.cn/20210122183413881.png)
---

* [BurpShiroPassiveScan](https://github.com/pmiaowu/BurpShiroPassiveScan)是一款burp插件，被动式扫描，自动识别是否为shiro框架，支持CBC/GCM两种加密方式，同时默认使用``SimplePrincipalCollection ``爆破key，项目在维护。
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021012218384769.png)

---
## 踩坑记录
### 编码不一致问题
由于Windows cmd的编码是gdk，导致读取cmd内容的时候会``aced0005``变成``efbfbdefbfbd``，导致无法反序列化。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210120125258810.png)
解决办法将生成的payload导入文件之中，然后读取二进制数据。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122171101605.png)

-----
## 课外知识补充
### springboot debug技巧
在配置中VM options 输入``-Xms512m -Xmx512m -Xmn164m -XX:MaxPermSize=250m -XX:ReservedCodeCacheSize=64m -Dserver.port=8001 -ea``
![在这里插入图片描述](https://img-blog.csdnimg.cn/202101221712423.png)
同时在配置文件pom.xml加入

```java
<plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <configuration>
            <jvmArguments>
                -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=5005
            </jvmArguments>
        </configuration>
    </plugin>
```

### VScode添加插件
Hex Editor插件

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122171520346.png)
效果如下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122171541915.png)

### Git 自带 xxd工具
将工具路径加入环境变量
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122171754706.png)
效果如下：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210122172003896.png)


-----

# 参考
https://issues.apache.org/jira/browse/SHIRO-550
https://paper.seebug.org/1378
https://ares-x.com/2020/10/26/Shiro%E9%AB%98%E7%89%88%E6%9C%AC%E5%8A%A0%E5%AF%86%E6%96%B9%E5%BC%8F%E4%B8%8B%E7%9A%84%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8/
https://mp.weixin.qq.com/s/do88_4Td1CSeKLmFqhGCuQ
