



### Sensitive keys in codebases



在方法2的情况下，前提条件是可以访问pod，那就可以使用下面这条命令代替使用gitdump的方式。根据命令的执行结果，做一下命令的解读。

```bash
export POD_NAME=$(kubectl get pods --namespace default -l "app=build-code" -o jsonpath="{.items[0].metadata.name}")
```



**kubectl get pods --namespace default** 获取默认的命名空间

![image-20220728130013942](https://img.sumsec.me/202207/202207281300237.png)