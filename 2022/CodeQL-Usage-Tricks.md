

## CodeQl Usage Tricks

## 前言

codeql大流行的时代，如何学会使用codeql变得由于重要。学习其中tricks，能够更好的方便进行代码审计工作。本文会从自动化build数据库，codeql的debug等角度帮助大家进一步了解codeql这款神器。



---

### 数据库build日志

####  build-tarcer.log

看CodeQL的database的日志，可以发现很多有用的信息。

![image-20220301155005984](https://cdn.jsdelivr.net/gh/SummerSec/Images/6u506ec6u506ec.png)

文件**build-tracer.log**中

> <font color=red>Loading extra JVM options from SEMMLE_JAVA_TOOL_OPTIONS instead of in-process variable.Passing through -javaagent:D:\codeql\codeql\java\tools/codeql-java-agent.jar=ignore-project,java to underlying JVM.</font>

可以发现CodeQL应用了Java的agent技术，将**codeql-java-agent.jar**文件加载到构建程序中。

> <font color=red>[T 11:42:48 19660] Passing through -Xbootclasspath/a:D:\codeql\codeql\java\tools/codeql-java-agent.jar to underlying JVM.
> [T 11:42:48 19660] Intercepted JVM creation with extra hidden args: ['-javaagent:D:\codeql\codeql\java\tools/codeql-java-agent.jar=ignore-project,java' '-Xbootclasspath/a:D:\codeql\codeql\java\tools/codeql-java-agent.jar'] (result: 1, 0).</font>

通过**codeql-java-agent.jar**传递给底层JVM之后，使用CodeQL自带的Java.exe程序拦截带有额外隐藏参数的JVM，也就是**codeql-java-agent.jar=ignore-project,java' '-Xbootclasspath/a:D:\codeql\codeql\java\tools/codeql-java-agent.jar**。

----

有兴趣可以继续看看jar里面的代码，本人还没有看出个所以然来，就不写具体的分析过程了。





### CodeQL Action

可以说CodeQL使用最六的一批人肯定是CodeQL的官方，为了可以学习到CodeQL的隐藏技巧，学习其Action的使用变得非常有必要了。

使用GitHub官方的CodeQL Action分析Java应用时，如果使用了javafx，创建数据库时会失败的。解决办法在，最开始的时候就设置action环境，添加javafx。完整的代码参考[codeql.yml](https://github.com/SummerSec/SPATool/blob/main/.github/workflows/codeql.yml)

![image-20220327122536672](https://cdn.jsdelivr.net/gh/SummerSec/Images/43u2543ec43u2543ec.png)



在执行分析ql查询，可以发现codeql的action使用一条命令就可以批量的进行ql查询， 不能发现关键在`java-queries-builtin.qls`文件，但其实codeql的仓库里是没有这个文件的。

```
codeql database run-queries --ram=5923 --threads=2 /home/runner/work/_temp/codeql_databases/java --min-disk-free=1024 -v /home/runner/work/_temp/codeql_databases/java-queries-builtin.qls
```



![image-20220327122943785](https://cdn.jsdelivr.net/gh/SummerSec/Images/14u514ec14u514ec.png)



询问GitHub官方人员之后，给出的答案是使用代码生成的文件。[code link](https://github.com/github/codeql-action/blob/b1c781d3983c105067e87232b504af53d61f803b/src/analyze.ts#L371-L372)

```
    const querySuitePath = `${databasePath}-queries-${type}.qls`;
    fs.writeFileSync(querySuitePath, querySuiteContents);
```

但看完代码之后，我本地也没环境去调试，生成这段代码，事情就变得复杂了起来。回头我转身想想，这个文件在GitHub action中，肯定是可以使用upload artifact传出来。于是乎我在codeql.yml文件添加了几行就非常简单的获取到这个文件。

```yml
    - name: Upload a Build Artifact
      id: upload-build-artifact
      uses: actions/upload-artifact@v2.3.1
      with:
        # Artifact name
        name: # optional, default is artifact
          java-queries-builtin.qls
        # A file, directory or wildcard pattern that describes what to upload
        path:
          /home/runner/work/_temp/codeql_databases/java-queries-builtin.qls
        # The desired behavior if no files are found using the provided path.
```

然后就可以在action执行完成之后，在Summary中下载到。比例本人在自己的SPATool仓库下载[https://github.com/SummerSec/SPATool/suites/5809018842/artifacts/194366370](https://github.com/SummerSec/SPATool/suites/5809018842/artifacts/194366370)

![image-20220327133948961](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/49u3949ec49u3949ec.png)

打开文件之后可以发现，codeql-action查询仓库是否存在漏洞都是使用了CWE目录下的ql文件，这些文件我们都是可以直接在codeql仓库获取到，我们只需要将文件的路径替换一下就可以本地绝对路径即可。

![image-20220327134033941](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/34u4034ec34u4034ec.png)

![image-20220327134725114](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/25u4725ec25u4725ec.png)

使用vscode的全部替换模式，`.*0.0.9\/` `- query: D:\codeql\vscode-codeql-starter\ql\java\ql\src\`，再将`\/`替换成`\`即可。

![image-20220327135047201](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/47u5047ec47u5047ec.png)

批量查询命令

```
codeql  database run-queries --ram=5932 --threads=2 SPATool --min-disk-free=1024 -v java-queries-builtin.qls 
```

![image-20220327135812265](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/12u5812ec12u5812ec.png)

导出查询的结果命令

```
codeql database interpret-results --threads=2 --format=sarif-latest -v --output=../results/java.sarif --no-sarif-add-snippets --print-diagnostics-summary --print-metrics-summary --sarif-group-rules-by-pack --sarif-add-query-help java-queries-builtin.qls
```





----

### CodeQL debug 

[codeql-debug](https://github.com/zbazztian/codeql-debug)项目在很早之前，本人在很早之前就关注了。之前没太研究其作用，最近突然发现pwntester大佬也star该项目了，我变得重新重视其作用。研究之后发现其就是为了找到database中的所有的source和sink点，目的就是为了在使用ql查询之后没有找到任何的漏洞，我们可以使用这个项目肉眼人工的进行寻找漏洞。

使用自己的项目[SPATool](https://github.com/SummerSec/SPATool)查询之后的效果如下：

![image-20220327141142706](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/42u1142ec42u1142ec.png)

![image-20220327141155339](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/55u1155ec55u1155ec.png)

![image-20220327141206776](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/6u126ec6u126ec.png)



#### **如何集成到GitHub的action呢？**

这个问题原作者其实已经解决了，但由于时间久远，原作者的项目一直没有更新，导致出现了一些问题。通过本地debug调试本人针对Java的部分ql规则进行改进解决问题，其主要诞生这些问题的所在均是codeql的库更新，原有的一些规则没了，更新到最新的规则即可。

![image-20220327141613701](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/13u1613ec13u1613ec.png)

本人已经将最新的Java部分的规则提交pr到原作者的项目，但截至写文章为止作者还没合并规则。建议使用我本人的项目[SummerSec/codeql-debug](https://github.com/SummerSec/codeql-debug)，如果在本地使用的话需要改一下process.py文件。

在56行将`dbpath`设置为**需要查询数据库绝对路径**，60行将`codeql_executable`设置为**codeql的执行文件的绝对路径**。

![image-20220327142148400](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/48u2148ec48u2148ec.png)

将129注释掉，将`qlf`变量设置为 **dependencies.ql的绝对路径**

![image-20220327142336152](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/36u2336ec36u2336ec.png)

运行设置参数第一个java 第二个和第三个由于设置成硬编码的方式，随便写就行。

![image-20220327142611394](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/11u2611ec11u2611ec.png)

---

集成到action就不需要改这些，在原本的action中添加这几行代码即可。完整的yml参考[codeql-debug.yml](https://github.com/SummerSec/SPATool/blob/main/.github/workflows/codeql-debug.yml)

![image-20220327142857104](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/57u2857ec57u2857ec.png)

这里的action触发方式采用的是手动触发，手动触发之后在执行结束之后可以在Summary下载结果。比例说本人在SPATool项目执行结果[Summary link](https://github.com/SummerSec/SPATool/actions/runs/2044595073)

![image-20220327143224242](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/24u3224ec24u3224ec.png)



---

### CodeQL with SCA 

突然看到楼兰师傅写的[**CodeQL 结合Maven实现SCA**](https://www.yuque.com/loulan-b47wt/rc30f7/ll3a4z)文章，这里给出我的解决方案，这里记录一下。**SCA Software Composition Analysis，软件成分分析，第三方组件安全检查。**

```ql
import java
import semmle.code.java.DependencyCounts

predicate jarDependencyCount(int total, string entity) {
  exists(JarFile targetJar, string jarStem |
    jarStem = targetJar.getStem() and
    jarStem != "rt"
  |
    total =
      sum(RefType r, RefType dep, int num |
        r.fromSource() and
        not dep.fromSource() and
        dep.getFile().getParentContainer*() = targetJar and
        numDepends(r, dep, num)
      |
        num
      ) and
    entity = jarStem
  )
}

from string name, int ndeps
where jarDependencyCount(ndeps, name)
select name, ndeps order by ndeps desc

```

运行下面命令就会得到`dependencies.bqrs`文件

```
codeql database run-queries --search-path  --threads 0 --rerun {database_path} {dependencies.ql}
```

在运行下面命令就会得到下面图片内容，输出格式有多种方式可选。

```
codeql bqrs decode --no-titles --format text --output dependencies.txt  dependencies.bqrs
```

![image-20220401135050399](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/57u5057ec57u5057ec.png)



---

### tricks

#### **First**

这条命令也是在CodeQL的action中学到，可以发现在一个完整的环境中，我们可以使用这条命令直接获取到类似上面的**java-queries-builtin.qls**文件，毕竟直接给出了绝对路径。

```
codeql resolve queries java-code-scanning.qls --format=text
```

![image-20220327143823075](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/23u3823ec23u3823ec.png)



---

#### second

codeql批量查询的方式，其实除了将所有的ql的绝对路径写入qls文件中，可以使用下面这种方式，这种方式是在codeql-debug中学到的。

qls文件里面写ql所在的文件夹，可以是相对的路径也可以是绝对路径。然后仅仅只需要将ql文件放入文件夹下面即可，codeql会自动递归搜索并执行查询该文件夹下面的所有ql文件。

![image-20220327151017356](https://cdn.jsdelivr.net/gh/SummerSec/Images/2022/03/17u1017ec17u1017ec.png)



---





### 参考

https://github.com/zbazztian/codeql-debug
