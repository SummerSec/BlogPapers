# CodeQL初见Shiro550
## 前言 

看到p牛师傅的文章[CommonsBeanutils与无commons-collections的Shiro反序列化利用](https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html)决定好好研究一下CommonsBeanutils反序列化漏洞。p牛将shiro此gadget改造成了无需依赖第三方组件，凭借shiro自带CommonsBeanutls将shiro的反序列化漏洞利用来到了一个新的高点。

本文思路都是基于在p牛原思路的进一步的探索和衍生，本质还是基于p牛提出的想法。

所有源码环境都会上传https://github.com/SummerSec/JavaLearnVulnerability



----

## Shiro550--真的会玩吗？



先抛出一个问题，你已知的shiro550利用方式有哪些？利用思路有哪些？

Shiro550已知利用方式：

* 有依赖

    * Commons-Collections反序列化组件

    * Commons-Beanutils反序列化组件

        ........

        

- 无依赖
    - 利用Shiro自带Commons-Beantils依赖（P牛）
- 利用Tomcat或Spring回显结果
- 注入内存马



在P牛之前发现无依赖利用之前，大家基本上都是使用ysoserial中CommonsCollections、CommonsBeanutils等gadget链。但这也带了一个问题，如果shiro没有添加第三方依赖怎么办？是不是就只能放弃？

个人觉得P牛的思路完全为Shiro550反序列化漏洞利用方式留下浓厚的一笔，但我觉得原不应该不应该局限与此。本文篇幅有限，只讨论无依赖的利用方式。无依赖指的是仅仅使用Shiro本身的所依赖的组件或JDK，而达到触发反序列化漏洞的目的。



---

## CommonsBenutils反序列化漏洞



### CommonsBeanutils Gadget分析

首先`TemplateImpl`类不难发现在Commons-collections4.0版本的反序列化漏洞都用到了这个类，前期大致流程都是差不多，如果不熟悉可以学习笔者之前写的[漫谈Commons-Collections反序列化](https://summersec.github.io/2020/05/26/%E6%BC%AB%E8%B0%88Commons-Collections%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/) 第二部分。

![image-20210609155556389](https://img.sumsec.me/summersec//56u55er56ec/56u55er56ec.png)

`PriorityQueue`调用`siftDownUsingComparator`方法的669行之后会调用`BeanComparator`类的`Compare`方法

![image-20210609162051136](https://img.sumsec.me/summersec//51u20er51ec/51u20er51ec.png)

这里的`property`通过反射修改了`outputProperties`，之后会调用**PropertyUtils.getProperty(o1, this.property)**

![image-20210609162106968](https://img.sumsec.me/summersec//7u21er7ec/7u21er7ec.png)

这里首先会得到一个`PropertyUtilsBean`的实例，然后调用`getProperty`方法，获取属性。

![image-20210609163254880](https://img.sumsec.me/summersec//54u32er54ec/54u32er54ec.png)

接下去是调用`getNestedProperty`方法，然后进行一系列的JavaBean判断之后调用`getSimpleProperty`方法。

![image-20210609163419984](https://img.sumsec.me/summersec//20u34er20ec/20u34er20ec.png)

![image-20210609163816013](https://img.sumsec.me/summersec//16u38er16ec/16u38er16ec.png)

首先还是进行判断之后调用`getPropertyDescriptor`方法，在这里很明显会获取恶意的`TemplatesImpl`对象

![image-20210609164452646](https://img.sumsec.me/summersec//52u44er52ec/52u44er52ec.png)

在方法结束之后返回`PropertyDescriptor`对象，会获取方法（反射调用）然后最终触发漏洞。

![image-20210609164728186](https://img.sumsec.me/summersec//28u47er28ec/28u47er28ec.png)





---

### 总结



```
/*
	Gadget chain:
		PriorityQueue.readObject()
			PriorityQueue.heapify()
				PriorityQueue.siftDown()
					PriorityQueue.siftDownUsingComparator()
						BeanComparator.compare()
							PriorityUtilsBean.getProperty()
								PriorityUtilsBean.getNestedProperty()
									PriorityUtilsBean.getSimpleProperty()
										PriorityUtilsBean.getPropertyDescriptor()
										------ 

	Requires:
		commons-beanutils1.9.2
 */
```

在Commons-Beanutils中`BeanComparetor`是实现了`Serialable`接口和`Compare`接口，在比较方法里面调用`PriorityUtilsBean#getProperty`方法获取属性，获取的过程中会将Bean对象(TemplatesImpl恶意对象)实例化，在调用`getPropertyDescriptor`时获取属性的描述触发反序列化漏洞。



----

## Shiro550无依赖利用分析

在文章[CommonsBeanutils与无commons-collections的Shiro反序列化利用](https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html#)（下文原文即指此文）给出了无依赖的解决方案，找到一个替代`ComparableComparator`类，当然这也不是随便找的。P牛给出了替代类所需要的条件：

* 实现`java.util.Comparator`接口
* 实现`java.io.Serializable`接口
* Java、shiro或commons-beanutils自带，且兼容性强

在文章中p牛使用IDEA自带的功能去找了，当我去复现的时候发现这种方式其实是有点效率低下，搞不好会遗落或者完全找不到。这里我使用的环境是[JavaLearnVulnerability](https://github.com/SummerSec/JavaLearnVulnerability)/[shiro](https://github.com/SummerSec/JavaLearnVulnerability/tree/master/shiro)/**shiro-deser**/结果大概是有200+，当然不完全都是shiro自带的依赖，当然原文中也有100+。

![image-20210613164632858](https://img.sumsec.me/summersec//33u46er33ec/33u46er33ec.png)

这种方式满足了第二和第三个条件，无法满足第一个条件。IDEA是支持导出查询结果，我当时想到是找到`Comparator`接口实现类和`Serializable`接口实现类，导出结果在去用工具合并对比。当时没有想到工具可以处理，自己写脚本处理？

![在这里插入图片描述](https://img.sumsec.me/summersec//34u12er34ec/34u12er34ec.png)



----

## CodeQL初见

当时的我抛弃了上面我提出的两种方式，使用CodeQL语言去查询结果 。CodeQL代码，查询的结果如下：



![image-20210613165637032](https://img.sumsec.me/summersec//37u56er37ec/37u56er37ec.png)



![image-20210613170425194](https://img.sumsec.me/summersec//25u04er25ec/25u04er25ec.png)







---

### CodeQL简单介绍

CodeQL是一个分析引擎，被开发人员用来自动进行安全检查，也被安全研究人员用来进行变体分析。

在CodeQL中，代码被当作数据处理。安全漏洞、缺陷和其他错误被建模为查询，可以针对从代码中提取的数据库执行。你可以运行由GitHub研究人员和社区贡献者编写的标准CodeQL查询，或编写你自己的查询，用于自定义分析。找到潜在漏洞的查询会直接在源文件中突出显示结果。

上面两段话是GitHub官方对CodeQL的定义。CodeQL采用的是类似于SQL语句方式去查询数据库中代码，将符合的代码显示。在上面就不能发现，CodeQL简单几行代码将之前那么多结果挑选完毕准确无误。这种查询式代码审计真的特别舒服，规则一次性编写多次运行。关键是他开源的，还有很多人在维护，背靠GitHub官方。CodeQL最早提出是在2007年，2019年CodeQL逐渐发展，越来越火。

这里推荐个人开源学习的项目[learning-codeql](https://github.com/SummerSec/learning-codeql)，项目里面收集了大量的资料。



---

鉴于篇幅不易过长，下篇文章将详细说一下CodeQL在挖掘gadget的实践，提出个人对shiro550漏洞应该怎么玩明白的理解。

未完待续......



----

## 参考

https://blog.csdn.net/blueheart20/article/details/80363870

https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html#



