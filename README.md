# JSINFO-SCAN

### 前言

很早以前就想写一款对网站进行爬取，并且对网站中引入的JS进行信息搜集的一个工具，之前一直没有思路，因为对正则的熟悉程度没有到可以对js中的info进行匹配的地步，最近实验室的朋友写了一款工具：[JSFinder](https://github.com/Threezh1/JSFinder "JSFinder")，借用了他的思路，写了一款递归爬取域名(netloc/domain)，以及递归从JS中获取信息的工具。

### 思路

写这个工具主要有这么几个点：

- 如何爬取域名
- 如何爬取JS
- 如何从JS中获取信息

三个点的解决方案：

- 正则匹配href属性中的链接
- 正则匹配src属性中的链接，并判断链接是否为js。正则匹配`<script></script>`标签中的文本。
-   使用LinkFinder的正则从JS中匹配敏感信息

### 优点

- 实现递归爬取
- 对JS中匹配到的info进行了处理，直观的展示出来

### 缺点

使用的是单线程，因为目前多线程还没学够，如果冒昧使用担心引起数据混乱的问题，也并不熟悉使用Lock()函数，怕使用的地方多了，多线程也变成了单线程。

### Usage

```
python3 jsinfo.py -d jd.com --keyword jd --save jd.api.txt --savedomain jd.domain.txt
```

- -d/-f

对单个域名或对域名文件进行扫描，文件需要一行一个域名。

- --keyword

设置爬取关键字，会使用该关键字对域名进行匹配，必选项。

- --savedomain

设置爬取出来的域名保存路径

- --save

设置api保存路径

### 实例

- 对京东进行爬取

只爬取jd.com，设置keyword为jd,joybuy,360：

![enter image description here](https://s2.ax1x.com/2019/06/27/Zma4Tf.png)

- 对百度进行爬取

![enter image description here](https://s2.ax1x.com/2019/06/27/Zmablj.png)

### Update

2019-7-5：重构代码，加入了爬行深度的设定，深度为1~2，默认为1，2即为深度爬取，同时增加了url的存储，即深度爬取爬取到的链接。

2020-2-10：重构代码，整体使用了协程，使用队列的方式作为递归标准，默认递归深度为8，可根据自身需要进行修改。

效果：

![](https://s2.ax1x.com/2020/02/10/1ImiUe.md.jpg)

