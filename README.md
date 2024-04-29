中文 | [English](https://github.com/enomothem/Whoamifuck/blob/main/README-EN.md) 

# 司稽
> [!note]
> **司稽，察留连不时去者** ——《周礼·司稽》  
> 司稽作为地官的属官，其职责就是确保市场的正常运行和人员的有序流动，对于那些违反规定、扰乱市场秩序的行为进行及时的制止和处罚。

> [!warning]
> 工具仅作为辅助，仅作为攻防技术学习交流，不可用于非法用途。下载则代表同意。

## ES_T0001 介绍
<p>Whoamifuck（司稽，先秦时抓小偷滴官员），永恒之锋发布的第一款开源工具，这是一款由shell编写的检测入侵用户的工具，经过功能的更新，已经不仅限于检查用户的登入信息。</p>
<p>该工具目前实现的功能基本满足了应急响应的基本需求，后续将加入更多的入侵检测点，并完善代码。如有新的功能建议，可提issue，欢迎关注永恒之锋战队公众号。</p>
<p>为什么不使用python，因为python依赖多，版本差异大，shell原生支持，除个别少数shell语法不同，大部分unix，linux基本都支持bash shell。</p>

> [!tip]
> 凡是bug提交者，赋予漏洞编号，并在github更新追加贡献者</p>

<p align="center"><img src="https://github.com/AppFlowy-IO/appflowy/blob/main/doc/imgs/howtostar.gif" alt="AppFlowy Github - how to star the repo" width="100%" /></p>

## ES_T0002 版本
#### 更新信息

 * 2021年2月8日 发布whoamifuck2。
 * 2021年6月3日 优化格式，加入用户基本信息。
 * 2021年6月6日 发布3.0版本
 * |       ...
 * 2022年6月3日 增加新功能，加入应急响应基础功能，如查看用户、服务、文件修改、历史命令等等。
 * 2022年6月6日 发布4.0版本
 * |       ... 
 * 2023年6月3日 增加新功能，加入开放端口、优化服务器状态、查看僵尸进程、优化用户状态等。
 * 2023年6月6日 发布5.0版本
 * |       ...
 * 2024年某月某日 敬请期待 ...

#### 待实现

- [x] 系统版本信息
- [x] 历史命令信息
- [x] 开启服务信息
- [x] 进程分析信息
- [x] 用户信息排查
- [x] 文件状态信息
- [x] 计划任务信息
- [x] 开启端口信息
- [x] 系统状态监控
- [x] 分析web日志
- [x] 支持基线检查
- [ ] 内存马查杀
- [ ] 挖矿病毒查杀
- [x] 查找webshell
- [x] 常见漏洞自查
- [ ] 后门文件查杀
- [x] 僵尸进程清理
- [x] 站点存活探测
- [x] 开机自启动项
- [x] 攻击痕迹发现
- [x] 生成多格式报告 -> 客户看了直说好

## ES_T0003 使用
### 下载
```
git clone https://github.com/enomothem/Whoamifuck.git
cd Whoamifuck
chmod +x whoamifuck.sh
```
### 使用方法
```
usage:  

	 -v --version			版本信息
 	 -h --help			帮助指南
	 -l --login [FILEPATH]		用户登录信息
	 -n --nomal			基本输出模式
	 -a --all			全量输出模式
	 -u --user-device		查看设备基本信息
	 -x --process-and-servic	检查用户进程与开启服务状态
	 -p --port			查看端口开放状态
	 -s --os-status			查看系统状态信息
	 -w --webshell [PATH]		查找可能存在的webshell文件
	 -r --risk			查看系统可能存在的漏洞
	 -b --baseline			基线安全评估
	 -o --output [FILENAME]		导出全量输出模式文件
```
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/2a291854-2efa-485c-bd75-fe71a56d5b65)

### 关于用户登录排查的优化
使用 `-l` 参数显示系统的用户登录信息。
该参数取代之前`-f`参数，对比`-f`，优化了以下功能：
1. 首先判断是否存在文件参数，能够在当前系统分析不同系统的文件类型。如用户指定了具体的文件路径，那么将分析文件名是auth.log还是secure，请注意从其它系统导出的日志文件名是否正确。
2. 用户没有指定具体的文件，那么会判断操作系统是红帽系还是debian系，如果是红帽系的系统则使用secure默认路径，debian系列则使用auth.log文件默认路径。
3. 如果用户没有指定具体的文件，系统也没有识别正确，如遇到阉割版的操作系统，则默认使用红帽系列的判断方法执行，则可指定具体文件的方法。
```
./whoamifuck -l
```
会列举出攻击次数的攻击者枚举的用户名、攻击者IP TOP10、成功登录的IP地址和对用户名进行爆破的次数

![image](https://github.com/enomothem/Whoamifuck/assets/45089051/7b13f4d2-d063-4b4d-9399-5b06408e99ff)

![image](https://github.com/enomothem/Whoamifuck/assets/45089051/ae0d0d63-d300-4eb5-9e88-6395de5542a2)
### 系统基本信息的优化
相比之前，优化了一些信息的突出，更加美观，增加了虚拟机判断，时间戳，用于取证中进行定位时间线和设备类型。
```
./whoamifuck -u
```
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/6917bb8d-ccf0-4c6a-a7a3-bb84e9e745ee)

![image](https://github.com/enomothem/Whoamifuck/assets/45089051/188fdd50-5523-42ad-8bd2-486b55a72e95)

### 增加对Root用户的判断
该程序需要root权限才能获取较为完整的信息，否则会发生一些未预期的错误，所以增加了对root的判断，保证程序的可用性。

![image](https://github.com/enomothem/Whoamifuck/assets/45089051/dbbf9a7f-74b1-4df6-8aff-30810b0a6d5a)

### 新特性🎉：webshell查杀
增加了对webshell的查杀，目前仅支持PHP和JSP。
使用方法：
1. 不指定目录，默认查找常见的web根目录。
```
./whoamifuck -w
```
2. 指定路径，深度查找指定的目录，力度更大。
```
./whoamifuck -w /root
```
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/16d2bbed-66c7-4983-bba7-d56ea7b86235)
### 新特性🎉：漏洞检测
使用漏洞检测模块`-r/--risk`
```shell
./whoamifuck -r
```
增加了漏洞检测模块，目前只支持了redis的检测
未授权则表示未开启密码机制，当然实际情况还需判断，仅作为参考。
如开启密码机制，会将找到的密码与弱口令字典TOP20进行匹配，如找到则显示出来，反正显示`*****`，该模块不记录在log中。
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/68e41b96-a5a3-40f7-bc61-43a5ec00a19e)

### 重构代码结构，执行速度加快4000倍🎿
由于功能的增加，变量变多，程序执行速度明显变慢，将变量按需求移入函数中，执行速度更加流畅！
优化前
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/e93fee42-0a0c-4634-9454-d0fe17de684d)
优化后
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/fe88780d-7c51-466b-9f90-8b43a49c753c)

### 新特性🎉：Html格式输出，呕心沥血几百次优化，细节感人，人性化体验，简洁舒服
在shell中查看文本文件非常的困难，导致分析过程不利于用眼的保护，所以更新了html的格式。

看这简洁明了的设计
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/416dec83-51ad-4941-bbca-f749559ec609)
钛合金金属的豪华按钮+突出的计数器
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/e7717a47-d067-4270-8809-abd196183d7b)

### 新特性🎉：~~站点扫描~~ 站点存活分析
大家可能第一反应把这当作攻击方的工具，那可大错，在应急过程中，免不了检测网页是否存在或存活状态，再配合端口检测，可查看页面的开启状态。
```
whoamifuck -p # 先查看是否存在http server端口
```
然后检测页面情况
```
whomifuck -c # 检测
```
当然，为了批量操作，也可以指定文件，这里演示检测永恒之锋实验室官方和我的博客。
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/c03294a5-9acb-41b7-b5bd-7f3207a73b94)


### 新特性🎉：日志分析-SQL注入专业分析
sql注入分析起来非常的繁琐，索性直接自动化，而且做CTF题目也是非常的给力哦~  
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/f6168455-f520-4d9a-bf59-4a505ae411af)


## ES_T0004 关注永恒之锋
<p align="center">
  <img src="https://lit.enomothem.com/zhixinghe/20220528141025.jfif">
</p>
