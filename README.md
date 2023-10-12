# 司稽

中文 | [English](https://github.com/enomothem/Whoamifuck/blob/main/README-EN.md) 

## Ax 介绍
<p>Whoamifuck（司稽，先秦时抓小偷滴官员），永恒之锋发布的第一款开源工具，这是一款由shell编写的检测入侵用户的工具，经过功能的更新，已经不仅限于检查用户的登入信息。</p>
<p>该工具目前实现的功能基本满足了应急响应的基本需求，后续将加入更多的入侵检测点，并完善代码。如有新的功能建议，可提issue，欢迎关注永恒之锋战队公众号。</p>
<p>为什么不使用python，因为python依赖多，版本差异大，shell原生支持，除个别少数shell语法不同，大部分unix，linux基本都支持bash shell。</p>

<p align="center"><img src="https://github.com/AppFlowy-IO/appflowy/blob/main/doc/imgs/howtostar.gif" alt="AppFlowy Github - how to star the repo" width="100%" /></p>

## Bx 版本
#### 更新信息

 * 2021年2月8日 发布whoamifuck2。
 * 2021年6月3日 优化格式，加入用户基本信息。
 * 2021年6月6日 发布3.0版本
 * | ...
 * 2022年6月3日 增加新功能，加入应急响应基础功能，如查看用户、服务、文件修改、历史命令等等。
 * 2022年6月6日 发布4.0版本
 * | ... 
 * 2023年6月3日 增加新功能，加入开放端口、优化服务器状态、查看僵尸进程、优化用户状态等。
 * 2023年6月6日 发布5.0版本
 * | ...
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
- [ ] 分析web日志
- [ ] 内存马查杀
- [ ] 挖矿病毒查杀
- [ ] 后门文件查杀
- [ ] 僵尸进程清理
- [ ] 开机自启动项
- [ ] 攻击痕迹发现
- [ ] 生成多格式报告 -> 客户看了直说好

## Cx 使用
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
	 -o --output			导出全量输出模式文件
```
![image](https://github.com/enomothem/Whoamifuck/assets/45089051/e52200c2-21ed-461a-b329-490e01aa8def)
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


## Dx 关注永恒之锋
<p align="center">
  <img src="https://lit.enomothem.com/zhixinghe/20220528141025.jfif">
</p>
