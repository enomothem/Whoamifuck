# Whoamifuck

中文 | English 

## Ax Introduction
<p>Eonian Sharp发布的第一款开源工具，这是一款由shell编写的检测入侵用户的工具，经过功能的更新，已经不仅限于检查用户的登入信息。</p>
<p>该工具目前实现的功能基本满足了应急响应的基本需求，后续将加入更多的入侵检测点，并完善代码。</p>


## Bx Version
#### Update
 * 2021年2月8日 发布whoamifuck2。
 * 2021年6月3日 优化格式。
 * 2021年6月6日 whoamifuck3，加入用户基本信息。
 * 2022年6月3日 增加新功能
 * 2022年6月6日 发布4.0版本

#### TODO

✔ 系统版本信息 <br>
✔ 历史命令信息 <br>
✔ 开启服务信息 <br>
✔ 进程分析信息 <br>
✔ 用户信息排查 <br>
✔ 文件状态信息 <br>
✔ 计划任务信息 <br>

## Cx Usage
### 下载
```
git clone https://github.com/enomothem/Whoamifuck.git
cd Whoamifuck
chmod +x whoamifuck.sh
```
### 使用方法
```
usage:  

	 -v              版本信息
 	 -h              帮助指南
	 -f [filepath]   选择需要查看用户信息的文件，默认文件: /var/log/auth.log
	 -n              基本信息输出
	 -u              查看设备基本信息
	 -a              检查用户进程与开启服务状态

```
![](https://lit.enomothem.com/zhixinghe/20220528141024.jfif)

## Cx About ES
![](https://lit.enomothem.com/zhixinghe/20220528141025.jfif)
