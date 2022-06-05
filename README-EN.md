# Whoamifuck

[中文](https://github.com/enomothem/Whoamifuck) | English 

## Ax Introduction
<p>Whoamifuck，Eonian sharp's first open source tool. This is a tool written by shell to detect intruders, after the function update, is not limited to checking users' login information.</p>
<p>The current functions of the tool basically meet the basic needs of emergency response, and more intrusion detection points will be added in the future and the code will be improved.</p>


## Bx Version
#### update

 * February 8, 2021 Release whoamifuck2.
 * June 3, 2021 Format to optimize.
 * June 6, 2021 Whoamifuck3, add user basic information.
 * June 3, 2022 New features added.
 * June 6, 2022 Release whoamifuck4.0.

#### TODO

- [x] System Version information
- [x] History Command `history` Information
- [x] Enabling Service Information
- [x] Process analysis information
- [x] User Information Verification
- [x] File Status information
- [x] Scheduled Task `crontab` Information

## Cx Usage
### Download
```
git clone https://github.com/enomothem/Whoamifuck.git
cd Whoamifuck
chmod +x whoamifuck.sh
```
### Usage
```
usage:  

	 -v --version			show version.
 	 -h --help			show help guide.
	 -f --file [filepath]		select file path, Default file: /var/log/auth.log
	 -n --nomal			nomal show.
	 -a --process-and-service	check service and process information.
	 -u --user-device		check device information.

```
![](https://lit.enomothem.com/zhixinghe/20220605001102.png)

## Cx About Eonian Sharp
<p align="center">
  <img src="https://lit.enomothem.com/zhixinghe/20220528141025.jfif">
</p>
