# reproducibleopeneuler
These tools are intended to make it easier to verify that the binaries resulting from openEuler builds are reproducible.

For this, we rebuild twice locally from source with variations in

* datetime
* hostname

within opensource libfaketime in Open Build Service(OBS),
unpack the differenc packages and compare the results using the build-compare script (diffoscope) that abstracts away some unavoidable (or unimportant) differences.

Steps:

1.install libfaketime：  
Download source https://github.com/opensourceways/reproducible-builds-libfaketime  
``make``  
``make install``  


2.To mock datetime and hostname, set the libfaketime environment  

```
echo 'export LD_PRELOAD=/usr/local/lib/faketime/libfaketimeMT.so.1' >> /etc/profile
echo 'export FAKETIME="2022-05-01 11:12:13"' >> /etc/profile
echo 'export FAKEHOSTNAME=fakename' >> /etc/profile
```

3.Solve the binary differences caused by time & random numbers in Python during the compilation of source packages  
```
echo 'export SOURCE_DATE_EPOCH=1' >> /etc/profile  
echo 'export PYTHONHASHSEED=0' >> /etc/profile  
```
4.使用OBS构建两次软件包 OBS rebuild packages twice locally from software source

4.使用unpacker工具解压两个软件包：
`python unpacker.py 第一个包的路径 第二个包的路径`
6.安装diffoscope : yum install diffoscope
解压结果输入diffoscope获取不一致对比:diffoscope 第一个文件路径 第二个文件路径 --html xxx.html
