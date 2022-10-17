# reproducibleopeneuler
These tools are intended to make it easier to verify that the binaries resulting from openEuler builds are reproducible.

For this, we rebuild twice locally from source with variations in

* datetime
* hostname

within opensource libfaketime in Open Build Service(OBS),
unpack the differenc packages and compare the results using the build-compare script (diffoscope) that abstracts away some unavoidable (or unimportant) differences.

Steps:

1.安装libfaketime：https://github.com/opensourceways/reproducible-builds-libfaketime

2.设置libfaketime参数，打桩datetime和hostname

```
echo 'export LD_PRELOAD=/usr/local/lib/faketime/libfaketimeMT.so.1' >> /etc/profile
echo 'export FAKETIME="2022-05-01 11:12:13"' >> /etc/profile
echo 'export SOURCE_DATE_EPOCH=1' >> /etc/profile
echo 'export PYTHONHASHSEED=0' >> /etc/profile
echo 'export FAKEHOSTNAME=fakename' >> /etc/profile
```
3.使用OBS构建两次软件包 OBS rebuild packages twice locally from software source

4.checksum256比较两个软件包是否一致

5.如果两次构建软件包checksum256不一致，使用unpacker工具解压两个软件包：unpacker.py
6.解压结果输入diffoscope获取不一致对比
