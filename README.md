# reproducibleopeneuler
These tools are intended to make it easier to verify that the binaries resulting from openEuler builds are reproducible.

For this, we rebuild twice locally from source with variations in

* datetime
* hostname

within opensource libfaketime in Open Build Service(OBS),
unpack the differenc packages and compare the results using the build-compare script (diffoscope) that abstracts away some unavoidable (or unimportant) differences.

Steps:

1.install libfaketime：  
Download libfaketime source https://github.com/opensourceways/reproducible-builds-libfaketime  
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
4.OBS rebuild packages twice locally from software source

5.Unpack your two packages using the unpacker.py tool  
`python unpacker.py ${first package path} ${second package path}`  
6.Display differences using diffoscope : 
```
yum install diffoscope  
diffoscope ${first file path} ${second file path} --html diff.html
```

