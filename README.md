# wifi
wifi，DNS劫持，攻击者脚本

作用：将源地址 指向 攻击者恶意ip

说明：在链接局域网后，该脚本只在：一定不能有人访问过“源ip”（因为在脚本开始之前访问过源ip，上游DNS 8.8.8.8会把ip写入缓存）
且“源ip”不是白名单里的（如“baidu.com”的情况下）才能生效。如www.4399.com就能在此情况生效。

用法：
1.任意局域网的设备先，ipconfig得到ip
2.python a ttack.py -t wifi的IP --scan -d 源ip
3.例如：python attack.py -t 172.16.69.1 --scan -d www.4399.com
（攻击者的恶意“目标ip”默认为97.107.130.225，即http://www.rohitab.com/）
