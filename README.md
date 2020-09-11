# frida_ssl_logger
ssl_logger based on frida
for from https://github.com/google/ssl_logger

## 修改内容
1. 优化了frida的JS脚本，修复了在新版frida上的语法错误；
2. 调整JS脚本，使其适配iOS和macOS，同时也兼容了Android；
3. 增加了更多的选项，使其能在多种情况下使用；

## Usage
  ```shell
    python3 ./ssl_logger.py  -U -f com.bfc.mm
    python3 ./ssl_logger.py -v  -p test.pcap  6666
  ````


## Todo
1. 解决IP的问题;
2. ~~适配Windows~~;
