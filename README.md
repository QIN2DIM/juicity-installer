# Juicy <a href = "https://t.me/+9HKsbFCuY4U3NmQx"><img src="https://img.shields.io/static/v1?style=social&logo=telegram&label=chat&message=studio" ></a>

Juicy 用于快速部署 [Juicity-server](https://github.com/juicity/juicity) 并输出客户端最佳实践配置。只需 15s 即可完成全自动部署，开箱即用！

## Prerequisites

- Python3.6+

  常见的操作系统镜像自带 Python3，如：
  
  | OS Release       | Default Python version    |
  | ---------------- | ------------------------- |
  | Ubuntu 18.04     | Python 3.6                |
  | Debian 10        | Python 3.7                |
  | Fedora 28        | Python 3.6                |
  | openSUSE Leap 15 | Python 3.6                |
  | Arch Linux       | Python 3.7                |
  | Kali Linux       | Python 2.7 and Python 3.6 |
  | Alpine Linux     | Python 2.7 and Python 3.6 |
  | CentOS 8         | Python 3.6                |
- 在管理员权限下运行
- 提前为你的服务器解析一个域名 A 纪录

## Get started

> 首次安装完毕后，你可以通过别名指令 `juicy` 调度脚本。

1. **One-Click deployment**

   在交互式引导下完成部署。脚本会在任务结束后打印代理客户端配置。
   ```shell
   python3 <(curl -fsSL https://ros.services/juicy.py) install
   ```

   也可以直接指定域名参数「一步到胃」：

   ```shell
   python3 <(curl -fsSL https://ros.services/juicy.py) install -d YOUR_DOMAIN
   ```

2. **Remove loads**

   这个指令会移除与 `juicity-server` 有关的一切依赖。需要注意的是，你必须指明与 `juicity-server` 绑定的域名才能安全卸载证书。
   
   ```shell
   python3 <(curl -fsSL https://ros.services/juicy.py) remove
   ```

3. **Next steps**

   查看 [项目 WiKi](https://github.com/QIN2DIM/juicity-installer/wiki/Usage) 以获取完整的技术文档🐧
