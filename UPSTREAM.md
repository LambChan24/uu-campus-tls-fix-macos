# 来源与致谢

本项目参考以下开源项目的 TLS ClientHello record 拆分思路及备用服务端端点，
使用 Python 标准库实现适用于本案例的本机适配器，不是上游官方 macOS 发行版。

- https://github.com/yunyancuo/campus-tls-fix
  - 排障时审阅 commit：`09051ef94452140a403295168ee38db4be463783`
  - MIT；许可保留在 `third_party/campus-tls-fix-LICENSE.txt`
- https://github.com/Earth3Dragon/uu-remote-tls-fix-portable
  - 排障时审阅 commit：`c251aa36d3fe2526dc28af13f651c557325f2b82`
  - MIT；许可保留在 `third_party/uu-remote-tls-fix-portable-LICENSE.txt`
  - 其许可同时注明原项目 https://github.com/yunyancuo/uu-remote-tls-fix

没有运行上游 Windows 安装器，也没有移植全局 hosts、LAN DNS、明文 HTTP 升级、
所有接口监听或绕过证书校验的分支。

备用端点只经特定日期的原域名证书/握手测试，不保证持续可用。
