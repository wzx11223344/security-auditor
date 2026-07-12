# security-auditor IT安全审计工具

## 概述

IT安全审计工具是一个纯Python标准库实现的安全工具集合，提供10个工具来辅助IT运维和安全审计工作。

## 功能列表

| 序号 | 函数名 | 功能说明 |
|------|--------|----------|
| 1 | `password_strength_checker` | 密码强度检测（长度/复杂度/常见密码库） |
| 2 | `log_analyzer` | 日志分析器 |
| 3 | `system_health_checker` | 系统健康检查（CPU/内存/磁盘/网络） |
| 4 | `vulnerability_scanner` | 漏洞扫描框架 |
| 5 | `firewall_rule_auditor` | 防火墙规则审计 |
| 6 | `ssl_certificate_checker` | SSL证书检查 |
| 7 | `permission_auditor` | 权限审计 |
| 8 | `security_report_generator` | 安全报告生成 |
| 9 | `incident_response_tracker` | 事件响应追踪 |
| 10 | `backup_verifier` | 备份验证器 |

## 安装

无需安装外部依赖，仅使用Python标准库。

## 使用方法

```python
from main import password_strength_checker, system_health_checker, ssl_certificate_checker

# 密码强度检测
result = password_strength_checker("MyP@ssw0rd123")

# 系统健康检查
health = system_health_checker(["cpu", "disk", "network"])

# SSL证书检查
cert = ssl_certificate_checker("www.example.com")
```

## 运行

```bash
python main.py
```

## 技术特点

- 零外部依赖，仅使用Python标准库
- 所有函数均有详细的中文docstring
- 支持文本/JSON/Markdown三种报告格式
- 内置常见弱密码库和已知漏洞模式
- 正则表达式驱动的日志分析
- 基于socket的端口扫描和SSL证书检查
