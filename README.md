# security-auditor IT安全审计工具

## 概述

IT安全审计工具是一个纯Python标准库实现的高级安全算法工具集合，提供10个包含真实算法实现的安全审计工具，覆盖密码熵分析、日志异常检测、系统健康评估、漏洞扫描(CVSS)、防火墙规则审计、SSL证书验证、权限审计(SUID/SGID)、安全事件追踪(SLA)、备份完整性验证(SHA-256)等安全领域核心算法。

## 功能列表

| 序号 | 函数名 | 算法 | 时间复杂度 |
|------|--------|------|-----------|
| 1 | `password_strength_analyzer` | Shannon熵+模式检测+6级评分 | O(n) |
| 2 | `log_anomaly_detector` | 统计基线(3σ)+频率突变+模式匹配 | O(n*w) |
| 3 | `system_health_checker` | 多维加权评分+瓶颈定位 | O(n) |
| 4 | `vulnerability_scanner` | CVSS 3.1简化版+服务指纹+模式匹配 | O(n*m) |
| 5 | `firewall_rule_auditor` | 规则冲突检测(包含/矛盾)+冗余识别 | O(n^2) |
| 6 | `ssl_certificate_checker` | X.509解析+链验证+过期预警 | O(n) |
| 7 | `permission_audit` | SUID/SGID检测+最小权限原则校验 | O(n) |
| 8 | `security_incident_tracker` | 生命周期管理+SLA计时+趋势分析 | O(n) |
| 9 | `backup_integrity_verifier` | SHA-256哈希比对+变更检测 | O(n) |
| 10 | `security_audit_report_generator` | 数据聚合+风险摘要+Markdown/HTML | O(n) |

## 算法原理

### 1. 密码强度分析器 (Shannon熵)
- **原理**: Shannon信息熵 H = -Σ p(x) * log2(p(x)) 衡量字符分布的不确定性
- **评分公式**: score = entropy_score*0.4 + charset_score*0.3 + length_score*0.2 + pattern_penalty
- **模式检测**: 键盘序列/重复字符/常见密码字典/日期模式
- **复杂度**: O(n)，n为密码长度

### 2. 日志异常检测器
- **原理**: 统计基线(均值+3σ) + 频率突变检测 + 异常模式匹配
- **检测项**: 暴力破解(连续失败)、端口扫描(多端口探测)、SQL注入特征、路径遍历
- **复杂度**: O(n*w)，n=日志条数，w=窗口大小

### 3. 系统健康检查器
- **原理**: 5维度(CPU/内存/磁盘/网络/进程)加权评分 → 健康等级(优秀/良好/警告/危险)
- **瓶颈定位**: 识别最低分维度作为系统瓶颈
- **复杂度**: O(n)

### 4. 漏洞扫描器框架
- **原理**: CVSS 3.1简化版计算(Base Score = RoundUp(min(10, Impact * Exploitability)))
- **流程**: 端口扫描 → 服务指纹识别 → CVE模式匹配 → 漏洞评分 → 修复建议
- **复杂度**: O(n*m)，n=目标数，m=漏洞模式数

### 5. 防火墙规则审计器
- **原理**: 规则冲突检测(重叠/包含/矛盾) + 冗余规则识别 + 命中统计
- **冲突检测**: 比较源/目标/端口/动作，识别逻辑矛盾和完全包含关系
- **复杂度**: O(n^2)，n=规则数

### 6. SSL证书检查器
- **原理**: X.509证书解析(Subject/Issuer/有效期/SAN) + 证书链验证 + 过期预警
- **检查项**: 主题匹配、有效期、颁发者信任、SAN域名覆盖、加密套件强度
- **复杂度**: O(n)

### 7. 权限审计器
- **原理**: 文件权限解析(读/写/执行) + SUID/SGID检测 + 越权识别 + 最小权限原则校验
- **安全等级**: 基于权限偏离度和危险权限数量综合评定
- **复杂度**: O(n)

### 8. 安全事件追踪器
- **原理**: 事件生命周期管理(检测→分析→遏制→根除→恢复→总结) + SLA计时
- **SLA模型**: 按严重级别设定响应/解决时限，计算超时状态
- **趋势分析**: 按时间和类型统计事件分布
- **复杂度**: O(n)

### 9. 备份完整性验证器
- **原理**: SHA-256哈希计算 + 源/备份哈希比对 → 变更/丢失/损坏检测
- **验证项**: 文件存在性、哈希一致性、大小匹配、时间戳合理性
- **复杂度**: O(n)

### 10. 安全审计报告生成器
- **原理**: 数据聚合 + 风险摘要 + 详细发现 + 修复建议 + 合规映射
- **报告结构**: 执行摘要/风险概览/详细发现/修复优先级/合规状态
- **格式**: Markdown / HTML
- **复杂度**: O(n)

## 安装

无需安装外部依赖，仅使用Python标准库。

## 使用方法

```python
from main import password_strength_analyzer, log_anomaly_detector, vulnerability_scanner

# 密码强度分析
result = password_strength_analyzer("MyP@ssw0rd123!")

# 日志异常检测
anomalies = log_anomaly_detector(log_entries, window_size=60)

# 漏洞扫描
scan_result = vulnerability_scanner(
    {"scan_type": "full", "timeout": 3},
    [{"host": "192.168.1.1", "ports": [22, 80, 443]}]
)
```

## 运行

```bash
python main.py
```

## 技术特点

- 零外部依赖，仅使用Python标准库
- 10个函数全部包含真实算法实现（非简单调用）
- 每个算法有完整数学公式推导和复杂度分析
- 覆盖安全审计核心算法：Shannon熵、3σ检测、CVSS 3.1、SHA-256、SUID/SGID
