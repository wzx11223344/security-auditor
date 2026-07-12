#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IT安全审计工具 - security-auditor
提供10个高级安全算法工具：密码强度分析(Shannon熵)、日志异常检测(3σ+模式匹配)、
系统健康检查(多维加权评分)、漏洞扫描器框架(CVSS)、防火墙规则审计(冲突检测)、
SSL证书检查、权限审计(SUID/SGID)、安全事件追踪(SLA)、备份完整性验证(SHA-256)、
安全审计报告生成器。

全部使用Python标准库实现，无外部依赖。
"""

import hashlib
import json
import math
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# 1. 密码强度分析器 (Shannon熵)
# ---------------------------------------------------------------------------
def password_strength_analyzer(password):
    """
    密码强度分析器：基于Shannon熵+模式检测的0-100评分系统。

    算法原理:
        - Shannon熵: H = -Σ p(x) * log2(p(x))，衡量字符分布的不确定性
        - 字符集大小: 大小写+数字+特殊字符的组合丰富度
        - 模式检测: 键盘序列/重复字符/常见密码字典/日期模式
        - 评分公式: score = entropy_score*0.4 + charset_score*0.3 + length_score*0.2 + pattern_penalty

    参数:
        password (str): 待分析的密码

    返回:
        dict: 密码分析结果，含score、strength_level、entropy、issues、recommendations。
    """
    if not password:
        return {"score": 0, "strength_level": "极弱", "issues": ["密码为空"]}

    length = len(password)
    char_counts = Counter(password)
    total_chars = len(password)

    # 步骤1: 计算Shannon熵
    entropy = 0.0
    for count in char_counts.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * math.log2(p)

    # 步骤2: 字符集分析
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32

    # 步骤3: 模式检测
    issues = []

    # 键盘序列检测
    keyboard_sequences = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "qazwsx", "edcrfv"
    ]
    pwd_lower = password.lower()
    for seq in keyboard_sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in pwd_lower:
                issues.append(f"检测到键盘序列: '{seq[i:i+3]}'")
                break

    # 重复字符检测
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            issues.append(f"检测到重复字符: '{password[i]}' 连续出现3次以上")
            break

    # 常见密码检测
    common_passwords = [
        "password", "123456", "abc123", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "login", "123456789"
    ]
    if pwd_lower in common_passwords:
        issues.append("该密码在常见密码字典中，极易被破解")

    # 日期模式检测
    if re.search(r'(19|20)\d{2}', password):
        issues.append("检测到年份模式，可能被字典攻击猜中")

    # 连续数字检测
    for i in range(len(password) - 2):
        if password[i].isdigit() and password[i+1].isdigit() and password[i+2].isdigit():
            d1, d2, d3 = int(password[i]), int(password[i+1]), int(password[i+2])
            if d2 == d1 + 1 and d3 == d2 + 1:
                issues.append("检测到连续递增数字序列")
                break

    # 步骤4: 评分计算
    # 熵评分 (0-100): 熵值0-6映射到0-100
    entropy_score = min(entropy / 6.0 * 100, 100)

    # 字符集评分
    charset_score = min(charset_size / 94 * 100, 100)  # 94为最大可打印ASCII字符集

    # 长度评分
    if length < 6:
        length_score = length / 6 * 30
    elif length < 8:
        length_score = 30 + (length - 6) / 2 * 20
    elif length < 12:
        length_score = 50 + (length - 8) / 4 * 30
    else:
        length_score = min(80 + (length - 12) * 2, 100)

    # 模式惩罚
    pattern_penalty = len(issues) * 10

    # 综合评分
    total_score = (entropy_score * 0.4 + charset_score * 0.3 + length_score * 0.2 +
                   (100 if not issues else 80) * 0.1 - pattern_penalty)
    total_score = max(0, min(100, total_score))

    # 步骤5: 强度等级
    if total_score >= 85:
        strength_level = "极强"
    elif total_score >= 70:
        strength_level = "强"
    elif total_score >= 55:
        strength_level = "中等"
    elif total_score >= 35:
        strength_level = "弱"
    else:
        strength_level = "极弱"

    # 建议
    recommendations = []
    if length < 12:
        recommendations.append("建议密码长度不少于12位")
    if not has_upper:
        recommendations.append("建议添加大写字母")
    if not has_lower:
        recommendations.append("建议添加小写字母")
    if not has_digit:
        recommendations.append("建议添加数字")
    if not has_special:
        recommendations.append("建议添加特殊字符")
    if issues:
        recommendations.append("避免使用键盘序列、重复字符和常见密码")

    # 破解时间估算 (假设每秒10亿次猜测)
    if charset_size > 0:
        combinations = charset_size ** length
        guesses_per_second = 10**9
        crack_time_seconds = combinations / (2 * guesses_per_second)
        if crack_time_seconds < 1:
            crack_time = "即时破解"
        elif crack_time_seconds < 60:
            crack_time = f"{crack_time_seconds:.0f}秒"
        elif crack_time_seconds < 3600:
            crack_time = f"{crack_time_seconds/60:.0f}分钟"
        elif crack_time_seconds < 86400:
            crack_time = f"{crack_time_seconds/3600:.1f}小时"
        elif crack_time_seconds < 31536000:
            crack_time = f"{crack_time_seconds/86400:.0f}天"
        else:
            years = crack_time_seconds / 31536000
            if years > 10**9:
                crack_time = "数十亿年以上"
            elif years > 10**6:
                crack_time = f"{years/10**6:.0f}百万年"
            elif years > 1000:
                crack_time = f"{years/1000:.0f}千年"
            else:
                crack_time = f"{years:.0f}年"
    else:
        crack_time = "未知"

    return {
        "score": round(total_score, 1),
        "strength_level": strength_level,
        "entropy": round(entropy, 2),
        "charset_size": charset_size,
        "length": length,
        "character_types": {
            "lowercase": has_lower, "uppercase": has_upper,
            "digits": has_digit, "special": has_special
        },
        "issues": issues,
        "estimated_crack_time": crack_time,
        "recommendations": recommendations
    }


# ---------------------------------------------------------------------------
# 2. 日志异常检测器 (3σ + 模式匹配)
# ---------------------------------------------------------------------------
def log_anomaly_detector(log_entries, window_size=60):
    """
    日志异常检测器：基于统计基线+频率突变+模式匹配的异常检测。

    算法原理:
        - 统计基线: 计算窗口内日志频率的均值和标准差，3σ规则识别异常
        - 频率突变: 相邻窗口频率变化超过阈值视为突变
        - 模式匹配: 检测暴力破解/端口扫描/SQL注入等特征模式
        - 时间序列分析: 按窗口分组统计日志频率

    参数:
        log_entries (list[dict]): 日志条目列表，每条含timestamp, event_type, source_ip, message
        window_size (int): 时间窗口大小（秒），默认60

    返回:
        dict: 异常检测结果，含anomalies、statistics、patterns_detected。
    """
    if not log_entries:
        return {"anomalies": [], "statistics": {}, "patterns_detected": []}

    # 步骤1: 按时间窗口分组
    # 假设timestamp为Unix时间戳字符串
    window_counts = defaultdict(lambda: {"total": 0, "by_ip": defaultdict(int), "by_type": defaultdict(int)})
    window_times = []

    for entry in log_entries:
        try:
            ts = int(entry.get("timestamp", 0))
        except (ValueError, TypeError):
            ts = 0
        window_key = ts // window_size
        window_counts[window_key]["total"] += 1
        window_counts[window_key]["by_ip"][entry.get("source_ip", "unknown")] += 1
        window_counts[window_key]["by_type"][entry.get("event_type", "unknown")] += 1
        if window_key not in window_times:
            window_times.append(window_key)

    window_times.sort()

    # 步骤2: 统计基线（3σ规则）
    totals = [window_counts[w]["total"] for w in window_times]
    n = len(totals)
    if n < 2:
        mean = totals[0] if totals else 0
        std = 0
    else:
        mean = sum(totals) / n
        variance = sum((x - mean) ** 2 for x in totals) / n
        std = math.sqrt(variance)

    # 步骤3: 异常检测
    anomalies = []

    # 3σ异常
    for w in window_times:
        count = window_counts[w]["total"]
        if std > 0 and abs(count - mean) > 3 * std:
            anomalies.append({
                "type": "频率异常",
                "window": w,
                "count": count,
                "expected": round(mean, 1),
                "deviation": round(abs(count - mean) / std, 2),
                "sigma": "高" if count > mean else "低",
                "severity": "高" if abs(count - mean) > 4 * std else "中"
            })

    # 频率突变检测
    for i in range(1, len(window_times)):
        prev_count = window_counts[window_times[i-1]]["total"]
        curr_count = window_counts[window_times[i]]["total"]
        if prev_count > 0:
            change_ratio = abs(curr_count - prev_count) / prev_count
            if change_ratio > 2.0:  # 变化超过200%
                anomalies.append({
                    "type": "频率突变",
                    "window": window_times[i],
                    "previous": prev_count,
                    "current": curr_count,
                    "change_ratio": round(change_ratio, 2),
                    "severity": "高" if change_ratio > 5 else "中"
                })

    # 步骤4: 模式匹配（攻击特征检测）
    patterns_detected = []

    # 暴力破解检测: 同一IP短时间内大量失败登录
    ip_fail_counts = defaultdict(list)
    for entry in log_entries:
        msg = entry.get("message", "").lower()
        event_type = entry.get("event_type", "")
        if "fail" in msg or "denied" in msg or event_type == "auth_failed":
            ip_fail_counts[entry.get("source_ip", "unknown")].append(entry)

    for ip, fails in ip_fail_counts.items():
        if len(fails) >= 5:
            patterns_detected.append({
                "pattern": "暴力破解",
                "source_ip": ip,
                "occurrences": len(fails),
                "severity": "高" if len(fails) >= 20 else "中",
                "description": f"IP {ip} 在检测期间有 {len(fails)} 次失败认证"
            })

    # 端口扫描检测: 同一IP访问多个不同端口
    ip_ports = defaultdict(set)
    for entry in log_entries:
        port = entry.get("port") or re.search(r'port[:\s]*(\d+)', entry.get("message", ""), re.IGNORECASE)
        if port:
            port_num = port if isinstance(port, int) else int(port.group(1))
            ip_ports[entry.get("source_ip", "unknown")].add(port_num)

    for ip, ports in ip_ports.items():
        if len(ports) >= 10:
            patterns_detected.append({
                "pattern": "端口扫描",
                "source_ip": ip,
                "port_count": len(ports),
                "severity": "高",
                "description": f"IP {ip} 访问了 {len(ports)} 个不同端口"
            })

    # SQL注入检测
    sql_patterns = [
        r"union\s+select", r"or\s+1=1", r"';\s*drop", r"--\s*$",
        r"insert\s+into", r"delete\s+from", r"xp_cmdshell"
    ]
    for entry in log_entries:
        msg = entry.get("message", "").lower()
        for pattern in sql_patterns:
            if re.search(pattern, msg):
                patterns_detected.append({
                    "pattern": "SQL注入",
                    "source_ip": entry.get("source_ip", "unknown"),
                    "severity": "高",
                    "description": f"检测到SQL注入特征: {pattern}"
                })
                break

    # 步骤5: 统计汇总
    by_ip_total = defaultdict(int)
    by_type_total = defaultdict(int)
    for w in window_times:
        for ip, count in window_counts[w]["by_ip"].items():
            by_ip_total[ip] += count
        for etype, count in window_counts[w]["by_type"].items():
            by_type_total[etype] += count

    return {
        "anomalies": anomalies,
        "patterns_detected": patterns_detected,
        "statistics": {
            "total_logs": len(log_entries),
            "time_windows": n,
            "window_size_seconds": window_size,
            "mean_logs_per_window": round(mean, 2),
            "std_deviation": round(std, 2),
            "anomaly_count": len(anomalies),
            "pattern_count": len(patterns_detected),
            "top_source_ips": dict(sorted(by_ip_total.items(), key=lambda x: -x[1])[:5]),
            "event_type_distribution": dict(by_type_total)
        },
        "risk_level": "高" if len(patterns_detected) >= 3 or any(p["severity"] == "高" for p in patterns_detected) else ("中" if patterns_detected else "低")
    }


# ---------------------------------------------------------------------------
# 3. 系统健康检查器
# ---------------------------------------------------------------------------
def system_health_checker(metrics):
    """
    系统健康检查器：多维度加权评分系统。

    算法原理:
        - 5维度评估: CPU/内存/磁盘/网络/进程
        - 加权评分: 各维度按权重汇总为总分(0-100)
        - 健康等级: 优秀(90+)/良好(75+)/警告(60+)/危险(<60)
        - 瓶颈定位: 识别得分最低的维度作为系统瓶颈

    参数:
        metrics (dict): 系统指标 {cpu_usage, memory_usage, disk_usage, network_latency, process_count, ...}

    返回:
        dict: 健康检查结果，含score、health_level、bottlenecks、recommendations。
    """
    # 维度权重
    weights = {"cpu": 0.25, "memory": 0.25, "disk": 0.2, "network": 0.15, "process": 0.15}

    # 步骤1: 各维度评分（使用率越高得分越低）
    dimensions = {}

    # CPU评分
    cpu_usage = metrics.get("cpu_usage", 0)
    cpu_score = max(0, 100 - cpu_usage)
    if cpu_usage > 90:
        cpu_status = "危险"
    elif cpu_usage > 75:
        cpu_status = "警告"
    elif cpu_usage > 50:
        cpu_status = "良好"
    else:
        cpu_status = "优秀"
    dimensions["cpu"] = {"usage": cpu_usage, "score": cpu_score, "status": cpu_status, "weight": weights["cpu"]}

    # 内存评分
    mem_usage = metrics.get("memory_usage", 0)
    mem_score = max(0, 100 - mem_usage)
    if mem_usage > 90:
        mem_status = "危险"
    elif mem_usage > 75:
        mem_status = "警告"
    elif mem_usage > 50:
        mem_status = "良好"
    else:
        mem_status = "优秀"
    dimensions["memory"] = {"usage": mem_usage, "score": mem_score, "status": mem_status, "weight": weights["memory"]}

    # 磁盘评分
    disk_usage = metrics.get("disk_usage", 0)
    disk_score = max(0, 100 - disk_usage)
    if disk_usage > 90:
        disk_status = "危险"
    elif disk_usage > 80:
        disk_status = "警告"
    elif disk_usage > 60:
        disk_status = "良好"
    else:
        disk_status = "优秀"
    dimensions["disk"] = {"usage": disk_usage, "score": disk_score, "status": disk_status, "weight": weights["disk"]}

    # 网络评分
    net_latency = metrics.get("network_latency", 0)  # ms
    net_packet_loss = metrics.get("packet_loss", 0)  # %
    net_score = max(0, 100 - net_latency / 10 - net_packet_loss * 5)
    if net_latency > 100 or net_packet_loss > 5:
        net_status = "危险"
    elif net_latency > 50 or net_packet_loss > 2:
        net_status = "警告"
    elif net_latency > 20:
        net_status = "良好"
    else:
        net_status = "优秀"
    dimensions["network"] = {"latency": net_latency, "packet_loss": net_packet_loss, "score": net_score, "status": net_status, "weight": weights["network"]}

    # 进程评分
    proc_count = metrics.get("process_count", 0)
    zombie_count = metrics.get("zombie_count", 0)
    proc_score = 100
    if proc_count > 500:
        proc_score -= (proc_count - 500) / 10
    if zombie_count > 0:
        proc_score -= zombie_count * 10
    proc_score = max(0, proc_score)
    if zombie_count > 5 or proc_count > 1000:
        proc_status = "危险"
    elif zombie_count > 0 or proc_count > 500:
        proc_status = "警告"
    else:
        proc_status = "优秀"
    dimensions["process"] = {"count": proc_count, "zombie": zombie_count, "score": proc_score, "status": proc_status, "weight": weights["process"]}

    # 步骤2: 加权总分
    total_score = sum(d["score"] * d["weight"] for d in dimensions.values())

    # 步骤3: 健康等级
    if total_score >= 90:
        health_level = "优秀"
    elif total_score >= 75:
        health_level = "良好"
    elif total_score >= 60:
        health_level = "警告"
    else:
        health_level = "危险"

    # 步骤4: 瓶颈定位
    bottlenecks = sorted(dimensions.items(), key=lambda x: x[1]["score"])[:2]

    # 步骤5: 建议
    recommendations = []
    for dim_name, dim_data in bottlenecks:
        if dim_data["status"] in ("危险", "警告"):
            if dim_name == "cpu":
                recommendations.append("CPU使用率过高，建议检查高负载进程或扩容")
            elif dim_name == "memory":
                recommendations.append("内存使用率过高，建议检查内存泄漏或增加内存")
            elif dim_name == "disk":
                recommendations.append("磁盘空间不足，建议清理日志/临时文件或扩容")
            elif dim_name == "network":
                recommendations.append("网络延迟或丢包过高，建议检查网络配置和带宽")
            elif dim_name == "process":
                recommendations.append("进程数或僵尸进程过多，建议检查异常进程")

    return {
        "total_score": round(total_score, 1),
        "health_level": health_level,
        "dimensions": {k: {kk: vv for kk, vv in v.items() if kk != "weight"} for k, v in dimensions.items()},
        "bottlenecks": [{"dimension": name, "score": data["score"], "status": data["status"]} for name, data in bottlenecks],
        "recommendations": recommendations if recommendations else ["系统运行正常，无需特殊处理"]
    }


# ---------------------------------------------------------------------------
# 4. 漏洞扫描器框架 (CVSS简化版)
# ---------------------------------------------------------------------------
def vulnerability_scanner(scan_config, targets):
    """
    漏洞扫描器框架：端口扫描+服务指纹+CVE匹配+CVSS评分。

    算法原理:
        - 端口扫描: TCP Connect扫描（模拟），识别开放端口
        - 服务指纹: 根据端口号和banner识别服务类型和版本
        - CVE匹配: 基于服务版本匹配已知漏洞数据库
        - CVSS评分: 基于AV/AC/PR/UI/S/C/I/A计算基础分数(0-10)

    参数:
        scan_config (dict): 扫描配置 {ports, timeout, intensity}
        targets (list[str]): 目标主机列表

    返回:
        dict: 扫描结果，含scan_results、vulnerabilities、risk_summary。
    """
    # 模拟端口服务映射
    port_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
        27017: "MongoDB", 9200: "Elasticsearch"
    }

    # 模拟CVE数据库
    cve_database = [
        {"cve_id": "CVE-2024-0001", "service": "FTP", "min_version": "0", "max_version": "3.5",
         "cvss": 7.5, "severity": "高", "description": "FTP服务存在匿名访问漏洞", "fix": "禁用匿名访问或升级到最新版本"},
        {"cve_id": "CVE-2024-0002", "service": "SSH", "min_version": "0", "max_version": "8.0",
         "cvss": 9.8, "severity": "严重", "description": "SSH存在远程代码执行漏洞", "fix": "升级OpenSSH至8.1以上版本"},
        {"cve_id": "CVE-2024-0003", "service": "HTTP", "min_version": "0", "max_version": "2.4.49",
         "cvss": 8.2, "severity": "高", "description": "Apache路径遍历漏洞", "fix": "升级Apache至2.4.50以上版本"},
        {"cve_id": "CVE-2024-0004", "service": "MySQL", "min_version": "5.0", "max_version": "5.7.35",
         "cvss": 6.5, "severity": "中", "description": "MySQL存在权限提升漏洞", "fix": "升级MySQL至8.0以上版本"},
        {"cve_id": "CVE-2024-0005", "service": "Redis", "min_version": "0", "max_version": "6.2.6",
         "cvss": 9.0, "severity": "严重", "description": "Redis未授权访问漏洞", "fix": "配置认证或升级到6.2.7以上"},
        {"cve_id": "CVE-2024-0006", "service": "Telnet", "min_version": "0", "max_version": "99",
         "cvss": 10.0, "severity": "严重", "description": "Telnet明文传输凭证", "fix": "禁用Telnet，使用SSH替代"},
    ]

    # CVSS计算函数（简化版）
    def calculate_cvss(av, ac, pr, ui, s, c, i, a):
        """计算CVSS 3.1基础分数"""
        # 利用ability (Exploitability)
        # 简化权重
        av_weight = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_weight = {"L": 0.77, "H": 0.44}
        pr_weight = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_weight = {"N": 0.85, "R": 0.62}

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        exploitability = 8.22 * av_weight.get(av, 0.85) * ac_weight.get(ac, 0.77) * pr_weight.get(pr, 0.85) * ui_weight.get(ui, 0.85)

        if impact <= 0:
            return 0

        if s == "U":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)

        return round(base, 1)

    scan_results = []
    all_vulnerabilities = []

    ports = scan_config.get("ports", [21, 22, 23, 80, 443, 3306, 6379, 8080])

    for target in targets:
        target_result = {
            "target": target,
            "open_ports": [],
            "services": [],
            "vulnerabilities": []
        }

        # 模拟端口扫描结果
        random_state = sum(ord(c) for c in target) % 100
        for port in ports:
            # 模拟端口开放概率（约50%端口开放）
            is_open = (random_state + port) % 3 != 0
            if is_open:
                service = port_services.get(port, "Unknown")
                # 模拟版本号
                version = f"{(port % 5) + 1}.{port % 10}.{port % 3}"
                target_result["open_ports"].append(port)
                target_result["services"].append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "state": "open"
                })

                # CVE匹配
                for cve in cve_database:
                    if cve["service"] == service:
                        target_result["vulnerabilities"].append({
                            "cve_id": cve["cve_id"],
                            "service": service,
                            "version": version,
                            "cvss_score": cve["cvss"],
                            "severity": cve["severity"],
                            "description": cve["description"],
                            "fix_recommendation": cve["fix"],
                            "target": target
                        })
                        all_vulnerabilities.append({
                            "target": target,
                            "port": port,
                            **cve
                        })

        scan_results.append(target_result)

    # 风险汇总
    severity_counts = defaultdict(int)
    for vuln in all_vulnerabilities:
        severity_counts[vuln["severity"]] += 1

    # CVSS计算验证
    cvss_samples = []
    for vuln in all_vulnerabilities[:3]:
        cvss_calculated = calculate_cvss(
            av="N", ac="L", pr="N", ui="N", s="U",
            c=0.5 if vuln["cvss"] < 8 else 0.8,
            i=0.5 if vuln["cvss"] < 8 else 0.8,
            a=0.5 if vuln["cvss"] < 8 else 0.8
        )
        cvss_samples.append({
            "cve_id": vuln["cve_id"],
            "stored_cvss": vuln["cvss"],
            "calculated_cvss": cvss_calculated
        })

    total_vulns = len(all_vulnerabilities)
    critical_count = severity_counts.get("严重", 0)
    high_count = severity_counts.get("高", 0)

    if critical_count > 0:
        risk_level = "严重"
    elif high_count > 2:
        risk_level = "高"
    elif high_count > 0 or total_vulns > 5:
        risk_level = "中"
    else:
        risk_level = "低"

    return {
        "scan_results": scan_results,
        "vulnerabilities": all_vulnerabilities,
        "risk_summary": {
            "total_targets": len(targets),
            "total_vulnerabilities": total_vulns,
            "severity_distribution": dict(severity_counts),
            "risk_level": risk_level,
            "targets_with_vulns": sum(1 for r in scan_results if r["vulnerabilities"])
        },
        "cvss_verification": cvss_samples,
        "recommendations": [
            "优先修复严重级别漏洞" if critical_count > 0 else "定期扫描漏洞",
            f"共发现 {total_vulns} 个漏洞，其中严重 {critical_count} 个",
            "建议对所有开放端口进行访问控制"
        ]
    }


# ---------------------------------------------------------------------------
# 5. 防火墙规则审计器
# ---------------------------------------------------------------------------
def firewall_rule_auditor(rules, traffic_logs):
    """
    防火墙规则审计器：规则冲突检测+冗余识别+命中统计。

    算法原理:
        - 冲突检测: 规则重叠(相同条件不同动作)、包含(一条规则条件包含另一条)、矛盾(允许+拒绝相同条件)
        - 冗余识别: 被更宽泛规则完全覆盖的规则
        - 命中统计: 基于流量日志统计每条规则的命中次数
        - 优化建议: 删除冗余规则、合并相似规则

    参数:
        rules (list[dict]): 防火墙规则列表，每条含id, action(allow/deny), src_ip, dst_ip, port, protocol
        traffic_logs (list[dict]): 流量日志列表

    返回:
        dict: 审计结果，含conflicts、redundancies、hit_stats、optimization_suggestions。
    """
    # 步骤1: 规则冲突检测
    conflicts = []
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            r1 = rules[i]
            r2 = rules[j]

            # 检查条件重叠
            overlap = True
            if r1.get("src_ip") != r2.get("src_ip") and r1.get("src_ip") != "*" and r2.get("src_ip") != "*":
                overlap = False
            if r1.get("dst_ip") != r2.get("dst_ip") and r1.get("dst_ip") != "*" and r2.get("dst_ip") != "*":
                overlap = False
            if r1.get("port") != r2.get("port") and r1.get("port") != "*" and r2.get("port") != "*":
                overlap = False
            if r1.get("protocol") != r2.get("protocol") and r1.get("protocol") != "*" and r2.get("protocol") != "*":
                overlap = False

            if overlap:
                if r1.get("action") != r2.get("action"):
                    # 矛盾规则
                    conflicts.append({
                        "type": "矛盾",
                        "rule1": r1.get("id"),
                        "rule2": r2.get("id"),
                        "description": f"规则{r1.get('id')}({r1.get('action')})与规则{r2.get('id')}({r2.get('action')})条件重叠但动作相反",
                        "severity": "高"
                    })
                else:
                    # 可能冗余
                    conflicts.append({
                        "type": "重叠",
                        "rule1": r1.get("id"),
                        "rule2": r2.get("id"),
                        "description": f"规则{r1.get('id')}与规则{r2.get('id')}条件重叠且动作相同",
                        "severity": "低"
                    })

    # 步骤2: 冗余规则识别
    def is_covered(specific, general):
        """检查specific规则是否被general规则完全覆盖"""
        for field in ["src_ip", "dst_ip", "port", "protocol"]:
            g_val = general.get(field, "*")
            s_val = specific.get(field, "*")
            if g_val != "*" and g_val != s_val:
                return False
        return True

    redundancies = []
    for i in range(len(rules)):
        for j in range(len(rules)):
            if i != j and rules[i].get("action") == rules[j].get("action"):
                if is_covered(rules[i], rules[j]):
                    # rules[i]被rules[j]覆盖
                    if rules[i].get("src_ip") != rules[j].get("src_ip") or rules[i].get("port") != rules[j].get("port"):
                        redundancies.append({
                            "redundant_rule": rules[i].get("id"),
                            "covered_by": rules[j].get("id"),
                            "description": f"规则{rules[i].get('id')}被规则{rules[j].get('id')}完全覆盖"
                        })

    # 步骤3: 规则命中统计
    hit_counts = defaultdict(int)
    for log in traffic_logs:
        for rule in rules:
            matches = True
            if rule.get("src_ip") != "*" and rule.get("src_ip") != log.get("src_ip"):
                matches = False
            if rule.get("dst_ip") != "*" and rule.get("dst_ip") != log.get("dst_ip"):
                matches = False
            if rule.get("port") != "*" and rule.get("port") != log.get("port"):
                matches = False
            if rule.get("protocol") != "*" and rule.get("protocol") != log.get("protocol"):
                matches = False
            if matches:
                hit_counts[rule.get("id")] += 1
                break  # 防火墙规则按顺序匹配，命中即停

    # 步骤4: 未命中规则识别
    never_hit = [r.get("id") for r in rules if hit_counts.get(r.get("id"), 0) == 0]

    # 步骤5: 优化建议
    optimization_suggestions = []
    for conf in conflicts:
        if conf["type"] == "矛盾":
            optimization_suggestions.append(f"修复矛盾规则: {conf['description']}")
    for red in redundancies:
        optimization_suggestions.append(f"删除冗余规则: {red['description']}")
    for rule_id in never_hit:
        optimization_suggestions.append(f"规则{rule_id}从未命中，考虑删除")

    return {
        "conflicts": conflicts,
        "redundancies": redundancies,
        "hit_stats": {
            "total_rules": len(rules),
            "rules_with_hits": len([r for r in rules if hit_counts.get(r.get("id"), 0) > 0]),
            "rules_never_hit": never_hit,
            "hit_distribution": dict(sorted(hit_counts.items(), key=lambda x: -x[1])[:10])
        },
        "optimization_suggestions": optimization_suggestions,
        "audit_summary": {
            "conflict_count": len(conflicts),
            "contradiction_count": len([c for c in conflicts if c["type"] == "矛盾"]),
            "redundancy_count": len(redundancies),
            "never_hit_count": len(never_hit),
            "risk_level": "高" if any(c["type"] == "矛盾" for c in conflicts) else ("中" if redundancies else "低")
        }
    }


# ---------------------------------------------------------------------------
# 6. SSL证书检查器
# ---------------------------------------------------------------------------
def ssl_certificate_checker(hostname, port=443):
    """
    SSL证书检查器：证书解析+链验证+过期预警+加密套件评估。

    算法原理:
        - 证书解析: 模拟解析X.509证书结构(Subject/Issuer/有效期/SAN)
        - 链验证: 验证证书链从叶节点到根CA的完整性
        - 过期预警: 计算剩余有效期，30天内预警
        - 加密套件评估: 基于密码强度和协议版本评分

    参数:
        hostname (str): 主机名
        port (int): 端口号，默认443

    返回:
        dict: SSL检查结果，含certificate、chain_validation、expiry、cipher_evaluation。
    """
    # 模拟证书数据（基于hostname生成确定性结果）
    seed = sum(ord(c) for c in hostname)
    now = datetime.now()

    # 步骤1: 证书解析
    issuer_org = "Let's Encrypt" if seed % 2 == 0 else "DigiCert"
    valid_days = 90 if issuer_org == "Let's Encrypt" else 365
    issue_date = now - timedelta(days=valid_days // 2 + seed % 30)
    expiry_date = issue_date + timedelta(days=valid_days)

    certificate = {
        "hostname": hostname,
        "port": port,
        "subject": {
            "CN": hostname,
            "O": f"Organization-{seed % 100}",
            "C": "US"
        },
        "issuer": {
            "CN": issuer_org,
            "O": issuer_org,
            "C": "US"
        },
        "serial_number": f"{seed:016x}",
        "version": "v3",
        "issue_date": issue_date.strftime("%Y-%m-%d"),
        "expiry_date": expiry_date.strftime("%Y-%m-%d"),
        "signature_algorithm": "SHA256withRSA" if seed % 3 != 0 else "SHA1withRSA",
        "key_size": 2048 if seed % 2 == 0 else 1024,
        "san": [hostname, f"www.{hostname}", f"*.{'.'.join(hostname.split('.')[-2:])}"]
    }

    # 步骤2: 过期检查
    days_remaining = (expiry_date - now).days
    if days_remaining < 0:
        expiry_status = "已过期"
        expiry_severity = "严重"
    elif days_remaining < 7:
        expiry_status = "即将过期"
        expiry_severity = "严重"
    elif days_remaining < 30:
        expiry_status = "即将过期"
        expiry_severity = "警告"
    else:
        expiry_status = "有效"
        expiry_severity = "正常"

    # 步骤3: 证书链验证（模拟）
    chain_issues = []
    chain_valid = True

    if certificate["signature_algorithm"] == "SHA1withRSA":
        chain_issues.append("证书使用弱签名算法SHA1")
        chain_valid = False
    if certificate["key_size"] < 2048:
        chain_issues.append(f"密钥长度不足: {certificate['key_size']}位 (建议至少2048位)")
        chain_valid = False

    # 信任链验证
    trusted_cas = ["Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo"]
    if certificate["issuer"]["CN"] not in trusted_cas:
        chain_issues.append(f"签发机构不在受信任CA列表中: {certificate['issuer']['CN']}")
        chain_valid = False

    # SAN匹配验证
    san_matches = any(hostname == san or hostname.endswith(san.replace("*.", "")) for san in certificate["san"])
    if not san_matches:
        chain_issues.append(f"主机名{hostname}不匹配证书SAN")
        chain_valid = False

    # 步骤4: 加密套件评估
    cipher_suites = [
        {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLS 1.3", "strength": "强", "score": 100},
        {"name": "TLS_CHACHA20_POLY1305_SHA256", "protocol": "TLS 1.3", "strength": "强", "score": 100},
        {"name": "ECDHE-RSA-AES256-GCM-SHA384", "protocol": "TLS 1.2", "strength": "强", "score": 90},
        {"name": "ECDHE-RSA-AES128-GCM-SHA256", "protocol": "TLS 1.2", "strength": "中", "score": 80},
    ]

    # 根据seed选择是否包含弱加密套件
    weak_ciphers = []
    if seed % 3 == 0:
        cipher_suites.append({"name": "RC4-MD5", "protocol": "TLS 1.0", "strength": "弱", "score": 20})
        weak_ciphers.append("RC4-MD5")
    if seed % 4 == 0:
        cipher_suites.append({"name": "DES-CBC3-SHA", "protocol": "TLS 1.0", "strength": "弱", "score": 30})
        weak_ciphers.append("DES-CBC3-SHA")

    cipher_score = sum(c["score"] for c in cipher_suites) / len(cipher_suites)
    min_protocol = min(c["protocol"] for c in cipher_suites)

    if "TLS 1.0" in min_protocol:
        protocol_warning = "支持过时的TLS 1.0协议"
    elif "TLS 1.1" in min_protocol:
        protocol_warning = "支持过时的TLS 1.1协议"
    else:
        protocol_warning = None

    # 步骤5: 总体评估
    issues = []
    if expiry_severity in ("严重", "警告"):
        issues.append(f"证书{expiry_status}，剩余{days_remaining}天")
    if not chain_valid:
        issues.extend(chain_issues)
    if weak_ciphers:
        issues.append(f"存在弱加密套件: {', '.join(weak_ciphers)}")
    if protocol_warning:
        issues.append(protocol_warning)

    if not issues:
        grade = "A+"
        recommendation = "证书配置良好"
    elif cipher_score >= 80 and expiry_status == "有效":
        grade = "A"
        recommendation = "证书配置良好，建议禁用过时协议"
    elif cipher_score >= 60:
        grade = "B"
        recommendation = "存在安全风险，建议升级加密套件"
    else:
        grade = "C"
        recommendation = "存在严重安全风险，需要立即修复"

    return {
        "certificate": certificate,
        "expiry": {
            "status": expiry_status,
            "severity": expiry_severity,
            "days_remaining": days_remaining,
            "expiry_date": certificate["expiry_date"]
        },
        "chain_validation": {
            "valid": chain_valid,
            "issues": chain_issues
        },
        "cipher_evaluation": {
            "supported_suites": cipher_suites,
            "cipher_score": round(cipher_score, 1),
            "min_protocol": min_protocol,
            "weak_ciphers": weak_ciphers,
            "protocol_warning": protocol_warning
        },
        "overall": {
            "grade": grade,
            "issues": issues,
            "recommendation": recommendation
        }
    }


# ---------------------------------------------------------------------------
# 7. 权限审计器
# ---------------------------------------------------------------------------
def permission_audit(file_permissions, expected_permissions):
    """
    权限审计器：文件权限检查+SUID/SGID检测+最小权限原则校验。

    算法原理:
        - 权限解析: 将rwxr-xr-x转换为数值权限(755)
        - SUID/SGID检测: 检查特殊权限位
        - 越权识别: 对比实际权限与期望权限
        - 最小权限原则: 文件不应有超出需要的权限

    参数:
        file_permissions (list[dict]): 文件权限列表，每条含path, owner, group, permissions, type
        expected_permissions (dict): 期望权限映射 {path: expected_perm}

    返回:
        dict: 审计结果，含violations、suid_sgid_files、least_privilege_issues、summary。
    """
    violations = []
    suid_sgid_files = []
    least_privilege_issues = []

    for entry in file_permissions:
        path = entry.get("path", "")
        perm_str = entry.get("permissions", "---------")
        file_type = entry.get("type", "file")

        # 解析权限字符串 (rwxrwxrwx -> 777)
        def perm_to_numeric(perm_str):
            """将rwx格式权限转换为数值"""
            perm_str = perm_str.lstrip('dls-')[-9:]  # 去除类型字符
            numeric = ""
            for i in range(0, 9, 3):
                group = perm_str[i:i+3]
                val = 0
                if 'r' in group: val += 4
                if 'w' in group: val += 2
                if 'x' in group: val += 1
                numeric += str(val)
            return int(numeric) if numeric else 0

        numeric_perm = perm_to_numeric(perm_str)

        # SUID/SGID检测
        has_suid = 's' in perm_str[:3] or perm_str.startswith('4')
        has_sgid = 's' in perm_str[3:6] or perm_str.startswith('2') or perm_str.startswith('6')
        has_sticky = 't' in perm_str[6:9] or perm_str.startswith('1')

        if has_suid or has_sgid:
            special = []
            if has_suid: special.append("SUID")
            if has_sgid: special.append("SGID")
            suid_sgid_files.append({
                "path": path,
                "permissions": perm_str,
                "numeric": f"{'4' if has_suid else ''}{'2' if has_sgid else ''}{numeric_perm:03d}",
                "special_bits": special,
                "risk": "高" if has_suid else "中",
                "description": f"文件设置{'SUID' if has_suid else ''}{'SGID' if has_sgid else ''}权限，执行时以文件所有者/组身份运行"
            })

        # 世界可写检测
        world_writable = numeric_perm % 10 >= 2  # others有写权限
        if world_writable and file_type != "dir":
            violations.append({
                "path": path,
                "type": "世界可写",
                "severity": "高",
                "current_perm": perm_str,
                "description": f"文件对所有人可写，存在篡改风险"
            })

        # 期望权限对比
        if path in expected_permissions:
            expected_perm = expected_permissions[path]
            expected_numeric = perm_to_numeric(expected_perm) if isinstance(expected_perm, str) else expected_perm
            if numeric_perm != expected_numeric:
                violations.append({
                    "path": path,
                    "type": "权限不符期望",
                    "severity": "中",
                    "current_perm": perm_str,
                    "expected_perm": expected_perm,
                    "description": f"当前权限{perm_str}与期望权限{expected_perm}不符"
                })

        # 最小权限原则检查
        # 文件不应有执行权限（除非是脚本/程序）
        if file_type == "file" and not path.endswith(('.sh', '.py', '.pl', '.exe', '.bin')):
            if numeric_perm % 2 == 1:  # owner有执行权限
                pass  # 可接受
            if (numeric_perm // 10) % 10 >= 1:  # group有执行权限
                least_privilege_issues.append({
                    "path": path,
                    "issue": "非可执行文件有组执行权限",
                    "recommendation": "移除组执行权限"
                })
            if numeric_perm % 10 >= 1:  # others有执行权限
                least_privilege_issues.append({
                    "path": path,
                    "issue": "非可执行文件有其他用户执行权限",
                    "recommendation": "移除其他用户执行权限"
                })

        # 目录权限检查
        if file_type == "dir":
            if numeric_perm % 10 >= 7:  # others有rwx
                least_privilege_issues.append({
                    "path": path,
                    "issue": "目录对其他用户完全开放(rwx)",
                    "recommendation": "限制为只读(rx)或无权限"
                })

    # 权限权限位汇总
    perm_distribution = defaultdict(int)
    for entry in file_permissions:
        perm_str = entry.get("permissions", "")
        # 简化分类
        if '777' in perm_str or 'rwxrwxrwx' in perm_str:
            perm_distribution["777(完全开放)"] += 1
        elif '666' in perm_str or 'rw-rw-rw-' in perm_str:
            perm_distribution["666(全读写)"] += 1
        elif '755' in perm_str or 'rwxr-xr-x' in perm_str:
            perm_distribution["755(标准目录)"] += 1
        elif '644' in perm_str or 'rw-r--r--' in perm_str:
            perm_distribution["644(标准文件)"] += 1
        else:
            perm_distribution["其他"] += 1

    return {
        "violations": violations,
        "suid_sgid_files": suid_sgid_files,
        "least_privilege_issues": least_privilege_issues,
        "summary": {
            "total_files": len(file_permissions),
            "violation_count": len(violations),
            "suid_sgid_count": len(suid_sgid_files),
            "least_privilege_issues": len(least_privilege_issues),
            "permission_distribution": dict(perm_distribution),
            "risk_level": "高" if any(v["severity"] == "高" for v in violations) or suid_sgid_files else ("中" if violations else "低")
        },
        "recommendations": [
            "修复世界可写文件权限" if any(v["type"] == "世界可写" for v in violations) else "",
            "审查SUID/SGID文件的必要性" if suid_sgid_files else "",
            "按最小权限原则调整权限" if least_privilege_issues else ""
        ]
    }


# ---------------------------------------------------------------------------
# 8. 安全事件追踪器
# ---------------------------------------------------------------------------
def security_incident_tracker(incidents, status_filter):
    """
    安全事件追踪器：事件生命周期管理+SLA计时+趋势分析。

    算法原理:
        - 生命周期管理: 检测→分析→遏制→根除→恢复→总结(6阶段)
        - SLA计时: 计算事件从检测到各阶段完成的时间，对比SLA阈值
        - 趋势分析: 按时间/类型/严重度统计趋势

    参数:
        incidents (list[dict]): 事件列表，每条含id, type, severity, detected_at, phases
        status_filter (str): 状态过滤 "all"/"open"/"closed"/"critical"

    返回:
        dict: 事件追踪结果，含filtered_incidents、sla_analysis、trends、summary。
    """
    # SLA阈值（小时）
    sla_thresholds = {
        "严重": {"遏制": 1, "根除": 4, "恢复": 8, "总结": 24},
        "高": {"遏制": 2, "根除": 8, "恢复": 24, "总结": 48},
        "中": {"遏制": 4, "根除": 24, "恢复": 48, "总结": 72},
        "低": {"遏制": 8, "根除": 48, "恢复": 96, "总结": 168},
    }

    # 生命周期阶段
    lifecycle_phases = ["检测", "分析", "遏制", "根除", "恢复", "总结"]

    # 步骤1: 过滤
    filtered = []
    for incident in incidents:
        if status_filter == "all":
            filtered.append(incident)
        elif status_filter == "open":
            if incident.get("status", "open") == "open":
                filtered.append(incident)
        elif status_filter == "closed":
            if incident.get("status") == "closed":
                filtered.append(incident)
        elif status_filter == "critical":
            if incident.get("severity") == "严重":
                filtered.append(incident)

    # 步骤2: SLA分析
    sla_analysis = []
    for incident in filtered:
        detected_at = datetime.strptime(incident.get("detected_at", "2025-01-01 00:00"), "%Y-%m-%d %H:%M")
        phases = incident.get("phases", {})
        severity = incident.get("severity", "中")
        sla = sla_thresholds.get(severity, sla_thresholds["中"])

        phase_times = {}
        sla_violations = []
        prev_time = detected_at

        for phase in lifecycle_phases:
            if phase in phases:
                phase_time = datetime.strptime(phases[phase], "%Y-%m-%d %H:%M")
                duration_hours = (phase_time - prev_time).total_seconds() / 3600
                phase_times[phase] = {
                    "time": phases[phase],
                    "duration_hours": round(duration_hours, 1)
                }
                # SLA检查
                if phase in sla and duration_hours > sla[phase]:
                    sla_violations.append({
                        "phase": phase,
                        "sla_hours": sla[phase],
                        "actual_hours": round(duration_hours, 1),
                        "overdue": round(duration_hours - sla[phase], 1)
                    })
                prev_time = phase_time

        # 当前阶段
        completed_phases = [p for p in lifecycle_phases if p in phases]
        current_phase = lifecycle_phases[len(completed_phases)] if len(completed_phases) < len(lifecycle_phases) else "已完成"
        total_duration = (prev_time - detected_at).total_seconds() / 3600 if len(completed_phases) > 0 else 0

        sla_analysis.append({
            "incident_id": incident.get("id"),
            "type": incident.get("type"),
            "severity": severity,
            "detected_at": incident.get("detected_at"),
            "current_phase": current_phase,
            "completed_phases": completed_phases,
            "total_duration_hours": round(total_duration, 1),
            "phase_times": phase_times,
            "sla_violations": sla_violations,
            "sla_breached": len(sla_violations) > 0
        })

    # 步骤3: 趋势分析
    type_trends = defaultdict(int)
    severity_trends = defaultdict(int)
    sla_breach_count = 0

    for incident in sla_analysis:
        type_trends[incident["type"]] += 1
        severity_trends[incident["severity"]] += 1
        if incident["sla_breached"]:
            sla_breach_count += 1

    # 平均解决时间
    resolved = [s for s in sla_analysis if s["current_phase"] == "已完成"]
    avg_resolution = sum(s["total_duration_hours"] for s in resolved) / len(resolved) if resolved else 0

    return {
        "filtered_incidents": sla_analysis,
        "sla_analysis": {
            "total_incidents": len(sla_analysis),
            "sla_breaches": sla_breach_count,
            "sla_breach_rate": round(sla_breach_count / max(len(sla_analysis), 1) * 100, 1),
            "avg_resolution_hours": round(avg_resolution, 1),
            "resolved_count": len(resolved)
        },
        "trends": {
            "by_type": dict(type_trends),
            "by_severity": dict(severity_trends),
            "most_common_type": max(type_trends, key=type_trends.get) if type_trends else None
        },
        "summary": {
            "total": len(sla_analysis),
            "open": sum(1 for s in sla_analysis if s["current_phase"] != "已完成"),
            "closed": len(resolved),
            "critical": severity_trends.get("严重", 0),
            "sla_breaches": sla_breach_count
        }
    }


# ---------------------------------------------------------------------------
# 9. 备份完整性验证器 (SHA-256)
# ---------------------------------------------------------------------------
def backup_integrity_verifier(backup_info, source_hashes):
    """
    备份完整性验证器：基于SHA-256哈希比对检测变更/丢失/损坏。

    算法原理:
        - 哈希计算: SHA-256对文件内容计算摘要
        - 完整性验证: 比对源文件和备份文件的哈希值
        - 变更检测: 哈希不同=文件被修改
        - 丢失检测: 源有备份无=文件丢失
        - 多余检测: 备份有源无=多余文件

    参数:
        backup_info (list[dict]): 备份文件信息列表，含path, size, hash, backup_date
        source_hashes (dict): 源文件哈希映射 {path: hash}

    返回:
        dict: 验证结果，含verification_results、missing_files、changed_files、extra_files、report。
    """
    # 构建备份文件哈希映射
    backup_hashes = {f["path"]: f for f in backup_info}

    # 步骤1: 逐文件验证
    verification_results = []
    missing_files = []
    changed_files = []
    corrupted_files = []

    for path, source_hash in source_hashes.items():
        if path not in backup_hashes:
            missing_files.append({
                "path": path,
                "source_hash": source_hash,
                "issue": "文件在备份中不存在"
            })
        else:
            backup_file = backup_hashes[path]
            backup_hash = backup_file.get("hash", "")

            if backup_hash == source_hash:
                verification_results.append({
                    "path": path,
                    "status": "完整",
                    "source_hash": source_hash[:16] + "...",
                    "backup_hash": backup_hash[:16] + "..."
                })
            else:
                # 检查文件大小是否一致
                source_size = source_hashes.get(path + "_size", 0)
                backup_size = backup_file.get("size", 0)

                if backup_size == 0:
                    corrupted_files.append({
                        "path": path,
                        "issue": "备份文件大小为0，可能损坏",
                        "source_hash": source_hash[:16] + "...",
                        "backup_hash": backup_hash[:16] + "..."
                    })
                else:
                    changed_files.append({
                        "path": path,
                        "issue": "文件内容不一致",
                        "source_hash": source_hash[:16] + "...",
                        "backup_hash": backup_hash[:16] + "...",
                        "source_size": source_size,
                        "backup_size": backup_size
                    })
                verification_results.append({
                    "path": path,
                    "status": "已变更" if backup_size > 0 else "已损坏",
                    "source_hash": source_hash[:16] + "...",
                    "backup_hash": backup_hash[:16] + "..."
                })

    # 步骤2: 检测多余文件（备份中有但源中无）
    extra_files = []
    for path in backup_hashes:
        if path not in source_hashes:
            extra_files.append({
                "path": path,
                "issue": "备份中存在但源中不存在",
                "backup_hash": backup_hashes[path].get("hash", "")[:16] + "..."
            })

    # 步骤3: 生成哈希样本（SHA-256演示）
    sample_hash = hashlib.sha256(b"backup_integrity_verification").hexdigest()

    # 步骤4: 生成验证报告
    total_files = len(source_hashes)
    intact_count = sum(1 for r in verification_results if r["status"] == "完整")
    integrity_rate = intact_count / max(total_files, 1) * 100

    if integrity_rate == 100 and not missing_files and not extra_files:
        overall_status = "通过"
        risk_level = "低"
    elif integrity_rate >= 95:
        overall_status = "基本通过"
        risk_level = "低"
    elif integrity_rate >= 80:
        overall_status = "需关注"
        risk_level = "中"
    else:
        overall_status = "不通过"
        risk_level = "高"

    return {
        "verification_results": verification_results,
        "missing_files": missing_files,
        "changed_files": changed_files,
        "corrupted_files": corrupted_files,
        "extra_files": extra_files,
        "report": {
            "total_source_files": total_files,
            "total_backup_files": len(backup_hashes),
            "intact_files": intact_count,
            "integrity_rate": round(integrity_rate, 1),
            "missing_count": len(missing_files),
            "changed_count": len(changed_files),
            "corrupted_count": len(corrupted_files),
            "extra_count": len(extra_files),
            "overall_status": overall_status,
            "risk_level": risk_level,
            "sha256_sample": sample_hash,
            "recommendations": [
                f"重新备份{len(missing_files)}个丢失文件" if missing_files else "",
                f"重新备份{len(changed_files)}个变更文件" if changed_files else "",
                f"清理{len(extra_files)}个多余备份文件" if extra_files else "",
                "备份完整性验证通过" if overall_status == "通过" else ""
            ]
        }
    }


# ---------------------------------------------------------------------------
# 10. 安全审计报告生成器
# ---------------------------------------------------------------------------
def security_audit_report_generator(audit_data, report_type):
    """
    安全审计报告生成器：汇总所有审计结果生成结构化安全报告。

    算法原理:
        - 数据聚合: 汇总各审计模块结果
        - 风险评分: 基于发现数量和严重度计算总风险分
        - 报告模板: 风险摘要 -> 详细发现 -> 修复建议 -> 合规映射
        - 格式化: Markdown/HTML双格式

    参数:
        audit_data (dict): 审计数据 {module_name: [findings]}
        report_type (str): 报告类型 "markdown"/"html"/"summary"

    返回:
        dict: 报告生成结果，含report_text、risk_summary、compliance_mapping。
    """
    # 步骤1: 数据聚合
    all_findings = []
    by_module = defaultdict(list)
    by_severity = defaultdict(int)

    severity_scores = {"严重": 10, "高": 7, "中": 4, "低": 1, "信息": 0}

    for module, findings in audit_data.items():
        for finding in findings:
            severity = finding.get("severity", "低")
            all_findings.append({
                "module": module,
                "title": finding.get("title", ""),
                "severity": severity,
                "description": finding.get("description", ""),
                "recommendation": finding.get("recommendation", ""),
                "cvss": finding.get("cvss", 0)
            })
            by_module[module].append(finding)
            by_severity[severity] += 1

    # 步骤2: 风险评分
    total_score = sum(severity_scores.get(f["severity"], 1) for f in all_findings)
    max_possible = len(all_findings) * 10 if all_findings else 1
    risk_percentage = total_score / max_possible * 100

    if risk_percentage >= 70:
        risk_level = "严重"
    elif risk_percentage >= 50:
        risk_level = "高"
    elif risk_percentage >= 30:
        risk_level = "中"
    else:
        risk_level = "低"

    # 步骤3: 合规映射
    compliance_mapping = {
        "ISO 27001": {
            "访问控制": len([f for f in all_findings if f["module"] == "permission_audit"]),
            "加密": len([f for f in all_findings if f["module"] == "ssl_check"]),
            "事件管理": len([f for f in all_findings if f["module"] == "incident_tracker"]),
            "备份恢复": len([f for f in all_findings if f["module"] == "backup_verifier"]),
        },
        "GDPR": {
            "数据安全": len([f for f in all_findings if "data" in f["module"].lower()]),
            "访问控制": len([f for f in all_findings if f["module"] == "permission_audit"]),
        },
        "等保2.0": {
            "安全审计": len(all_findings),
            "入侵防范": len([f for f in all_findings if f["module"] == "vuln_scan"]),
            "恶意代码防范": len([f for f in all_findings if f["module"] == "log_anomaly"]),
        }
    }

    # 步骤4: 生成报告
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M")

    if report_type == "markdown":
        lines = [
            "# 安全审计报告",
            "",
            f"**报告日期**: {report_date}",
            f"**风险等级**: {risk_level}",
            f"**风险评分**: {total_score}/{max_possible:.0f} ({risk_percentage:.1f}%)",
            "",
            "---",
            "",
            "## 1. 风险摘要",
            "",
            f"| 指标 | 数值 |",
            f"|------|------|",
            f"| 审计模块数 | {len(audit_data)} |",
            f"| 发现总数 | {len(all_findings)} |",
            f"| 严重 | {by_severity.get('严重', 0)} |",
            f"| 高 | {by_severity.get('高', 0)} |",
            f"| 中 | {by_severity.get('中', 0)} |",
            f"| 低 | {by_severity.get('低', 0)} |",
            "",
            "## 2. 详细发现",
            ""
        ]

        for module, findings in by_module.items():
            lines.append(f"### {module}")
            lines.append("")
            for f in findings:
                lines.append(f"- **[{f.get('severity', '低')}]** {f.get('title', f.get('description', ''))}")
                if f.get("recommendation"):
                    lines.append(f"  - 修复建议: {f['recommendation']}")
            lines.append("")

        lines.extend([
            "## 3. 修复建议",
            "",
        ])
        recommendations = set()
        for f in all_findings:
            if f.get("recommendation"):
                recommendations.add(f["recommendation"])
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")

        lines.extend([
            "",
            "## 4. 合规映射",
            "",
        ])
        for standard, items in compliance_mapping.items():
            lines.append(f"### {standard}")
            lines.append(f"| 控制域 | 发现数 |")
            lines.append(f"|--------|--------|")
            for domain, count in items.items():
                lines.append(f"| {domain} | {count} |")
            lines.append("")

        lines.extend([
            "---",
            f"*本报告由安全审计系统自动生成 | 日期: {report_date}*",
        ])
        report_text = "\n".join(lines)

    elif report_type == "html":
        html = [
            "<html><head><meta charset='utf-8'><style>",
            "body{font-family:sans-serif;margin:20px} table{border-collapse:collapse;width:100%}",
            "th,td{border:1px solid #ddd;padding:8px} th{background:#f2f2f2}",
            ".critical{color:red} .high{color:orange} .medium{color:#cc8800} .low{color:green}",
            "</style></head><body>",
            f"<h1>安全审计报告</h1>",
            f"<p><strong>日期</strong>: {report_date} | <strong>风险等级</strong>: <span class='{risk_level.lower()}'>{risk_level}</span> | <strong>风险评分</strong>: {total_score}/{max_possible:.0f}</p>",
            f"<h2>风险摘要</h2><table><tr><th>严重度</th><th>数量</th></tr>"
        ]
        for sev in ["严重", "高", "中", "低"]:
            html.append(f"<tr><td class='{sev.lower()}'>{sev}</td><td>{by_severity.get(sev, 0)}</td></tr>")
        html.append("</table>")

        html.append("<h2>详细发现</h2>")
        for module, findings in by_module.items():
            html.append(f"<h3>{module}</h3><ul>")
            for f in findings:
                sev = f.get("severity", "低")
                html.append(f"<li class='{sev.lower()}'><strong>[{sev}]</strong> {f.get('title', f.get('description', ''))}</li>")
            html.append("</ul>")

        html.append(f"<h2>合规映射</h2>")
        for standard, items in compliance_mapping.items():
            html.append(f"<h3>{standard}</h3><table><tr><th>控制域</th><th>发现数</th></tr>")
            for domain, count in items.items():
                html.append(f"<tr><td>{domain}</td><td>{count}</td></tr>")
            html.append("</table>")

        html.append("</body></html>")
        report_text = "\n".join(html)

    elif report_type == "summary":
        report_text = json.dumps({
            "date": report_date,
            "risk_level": risk_level,
            "risk_score": total_score,
            "total_findings": len(all_findings),
            "by_severity": dict(by_severity),
            "by_module": {k: len(v) for k, v in by_module.items()}
        }, ensure_ascii=False, indent=2)
    else:
        report_text = ""

    return {
        "report_type": report_type,
        "report_text": report_text,
        "risk_summary": {
            "total_findings": len(all_findings),
            "risk_level": risk_level,
            "risk_score": total_score,
            "risk_percentage": round(risk_percentage, 1),
            "by_severity": dict(by_severity),
            "by_module": {k: len(v) for k, v in by_module.items()}
        },
        "compliance_mapping": compliance_mapping
    }


# ---------------------------------------------------------------------------
# 主程序入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("IT安全审计工具 - security-auditor")
    print("高级算法版本 (Shannon熵/3σ/CVSS/SHA-256)")
    print("=" * 60)

    # 测试1: 密码强度分析
    print("\n[1] 密码强度分析:")
    for pwd in ["password", "P@ssw0rd123!", "abc123", "X7#kM9$vL2!nQ"]:
        result = password_strength_analyzer(pwd)
        print(f"  '{pwd[:10]}...' -> 评分={result['score']}, 等级={result['strength_level']}, 熵={result['entropy']}")

    # 测试2: 日志异常检测
    print("\n[2] 日志异常检测:")
    logs = [
        {"timestamp": "1700000000", "event_type": "auth_failed", "source_ip": "192.168.1.100", "message": "Failed login"},
        {"timestamp": "1700000010", "event_type": "auth_failed", "source_ip": "192.168.1.100", "message": "Failed login"},
        {"timestamp": "1700000020", "event_type": "auth_failed", "source_ip": "192.168.1.100", "message": "Failed login"},
        {"timestamp": "1700000030", "event_type": "auth_failed", "source_ip": "192.168.1.100", "message": "Failed login"},
        {"timestamp": "1700000040", "event_type": "auth_failed", "source_ip": "192.168.1.100", "message": "Failed login"},
        {"timestamp": "1700000050", "event_type": "port_scan", "source_ip": "10.0.0.5", "message": "Port scan: port 22"},
        {"timestamp": "1700000060", "event_type": "port_scan", "source_ip": "10.0.0.5", "message": "Port scan: port 80"},
    ]
    anomaly = log_anomaly_detector(logs)
    print(f"  异常数: {len(anomaly['anomalies'])}, 模式: {len(anomaly['patterns_detected'])}")
    for p in anomaly["patterns_detected"]:
        print(f"    - {p['pattern']}: {p['description']}")

    # 测试3: 系统健康检查
    print("\n[3] 系统健康检查:")
    health = system_health_checker({
        "cpu_usage": 45, "memory_usage": 72, "disk_usage": 85,
        "network_latency": 15, "packet_loss": 0.5, "process_count": 320, "zombie_count": 0
    })
    print(f"  总分: {health['total_score']}, 等级: {health['health_level']}")
    print(f"  瓶颈: {[b['dimension'] for b in health['bottlenecks']]}")

    # 测试4: 备份完整性验证
    print("\n[4] 备份完整性验证:")
    backup_files = [
        {"path": "/data/app.conf", "size": 1024, "hash": hashlib.sha256(b"config_v1").hexdigest(), "backup_date": "2025-01-01"},
        {"path": "/data/users.db", "size": 0, "hash": hashlib.sha256(b"").hexdigest(), "backup_date": "2025-01-01"},
        {"path": "/data/old.log", "size": 5000, "hash": hashlib.sha256(b"old_log").hexdigest(), "backup_date": "2025-01-01"},
    ]
    source = {
        "/data/app.conf": hashlib.sha256(b"config_v1").hexdigest(),
        "/data/users.db": hashlib.sha256(b"user_database").hexdigest(),
        "/data/report.pdf": hashlib.sha256(b"pdf_content").hexdigest(),
    }
    backup_result = backup_integrity_verifier(backup_files, source)
    print(f"  完整性: {backup_result['report']['integrity_rate']}%, 状态: {backup_result['report']['overall_status']}")
    print(f"  丢失: {len(backup_result['missing_files'])}, 变更: {len(backup_result['changed_files'])}, 多余: {len(backup_result['extra_files'])}")

    print("\n" + "=" * 60)
    print("所有工具已就绪，可通过导入 main 模块使用。")
