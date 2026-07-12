#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IT安全审计工具 - security-auditor
提供10个安全审计工具：密码强度检测、日志分析、系统健康检查、漏洞扫描框架、
防火墙规则审计、SSL证书检查、权限审计、安全报告生成、事件响应追踪、备份验证器。

无外部依赖，仅使用Python标准库。
"""

import re
import json
import os
import platform
import socket
import ssl
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# 1. 密码强度检测
# ---------------------------------------------------------------------------
def password_strength_checker(password):
    """
    密码强度检测：评估密码的安全性，包括长度、复杂度和常见密码库检查。

    参数:
        password (str): 待检测的密码字符串。

    返回:
        dict: 密码强度报告，含评分、等级、问题列表和改进建议。
    """
    # 常见弱密码库
    common_passwords = {
        "123456", "password", "123456789", "12345678", "12345",
        "qwerty", "abc123", "111111", "1234567", "password1",
        "admin", "letmein", "welcome", "monkey", "1234567890",
        "iloveyou", "000000", "sunshine", "princess", "football",
        "654321", "superman", "hello", "master", "dragon"
    }

    score = 0
    issues = []
    suggestions = []

    # 长度检查
    length = len(password)
    if length >= 16:
        score += 25
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 4:
        score += 5
    else:
        issues.append("密码长度过短（少于4位）")
        suggestions.append("建议密码长度至少12位以上")

    # 复杂度检查
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password))

    char_types = sum([has_lower, has_upper, has_digit, has_special])
    score += char_types * 10

    if not has_lower:
        issues.append("缺少小写字母")
        suggestions.append("添加小写字母（a-z）")
    if not has_upper:
        issues.append("缺少大写字母")
        suggestions.append("添加大写字母（A-Z）")
    if not has_digit:
        issues.append("缺少数字")
        suggestions.append("添加数字（0-9）")
    if not has_special:
        issues.append("缺少特殊字符")
        suggestions.append("添加特殊字符（如!@#$%^&*）")

    # 常见密码检查
    if password.lower() in common_passwords:
        score -= 30
        issues.append("密码在常见弱密码库中")
        suggestions.append("该密码极易被破解，请立即更换")

    # 连续字符检查
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("存在连续重复字符")
        suggestions.append("避免连续重复字符（如aaa、111）")

    # 顺序字符检查
    sequences = ["abcdef", "123456", "qwerty", "asdfgh"]
    for seq in sequences:
        if seq in password.lower():
            score -= 15
            issues.append(f"包含顺序字符模式: {seq}")
            suggestions.append("避免使用键盘顺序或字母数字序列")
            break

    # 限制分数范围
    score = max(0, min(score, 100))

    # 确定等级
    if score >= 80:
        level = "强"
        verdict = "密码强度良好"
    elif score >= 60:
        level = "中等"
        verdict = "密码强度一般，建议改进"
    elif score >= 40:
        level = "弱"
        verdict = "密码强度较弱，建议更换"
    else:
        level = "极弱"
        verdict = "密码极不安全，必须立即更换"

    return {
        "password_length": length,
        "score": score,
        "level": level,
        "verdict": verdict,
        "character_types": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digit,
            "special": has_special,
            "total_types": char_types
        },
        "issues": issues,
        "suggestions": suggestions,
        "estimated_crack_time": _estimate_crack_time(length, char_types)
    }


def _estimate_crack_time(length, char_types):
    """估算暴力破解所需时间。"""
    charset_size = 0
    if char_types >= 1:
        charset_size += 26
    if char_types >= 2:
        charset_size += 26
    if char_types >= 3:
        charset_size += 10
    if char_types >= 4:
        charset_size += 32

    if charset_size == 0:
        return "即时"

    combinations = charset_size ** length
    seconds = combinations / 1e10  # 假设每秒10亿次尝试

    if seconds < 1:
        return "即时"
    elif seconds < 60:
        return f"{int(seconds)}秒"
    elif seconds < 3600:
        return f"{int(seconds / 60)}分钟"
    elif seconds < 86400:
        return f"{int(seconds / 3600)}小时"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)}天"
    elif seconds < 31536000 * 100:
        return f"{int(seconds / 31536000)}年"
    elif seconds < 31536000 * 1e6:
        return f"{int(seconds / 31536000 / 1000)}千年"
    else:
        return "数百万年以上"


# ---------------------------------------------------------------------------
# 2. 日志分析器
# ---------------------------------------------------------------------------
def log_analyzer(log_file, patterns=None, severity_levels=None):
    """
    日志分析器：解析日志文件，按模式和严重级别分析。

    参数:
        log_file (str): 日志文件路径或日志文本内容。
        patterns (list[str]): 需要匹配的正则模式列表，为None时使用默认模式。
        severity_levels (list[str]): 需关注的严重级别，如 ["ERROR", "WARNING", "CRITICAL"]，
            为None时关注所有级别。

    返回:
        dict: 日志分析报告，含统计、匹配项和异常摘要。
    """
    if patterns is None:
        patterns = [
            r'(?i)\bERROR\b',
            r'(?i)\bWARNING\b',
            r'(?i)\bCRITICAL\b',
            r'(?i)\bFATAL\b',
            r'(?i)\bFAIL(?:ED|URE)?\b',
            r'(?i)\bexception\b',
            r'(?i)\btimeout\b',
            r'(?i)\bdenied\b'
        ]

    if severity_levels is None:
        severity_levels = ["ERROR", "WARNING", "CRITICAL", "FATAL", "INFO", "DEBUG"]

    # 读取日志内容
    if os.path.isfile(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    else:
        # 当作文本处理
        lines = log_file.split("\n")

    # 分析结果
    total_lines = len(lines)
    level_counts = {level: 0 for level in severity_levels}
    pattern_matches = {f"pattern_{i}": 0 for i in range(len(patterns))}
    matched_lines = []
    timestamps = []

    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()

        # 检查严重级别
        for level in severity_levels:
            if re.search(rf'(?i)\b{level}\b', line_stripped):
                level_counts[level] += 1
                if level in ("ERROR", "CRITICAL", "FATAL"):
                    matched_lines.append({
                        "line_number": line_num,
                        "level": level,
                        "content": line_stripped[:200],
                        "timestamp": _extract_timestamp(line_stripped)
                    })

        # 检查自定义模式
        for i, pattern in enumerate(patterns):
            if re.search(pattern, line_stripped):
                pattern_matches[f"pattern_{i}"] += 1

    # 提取时间戳
    for ml in matched_lines:
        if ml["timestamp"]:
            timestamps.append(ml["timestamp"])

    # 计算错误密度
    error_total = sum(level_counts.get(l, 0) for l in ["ERROR", "CRITICAL", "FATAL"])
    error_density = round(error_total / total_lines * 100, 2) if total_lines > 0 else 0

    return {
        "total_lines": total_lines,
        "severity_distribution": level_counts,
        "pattern_matches": pattern_matches,
        "critical_lines": matched_lines[:50],  # 限制输出数量
        "total_critical": len(matched_lines),
        "error_density": f"{error_density}%",
        "analysis_summary": {
            "has_critical_errors": level_counts.get("CRITICAL", 0) + level_counts.get("FATAL", 0) > 0,
            "error_count": level_counts.get("ERROR", 0),
            "warning_count": level_counts.get("WARNING", 0),
            "recommendation": "存在严重错误，建议立即排查" if error_total > 0 else "日志未发现严重问题"
        }
    }


def _extract_timestamp(line):
    """从日志行中提取时间戳。"""
    ts_patterns = [
        r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})',
        r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2})',
        r'(\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\])'
    ]
    for pattern in ts_patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


# ---------------------------------------------------------------------------
# 3. 系统健康检查
# ---------------------------------------------------------------------------
def system_health_checker(checks=None):
    """
    系统健康检查：检查CPU、内存、磁盘和网络状态。

    参数:
        checks (list[str]): 需要检查的项目，如 ["cpu", "memory", "disk", "network"]，
            为None时检查所有项目。

    返回:
        dict: 系统健康报告，含各项指标和总体状态。
    """
    if checks is None:
        checks = ["cpu", "memory", "disk", "network", "system_info"]

    report = {
        "check_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "checks": {},
        "overall_status": "健康"
    }

    # CPU检查
    if "cpu" in checks:
        cpu_info = {
            "processor": platform.processor() or "未知",
            "cpu_count": os.cpu_count() or 0,
            "load_average": None
        }
        # 尝试获取负载平均值（仅Unix）
        try:
            load_avg = os.getloadavg()
            cpu_info["load_average"] = {
                "1min": load_avg[0],
                "5min": load_avg[1],
                "15min": load_avg[2]
            }
            cpu_core = cpu_info["cpu_count"] or 1
            if load_avg[0] > cpu_core * 0.8:
                report["checks"]["cpu"] = {**cpu_info, "status": "负载偏高"}
                report["overall_status"] = "需关注"
            else:
                report["checks"]["cpu"] = {**cpu_info, "status": "正常"}
        except (AttributeError, OSError):
            report["checks"]["cpu"] = {**cpu_info, "status": "正常（Windows不支持负载均值）"}

    # 内存检查
    if "memory" in checks:
        mem_info = {"status": "正常", "total": None, "available": None, "usage_percent": None}
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            mem_info["process_memory_mb"] = round(usage.ru_maxrss / 1024, 2) if hasattr(usage, 'ru_maxrss') else None
        except (ImportError, AttributeError):
            mem_info["note"] = "详细内存信息需要系统特定工具"
        report["checks"]["memory"] = mem_info

    # 磁盘检查
    if "disk" in checks:
        disk_info = {"status": "正常", "partitions": []}
        try:
            import shutil
            if platform.system() == "Windows":
                drives = ["C:\\", "D:\\"]
                for drive in drives:
                    if os.path.exists(drive):
                        total, used, free = shutil.disk_usage(drive)
                        usage_pct = round(used / total * 100, 1)
                        disk_info["partitions"].append({
                            "drive": drive,
                            "total_gb": round(total / 1e9, 1),
                            "used_gb": round(used / 1e9, 1),
                            "free_gb": round(free / 1e9, 1),
                            "usage_percent": usage_pct,
                            "status": "空间不足" if usage_pct > 85 else "正常"
                        })
                        if usage_pct > 85:
                            disk_info["status"] = "磁盘空间不足"
                            report["overall_status"] = "需关注"
            else:
                disk_info["partitions"].append({
                    "path": "/",
                    "status": "使用shutil.disk_usage获取"
                })
                total, used, free = shutil.disk_usage("/")
                usage_pct = round(used / total * 100, 1)
                disk_info["partitions"][0].update({
                    "total_gb": round(total / 1e9, 1),
                    "used_gb": round(used / 1e9, 1),
                    "free_gb": round(free / 1e9, 1),
                    "usage_percent": usage_pct
                })
        except Exception as e:
            disk_info["status"] = f"检查失败: {str(e)}"
        report["checks"]["disk"] = disk_info

    # 网络检查
    if "network" in checks:
        net_info = {"status": "正常", "hostname": socket.gethostname()}
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            net_info["local_ip"] = ip
        except socket.gaierror:
            net_info["local_ip"] = "无法获取"
        report["checks"]["network"] = net_info

    # 系统信息
    if "system_info" in checks:
        report["checks"]["system_info"] = {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "python_version": platform.python_version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "未知"
        }

    return report


# ---------------------------------------------------------------------------
# 4. 漏洞扫描框架
# ---------------------------------------------------------------------------
def vulnerability_scanner(target_info, scan_type="basic"):
    """
    漏洞扫描框架：对目标进行基础安全扫描。

    参数:
        target_info (dict): 目标信息，含 host、port、service 等字段。
        scan_type (str): 扫描类型，可选 "basic"（基础扫描）、"port_scan"（端口扫描）、
            "service_scan"（服务扫描）、"full"（全面扫描），默认 "basic"。

    返回:
        dict: 扫描结果，含发现漏洞、端口状态和建议。
    """
    host = target_info.get("host", "localhost")
    ports = target_info.get("ports", [22, 80, 443, 3306, 8080, 8443])
    service = target_info.get("service", "")

    results = {
        "target": host,
        "scan_type": scan_type,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": [],
        "closed_ports": [],
        "vulnerabilities": [],
        "recommendations": []
    }

    # 端口扫描
    if scan_type in ("basic", "port_scan", "full"):
        for port in ports:
            port_status = _check_port(host, port)
            if port_status["open"]:
                results["open_ports"].append(port_status)
            else:
                results["closed_ports"].append(port_status)

    # 已知漏洞模式检测
    known_vulns = {
        22: {"name": "SSH服务", "risks": ["弱密码风险", "默认端口易被扫描"],
             "recommendation": "禁用密码登录，使用密钥认证，修改默认端口"},
        21: {"name": "FTP服务", "risks": ["明文传输", "匿名访问风险"],
             "recommendation": "使用SFTP替代，禁用匿名访问"},
        3306: {"name": "MySQL数据库", "risks": ["远程访问风险", "默认弱配置"],
               "recommendation": "限制远程访问IP，修改默认配置"},
        6379: {"name": "Redis缓存", "risks": ["未授权访问", "默认无密码"],
               "recommendation": "设置密码，绑定本地地址"},
        27017: {"name": "MongoDB数据库", "risks": ["未授权访问", "默认无认证"],
                "recommendation": "启用认证，限制网络访问"},
        8080: {"name": "HTTP代理/管理端口", "risks": ["管理界面暴露", "弱认证"],
               "recommendation": "限制访问IP，启用强认证"},
        3389: {"name": "远程桌面(RDP)", "risks": ["暴力破解", "漏洞利用"],
               "recommendation": "启用网络级认证，限制访问来源"},
        445: {"name": "SMB共享", "risks": ["勒索病毒利用", "未授权共享"],
              "recommendation": "关闭不必要的共享，更新补丁"}
    }

    for open_port in results["open_ports"]:
        port_num = open_port["port"]
        if port_num in known_vulns:
            vuln = known_vulns[port_num]
            results["vulnerabilities"].append({
                "port": port_num,
                "service": vuln["name"],
                "severity": "高" if port_num in (3306, 6379, 27017, 3389) else "中",
                "risks": vuln["risks"],
                "recommendation": vuln["recommendation"]
            })
            results["recommendations"].append(vuln["recommendation"])

    # 服务扫描
    if scan_type in ("service_scan", "full") and service:
        results["service_scan"] = {
            "target_service": service,
            "note": f"针对{service}的服务级扫描需要专用工具，建议使用Nessus或OpenVAS。"
        }

    # 风险评估
    high_risk = len([v for v in results["vulnerabilities"] if v["severity"] == "高"])
    medium_risk = len([v for v in results["vulnerabilities"] if v["severity"] == "中"])

    results["risk_summary"] = {
        "total_vulnerabilities": len(results["vulnerabilities"]),
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "open_port_count": len(results["open_ports"]),
        "overall_risk": "高风险" if high_risk > 0 else ("中风险" if medium_risk > 0 else "低风险")
    }

    if not results["recommendations"]:
        results["recommendations"].append("未发现明显漏洞，建议保持定期扫描和安全更新。")

    return results


def _check_port(host, port, timeout=1):
    """检查端口是否开放。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = _identify_service(port)
            return {"port": port, "open": True, "service": service, "state": "open"}
        else:
            return {"port": port, "open": False, "service": "", "state": "closed"}
    except (socket.gaierror, socket.timeout, OSError):
        return {"port": port, "open": False, "service": "", "state": "filtered"}


def _identify_service(port):
    """根据端口号识别常见服务。"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        27017: "MongoDB", 9200: "Elasticsearch"
    }
    return services.get(port, "未知")


# ---------------------------------------------------------------------------
# 5. 防火墙规则审计
# ---------------------------------------------------------------------------
def firewall_rule_auditor(rules, policy="default_deny"):
    """
    防火墙规则审计：审查防火墙规则的安全性和合规性。

    参数:
        rules (list[dict]): 防火墙规则列表，每项含 id、action(allow/deny)、
            protocol、source_ip、source_port、dest_ip、dest_port。
        policy (str): 默认策略，可选 "default_deny"（默认拒绝）或
            "default_allow"（默认允许），默认 "default_deny"。

    返回:
        dict: 审计报告，含规则分析、安全风险和建议。
    """
    audit = {
        "total_rules": len(rules),
        "policy": policy,
        "allow_rules": 0,
        "deny_rules": 0,
        "issues": [],
        "redundant_rules": [],
        "overly_permissive": [],
        "recommendations": []
    }

    for i, rule in enumerate(rules):
        action = rule.get("action", "").lower()

        if action == "allow":
            audit["allow_rules"] += 1
        elif action == "deny":
            audit["deny_rules"] += 1

        # 检查过于宽松的规则
        source_ip = rule.get("source_ip", "")
        dest_ip = rule.get("dest_ip", "")
        dest_port = rule.get("dest_port", "")

        if action == "allow":
            # 允许任意来源
            if source_ip in ("0.0.0.0/0", "any", "*", "ANY"):
                issue = {
                    "rule_id": rule.get("id", i + 1),
                    "issue": "允许任意来源访问",
                    "severity": "高",
                    "detail": f"规则允许来自任意IP的{rule.get('protocol', 'tcp')}流量到端口{dest_port}",
                    "suggestion": "限制来源IP范围，仅允许必要的IP段"
                }
                audit["overly_permissive"].append(issue)
                audit["issues"].append(issue)

            # 允许任意端口
            if dest_port in ("any", "*", "0-65535", "ALL"):
                issue = {
                    "rule_id": rule.get("id", i + 1),
                    "issue": "允许访问所有端口",
                    "severity": "高",
                    "detail": f"规则允许访问所有端口，存在极大安全风险",
                    "suggestion": "仅开放必要端口"
                }
                audit["overly_permissive"].append(issue)
                audit["issues"].append(issue)

            # 检查高危端口
            high_risk_ports = [22, 23, 3389, 445, 3306, 6379, 27017]
            try:
                if int(dest_port) in high_risk_ports:
                    issue = {
                        "rule_id": rule.get("id", i + 1),
                        "issue": f"允许访问高危端口 {dest_port}",
                        "severity": "中",
                        "detail": f"端口{dest_port}为高危端口，需确保访问来源受控",
                        "suggestion": "确保仅信任IP可访问该端口"
                    }
                    audit["issues"].append(issue)
            except (ValueError, TypeError):
                pass

    # 检查冗余规则
    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):
            r1 = rules[i]
            r2 = rules[j]
            if (r1.get("action") == r2.get("action") and
                r1.get("source_ip") == r2.get("source_ip") and
                r1.get("dest_ip") == r2.get("dest_ip") and
                r1.get("dest_port") == r2.get("dest_port") and
                r1.get("protocol") == r2.get("protocol")):
                audit["redundant_rules"].append({
                    "rule_ids": [r1.get("id", i + 1), r2.get("id", j + 1)],
                    "issue": "存在重复规则",
                    "suggestion": "删除冗余规则以简化规则集"
                })

    # 策略检查
    if policy == "default_allow":
        audit["recommendations"].append("当前默认策略为'允许'，建议改为'默认拒绝'以提高安全性。")
    else:
        audit["recommendations"].append("默认拒绝策略是良好实践，保持当前配置。")

    if audit["overly_permissive"]:
        audit["recommendations"].append(f"发现{len(audit['overly_permissive'])}条过于宽松的规则，建议收紧。")

    if audit["redundant_rules"]:
        audit["recommendations"].append(f"发现{len(audit['redundant_rules'])}组冗余规则，建议清理。")

    audit["overall_status"] = "高风险" if len(audit["overly_permissive"]) > 2 else ("中风险" if audit["issues"] else "低风险")

    return audit


# ---------------------------------------------------------------------------
# 6. SSL证书检查
# ---------------------------------------------------------------------------
def ssl_certificate_checker(domain):
    """
    SSL证书检查：检查域名的SSL证书信息。

    参数:
        domain (str): 要检查的域名，如 "www.example.com"。

    返回:
        dict: SSL证书信息，含有效期、颁发者、算法等。
    """
    result = {
        "domain": domain,
        "check_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "has_ssl": False,
        "certificate_info": None,
        "warnings": [],
        "status": "未知"
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    result["has_ssl"] = True

                    # 解析证书信息
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (not_after - datetime.now()).days

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))

                    san_list = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        san_list.append(san_value)

                    result["certificate_info"] = {
                        "subject": subject.get("commonName", "未知"),
                        "issuer": issuer.get("commonName", "未知"),
                        "issuer_org": issuer.get("organizationName", "未知"),
                        "valid_from": not_before.strftime("%Y-%m-%d"),
                        "valid_to": not_after.strftime("%Y-%m-%d"),
                        "days_remaining": days_remaining,
                        "serial_number": cert.get("serialNumber", "未知"),
                        "version": cert.get("version", "未知"),
                        "san_domains": san_list[:10]
                    }

                    # 证书版本检查
                    if cert.get("version", 0) < 3:
                        result["warnings"].append("证书版本低于v3，建议升级。")

                    # 有效期检查
                    if days_remaining < 0:
                        result["warnings"].append(f"证书已过期 {-days_remaining} 天！")
                        result["status"] = "已过期"
                    elif days_remaining < 30:
                        result["warnings"].append(f"证书将在 {days_remaining} 天后过期，请及时续期。")
                        result["status"] = "即将过期"
                    else:
                        result["status"] = "有效"

                    # SAN检查
                    if domain not in san_list and subject.get("commonName") != domain:
                        result["warnings"].append(f"域名 {domain} 不在证书的SAN列表中。")

    except socket.gaierror:
        result["warnings"].append(f"无法解析域名: {domain}")
        result["status"] = "域名解析失败"
    except socket.timeout:
        result["warnings"].append(f"连接 {domain}:443 超时")
        result["status"] = "连接超时"
    except ssl.SSLError as e:
        result["warnings"].append(f"SSL错误: {str(e)}")
        result["status"] = "SSL错误"
    except ConnectionRefusedError:
        result["warnings"].append(f"连接被拒绝，{domain} 可能未启用HTTPS")
        result["status"] = "未启用HTTPS"
    except Exception as e:
        result["warnings"].append(f"检查失败: {str(e)}")
        result["status"] = "检查失败"

    return result


# ---------------------------------------------------------------------------
# 7. 权限审计
# ---------------------------------------------------------------------------
def permission_auditor(file_paths, expected_permissions=None):
    """
    权限审计：检查文件和目录的权限设置是否安全。

    参数:
        file_paths (list[str]): 文件或目录路径列表。
        expected_permissions (dict): 期望权限映射，键为路径，值为期望权限如 "600"。
            为None时不做期望对比。

    返回:
        dict: 权限审计报告，含每项的权限状态和风险。
    """
    audit = {
        "total_paths": len(file_paths),
        "audited": [],
        "issues": [],
        "recommendations": []
    }

    for path in file_paths:
        item = {
            "path": path,
            "exists": os.path.exists(path),
            "type": "目录" if os.path.isdir(path) else ("文件" if os.path.isfile(path) else "不存在"),
            "permissions": None,
            "permissions_octal": None,
            "status": "正常"
        }

        if item["exists"]:
            stat_info = os.stat(path)
            mode = stat_info.st_mode
            perm_octal = oct(mode & 0o777)

            item["permissions_octal"] = perm_octal
            item["permissions"] = _format_permissions(mode)

            # 检查权限安全性
            world_writable = bool(mode & 0o002)
            world_readable = bool(mode & 0o004)
            group_writable = bool(mode & 0o020)
            is_executable = bool(mode & 0o111)

            risks = []
            if world_writable:
                risks.append("全局可写")
                item["status"] = "风险"
            if world_readable and item["type"] == "文件":
                risks.append("全局可读")
            if group_writable:
                risks.append("组可写")

            item["risks"] = risks

            if risks:
                audit["issues"].append({
                    "path": path,
                    "permissions": perm_octal,
                    "risks": risks,
                    "severity": "高" if world_writable else "中",
                    "suggestion": "收紧文件权限，移除全局写权限"
                })

            # 期望权限对比
            if expected_permissions:
                expected = expected_permissions.get(path)
                if expected:
                    expected_octal = "0o" + expected if not expected.startswith("0o") else expected
                    actual = perm_octal
                    if expected_octal != actual:
                        item["mismatch"] = f"期望 {expected_octal}, 实际 {actual}"
                        item["status"] = "权限不匹配"
                        audit["issues"].append({
                            "path": path,
                            "permissions": actual,
                            "expected": expected_octal,
                            "issue": "权限与期望不符",
                            "severity": "中",
                            "suggestion": f"建议设置为 {expected_octal}"
                        })
        else:
            item["status"] = "文件不存在"
            audit["issues"].append({
                "path": path,
                "issue": "路径不存在",
                "severity": "低",
                "suggestion": "检查路径是否正确"
            })

        audit["audited"].append(item)

    if audit["issues"]:
        high_risk = [i for i in audit["issues"] if i.get("severity") == "高"]
        if high_risk:
            audit["recommendations"].append(f"发现{len(high_risk)}个高风险权限问题，建议立即修复。")
        audit["recommendations"].append("建议定期审计敏感文件权限，确保最小权限原则。")
    else:
        audit["recommendations"].append("权限配置良好，未发现安全问题。")

    audit["overall_status"] = "高风险" if any(i.get("severity") == "高" for i in audit["issues"]) else ("需关注" if audit["issues"] else "安全")

    return audit


def _format_permissions(mode):
    """格式化权限为rwx字符串。"""
    perms = ""
    for who in ("USR", "GRP", "OTH"):
        for what in ("R", "W", "X"):
            flag = getattr(os.stat, f"S_I{what}{who}")
            perms += what.lower() if mode & flag else "-"
    return perms


# ---------------------------------------------------------------------------
# 8. 安全报告生成
# ---------------------------------------------------------------------------
def security_report_generator(scan_results, output_format="text"):
    """
    安全报告生成：将安全扫描结果整理为结构化报告。

    参数:
        scan_results (dict): 扫描结果数据，含 scan_type、target、timestamp、
            findings、vulnerabilities 等。
        output_format (str): 输出格式，可选 "text"/"json"/"markdown"，默认 "text"。

    返回:
        str: 格式化的安全报告。
    """
    scan_type = scan_results.get("scan_type", "安全扫描")
    target = scan_results.get("target", "未知目标")
    timestamp = scan_results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    findings = scan_results.get("findings", [])
    vulnerabilities = scan_results.get("vulnerabilities", [])
    recommendations = scan_results.get("recommendations", [])
    overall_risk = scan_results.get("overall_risk", "未知")

    # 统计
    critical_vulns = [v for v in vulnerabilities if v.get("severity") == "严重" or v.get("severity") == "critical"]
    high_vulns = [v for v in vulnerabilities if v.get("severity") == "高" or v.get("severity") == "high"]
    medium_vulns = [v for v in vulnerabilities if v.get("severity") == "中" or v.get("severity") == "medium"]
    low_vulns = [v for v in vulnerabilities if v.get("severity") == "低" or v.get("severity") == "low"]

    stats = {
        "total_vulnerabilities": len(vulnerabilities),
        "critical": len(critical_vulns),
        "high": len(high_vulns),
        "medium": len(medium_vulns),
        "low": len(low_vulns),
        "total_findings": len(findings)
    }

    if output_format == "json":
        report = {
            "report_type": "security_audit",
            "scan_type": scan_type,
            "target": target,
            "timestamp": timestamp,
            "overall_risk": overall_risk,
            "statistics": stats,
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "recommendations": recommendations
        }
        return json.dumps(report, ensure_ascii=False, indent=2)

    elif output_format == "markdown":
        lines = [
            f"# 安全审计报告",
            "",
            f"**扫描类型**: {scan_type}  ",
            f"**目标**: {target}  ",
            f"**扫描时间**: {timestamp}  ",
            f"**总体风险**: {overall_risk}",
            "",
            "## 风险统计",
            "",
            f"| 风险等级 | 数量 |",
            f"|----------|------|",
            f"| 严重 | {stats['critical']} |",
            f"| 高 | {stats['high']} |",
            f"| 中 | {stats['medium']} |",
            f"| 低 | {stats['low']} |",
            f"| **合计** | **{stats['total_vulnerabilities']}** |",
            ""
        ]

        if vulnerabilities:
            lines.append("## 漏洞详情")
            lines.append("")
            for i, v in enumerate(vulnerabilities, 1):
                lines.append(f"### 漏洞 {i}")
                lines.append(f"- **名称**: {v.get('name', v.get('service', '未知'))}")
                lines.append(f"- **严重程度**: {v.get('severity', '未知')}")
                if v.get("port"):
                    lines.append(f"- **端口**: {v.get('port')}")
                if v.get("risks"):
                    lines.append(f"- **风险**: {', '.join(v.get('risks', []))}")
                if v.get("recommendation"):
                    lines.append(f"- **建议**: {v.get('recommendation')}")
                lines.append("")

        if recommendations:
            lines.append("## 安全建议")
            lines.append("")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.append("---")
        lines.append(f"*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    else:  # text format
        lines = [
            "=" * 60,
            f"  安全审计报告",
            "=" * 60,
            "",
            f"  扫描类型: {scan_type}",
            f"  目标: {target}",
            f"  扫描时间: {timestamp}",
            f"  总体风险: {overall_risk}",
            "",
            "-" * 60,
            "  风险统计",
            "-" * 60,
            f"  严重: {stats['critical']}",
            f"  高: {stats['high']}",
            f"  中: {stats['medium']}",
            f"  低: {stats['low']}",
            f"  漏洞总数: {stats['total_vulnerabilities']}",
            "",
        ]

        if vulnerabilities:
            lines.append("-" * 60)
            lines.append("  漏洞详情")
            lines.append("-" * 60)
            for i, v in enumerate(vulnerabilities, 1):
                lines.append(f"  [{i}] {v.get('name', v.get('service', '未知'))}")
                lines.append(f"      严重程度: {v.get('severity', '未知')}")
                if v.get("port"):
                    lines.append(f"      端口: {v.get('port')}")
                if v.get("risks"):
                    lines.append(f"      风险: {', '.join(v.get('risks', []))}")
                if v.get("recommendation"):
                    lines.append(f"      建议: {v.get('recommendation')}")
                lines.append("")

        if recommendations:
            lines.append("-" * 60)
            lines.append("  安全建议")
            lines.append("-" * 60)
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        lines.append("=" * 60)
        lines.append(f"  报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 9. 事件响应追踪
# ---------------------------------------------------------------------------
def incident_response_tracker(incidents, severity="all"):
    """
    事件响应追踪：追踪安全事件的响应和处理状态。

    参数:
        incidents (list[dict]): 安全事件列表，每项含 id、title、severity、status、
            detected_at、assigned_to、description。
        severity (str): 筛选严重级别，可选 "all"/"critical"/"high"/"medium"/"low"，
            默认 "all"。

    返回:
        dict: 事件追踪报告，含状态统计和优先处理项。
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    # 筛选
    if severity != "all":
        filtered = [inc for inc in incidents if inc.get("severity", "").lower() == severity.lower()]
    else:
        filtered = list(incidents)

    # 排序
    filtered.sort(key=lambda x: severity_order.get(x.get("severity", "").lower(), 99))

    # 统计
    all_incidents = incidents
    stats = {
        "total": len(all_incidents),
        "critical": len([i for i in all_incidents if i.get("severity", "").lower() == "critical"]),
        "high": len([i for i in all_incidents if i.get("severity", "").lower() == "high"]),
        "medium": len([i for i in all_incidents if i.get("severity", "").lower() == "medium"]),
        "low": len([i for i in all_incidents if i.get("severity", "").lower() == "low"]),
        "open": len([i for i in all_incidents if i.get("status", "").lower() == "open"]),
        "investigating": len([i for i in all_incidents if i.get("status", "").lower() == "investigating"]),
        "resolved": len([i for i in all_incidents if i.get("status", "").lower() == "resolved"]),
        "closed": len([i for i in all_incidents if i.get("status", "").lower() == "closed"])
    }

    # 响应时间分析
    now = datetime.now()
    for inc in filtered:
        detected = inc.get("detected_at", "")
        if detected:
            try:
                detected_dt = datetime.strptime(detected, "%Y-%m-%d %H:%M:%S")
                response_time = (now - detected_dt).total_seconds() / 3600  # 小时
                inc["hours_since_detection"] = round(response_time, 1)
                if inc.get("status", "").lower() in ("open", "investigating"):
                    if response_time > 72:
                        inc["sla_status"] = "SLA违规"
                    elif response_time > 24:
                        inc["sla_status"] = "接近SLA超时"
                    else:
                        inc["sla_status"] = "SLA正常"
            except (ValueError, TypeError):
                inc["hours_since_detection"] = None

    # 优先处理项
    priority_items = [i for i in filtered if i.get("status", "").lower() in ("open", "investigating") and i.get("severity", "").lower() in ("critical", "high")]

    return {
        "filter": severity,
        "statistics": stats,
        "filtered_incidents": filtered,
        "priority_items": priority_items,
        "action_required": len(priority_items) > 0,
        "sla_violations": [i for i in filtered if i.get("sla_status") == "SLA违规"],
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": f"共{stats['total']}个事件，{stats['open']}个未处理，{stats['critical']}个严重事件"
    }


# ---------------------------------------------------------------------------
# 10. 备份验证器
# ---------------------------------------------------------------------------
def backup_verifier(backup_config, last_backup):
    """
    备份验证器：验证备份配置和最近备份的状态。

    参数:
        backup_config (dict): 备份配置，含 backup_type、frequency、retention_days、
            target_paths、encryption_enabled。
        last_backup (dict): 最近备份信息，含 timestamp、status、size_mb、
            files_count、verification_status。

    返回:
        dict: 备份验证报告，含状态评估和建议。
    """
    now = datetime.now()
    report = {
        "check_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "backup_type": backup_config.get("backup_type", "未知"),
        "frequency": backup_config.get("frequency", "未知"),
        "retention_days": backup_config.get("retention_days", 0),
        "encryption_enabled": backup_config.get("encryption_enabled", False),
        "issues": [],
        "recommendations": [],
        "status": "正常"
    }

    # 检查最近备份时间
    last_backup_time_str = last_backup.get("timestamp", "")
    if last_backup_time_str:
        try:
            last_dt = datetime.strptime(last_backup_time_str, "%Y-%m-%d %H:%M:%S")
            hours_since = (now - last_dt).total_seconds() / 3600

            report["last_backup_time"] = last_backup_time_str
            report["hours_since_last_backup"] = round(hours_since, 1)

            # 根据频率判断是否超时
            frequency = backup_config.get("frequency", "daily")
            expected_hours = {"hourly": 1, "daily": 24, "weekly": 168, "monthly": 720}
            max_hours = expected_hours.get(frequency, 24)

            if hours_since > max_hours * 1.5:
                report["issues"].append({
                    "issue": "备份超时",
                    "detail": f"距上次备份已 {hours_since:.1f} 小时，超出预期({max_hours}小时)的50%",
                    "severity": "高"
                })
                report["status"] = "异常"
            elif hours_since > max_hours:
                report["issues"].append({
                    "issue": "备份延迟",
                    "detail": f"距上次备份已 {hours_since:.1f} 小时，超出预期({max_hours}小时)",
                    "severity": "中"
                })
                report["status"] = "需关注"
        except (ValueError, TypeError):
            report["issues"].append({
                "issue": "备份时间格式错误",
                "detail": f"无法解析时间: {last_backup_time_str}",
                "severity": "低"
            })
    else:
        report["issues"].append({
            "issue": "无备份记录",
            "detail": "未找到最近的备份记录",
            "severity": "高"
        })
        report["status"] = "异常"

    # 检查备份状态
    backup_status = last_backup.get("status", "unknown")
    if backup_status == "failed":
        report["issues"].append({
            "issue": "上次备份失败",
            "detail": "最近一次备份状态为失败，需要立即处理",
            "severity": "严重"
        })
        report["status"] = "异常"
    elif backup_status == "partial":
        report["issues"].append({
            "issue": "部分备份",
            "detail": "上次备份为部分备份，可能存在数据缺失",
            "severity": "中"
        })

    # 检查加密
    if not backup_config.get("encryption_enabled", False):
        report["issues"].append({
            "issue": "备份未加密",
            "detail": "备份数据未启用加密，存在数据泄露风险",
            "severity": "高"
        })
        report["recommendations"].append("建议启用备份加密以保护敏感数据。")

    # 检查验证状态
    verification = last_backup.get("verification_status", "unknown")
    if verification != "verified":
        report["issues"].append({
            "issue": "备份未验证",
            "detail": "上次备份未经过完整性验证",
            "severity": "中"
        })
        report["recommendations"].append("建议定期验证备份数据的完整性和可恢复性。")

    # 检查保留策略
    retention = backup_config.get("retention_days", 0)
    if retention < 7:
        report["issues"].append({
            "issue": "保留期限过短",
            "detail": f"备份保留{retention}天，建议至少保留7天以上",
            "severity": "低"
        })
        report["recommendations"].append("建议增加备份保留期限以支持长期恢复需求。")

    # 检查备份大小
    size_mb = last_backup.get("size_mb", 0)
    if size_mb > 0:
        report["last_backup_size_mb"] = size_mb
    files_count = last_backup.get("files_count", 0)
    if files_count > 0:
        report["last_backup_files"] = files_count

    if not report["issues"]:
        report["status"] = "正常"
        report["recommendations"].append("备份配置良好，建议保持定期验证。")
    else:
        critical = [i for i in report["issues"] if i["severity"] in ("严重", "高")]
        if critical:
            report["status"] = "需要立即处理"

    return report


# ---------------------------------------------------------------------------
# 主程序入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("IT安全审计工具 - security-auditor")
    print("=" * 60)

    # 演示：密码强度检测
    print("\n[1] 密码强度检测示例:")
    pwd_result = password_strength_checker("MyStr0ng!Pass2024")
    print(json.dumps(pwd_result, ensure_ascii=False, indent=2))

    # 演示：系统健康检查
    print("\n[2] 系统健康检查示例:")
    health = system_health_checker(["cpu", "disk", "system_info"])
    print(json.dumps(health, ensure_ascii=False, indent=2))

    # 演示：防火墙规则审计
    print("\n[3] 防火墙规则审计示例:")
    rules = [
        {"id": 1, "action": "allow", "protocol": "tcp", "source_ip": "0.0.0.0/0", "dest_port": "443"},
        {"id": 2, "action": "allow", "protocol": "tcp", "source_ip": "10.0.0.0/8", "dest_port": "22"},
        {"id": 3, "action": "deny", "protocol": "all", "source_ip": "any", "dest_port": "any"}
    ]
    fw_audit = firewall_rule_auditor(rules)
    print(json.dumps(fw_audit, ensure_ascii=False, indent=2))

    print("\n" + "=" * 60)
    print("所有工具已就绪，可通过导入 main 模块使用。")
