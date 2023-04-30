---
title: A Shockingly Simple Bug in Windows CLFS (CVE-2022-24481)
published: true
---

# Introduction

Complex code contains complex bugs. For this reason, Microsoft stuck an incredibly complex log parsing system into their kernel. Called the Common Log File System (CLFS), it has [proven](https://www.zscaler.com/blogs/security-research/technical-analysis-windows-clfs-zero-day-vulnerability-cve-2022-37969-part) [remarkably](https://blog.exodusintel.com/2022/03/10/exploiting-a-use-after-free-in-windows-common-logging-file-system-clfs/) [resiliant](https://www.pixiepointsecurity.com/blog/nday-cve-2022-24521.html) [to](https://blog.northseapwn.top/2022/11/11/Windows-Kernel-Exploit-CVE-2022-35803-in-Common-Log-File-System/index.html) [bugs](https://www.pixiepointsecurity.com/blog/nday-cve-2022-24521.html) over the years, and given birth to at [least](https://www.bleepingcomputer.com/news/security/windows-zero-day-vulnerability-exploited-in-ransomware-attacks/) [two](https://www.helpnetsecurity.com/2023/02/14/microsoft-patches-three-exploited-zero-days-cve-2023-21715-cve-2023-23376-cve-2023-21823/) exploited-in-the-wild vulnerabilities this year alone. As such, an understanding of how CLFS works (and how it can be broken) is quite a useful tool for Windows vulnerability researchers. Today, we will develop such an understanding by going through one such vulnerability -- CVE-2022-24481 -- and seeing how a complex system can contain simple bugs as well.

(This writeup will largely follow [northseapwn's excellent writeup of the same bug](https://blog.northseapwn.top/2022/11/11/Windows-Kernel-Exploit-CVE-2022-35803-in-Common-Log-File-System/index.html?trk=public_post_comment-text). However, we hope to add some exposition on CLFS as a whole, as well as example code for how such a bug might be exploited for privilege escalation.

# CLFS Primer
