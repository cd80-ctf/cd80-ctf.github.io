---
title: A Shockingly Simple Bug in Windows CLFS (CVE-2022-24481)
published: true
---

# Introduction

Complex code contains complex bugs. For this reason, Microsoft stuck an incredibly complex log parsing system into their kernel. Called the Common Log File System (CLFS), it has [proven](https://www.zscaler.com/blogs/security-research/technical-analysis-windows-clfs-zero-day-vulnerability-cve-2022-37969-part) [remarkably](https://blog.exodusintel.com/2022/03/10/exploiting-a-use-after-free-in-windows-common-logging-file-system-clfs/) [resiliant](https://www.pixiepointsecurity.com/blog/nday-cve-2022-24521.html) [to](https://blog.northseapwn.top/2022/11/11/Windows-Kernel-Exploit-CVE-2022-35803-in-Common-Log-File-System/index.html) [bugs](https://www.pixiepointsecurity.com/blog/nday-cve-2022-24521.html) over the years, and given birth to at [least](https://www.bleepingcomputer.com/news/security/windows-zero-day-vulnerability-exploited-in-ransomware-attacks/) [two](https://www.helpnetsecurity.com/2023/02/14/microsoft-patches-three-exploited-zero-days-cve-2023-21715-cve-2023-23376-cve-2023-21823/) exploited-in-the-wild vulnerabilities this year alone. As such, an understanding of how CLFS works (and how it can be broken) is quite a useful tool for Windows vulnerability researchers. Basically, it's an easy target. Today, we will develop such an understanding by going through one such vulnerability -- CVE-2022-24481 -- and seeing how a complex system can contain simple bugs as well.

(This writeup will largely follow [northseapwn's excellent writeup of the same bug](https://blog.northseapwn.top/2022/11/11/Windows-Kernel-Exploit-CVE-2022-35803-in-Common-Log-File-System/index.html). However, we hope to add some exposition on CLFS as a whole, as well as example code for how such a bug might be abused for privilege escalation.)

# CLFS Primer

As the name suggests, CLFS is designed to store logs. As the prelude suggests, it stores them in just about the most convoluted way possible.

In a normal log file, we might expect to find some metadata (probably stored in some sort of header), followed by some data (such as log messages). However, in CLFS, the metadata and log data are kept across multiple files. Instead of a header that contains metadata, we have the **Base Log File**; instead of a file body containing log messages, we have potentially multiple **container files**. A single CLFS log consists of one such Base Log File and one or more containers.
Basically, we can view a CLFS log as what would happen if a "normal" log file exploded and its various fragments were scattered throughout space, but they all somehow continued to function as a single log, frozen in a lattice of immortal agony:

<p align="center">
  <img src="https://raw.githubusercontent.com/cd80-ctf/cd80-ctf.github.io/master/assets/log_explosion.png">
  <div align="center">Figure 1: A normal log file and a CLFS log. For added effect, imagine the log file smiling and all the CLFS fragments screaming.</div>
</p>

Amongst this lattice, we are most interested in the metadata part -- that's the Base Log File (BLF). The BLF is extremely complex and entirely attacker-controlled, so it's an obvious target for exploitation. We will focus on the BLF for the remainder of this writeup.

## The Base Log File

The Base Log File is where the metadata for a CLFS log lives. Because this is CLFS, we'll be three layers of metadata deep by the time we finish describing it. Don't worry: the majority of the detail is unimportant. In fact, we can summarize all we need to know about the structure of a Base Log File pretty quickly: 

- Every part of a CLFS log -- the metadata and the log data -- consists of a series of **Log Blocks**.
- Each **Log Block** consists of a **Log Block Header** (that's metadata layer 2), followed by one or more **Records.** Records are where the actual data is stored.
- The Base Log File is made up of **six Log Blocks**.
- Only three of the BLF's Log Blocks are interesting. The other three are backup copies ("shadows") of the main three, and are [mostly useful for their use-after-free vulnerabilities](https://blog.exodusintel.com/2022/03/10/exploiting-a-use-after-free-in-windows-common-logging-file-system-clfs/).
- The three potentially interesting Log Blocks in the Base Log File are:
  1. The **Control Metadata Block**, which mostly contains metadata about the other metadata blocks (that's metadata layer 3!)
  2. The **Base Metadata Block**, which mostly contains metadata about the actual log data
  3. The **Scratch Metadata Block**, which is a box of discarded toys where Bill Gates throws metadata that didn't fit anywhere else. Currently, this block only contains information about how logs are being truncated.

Of these three potentially interesting Log Blocks, only the Base Metadata Block is actually interesting to us right now.

## The Base Log Block

All Log Blocks contain Records. The Base Log Block of the Base Metadata File of a CLFS log contains one Record, fittingly dubbed the Base Record.

The Base Record of the Base Metadata Block of the Base Log File of a CLFS log (don't worry, it gets worse) contains metadata about the log itself. Specifically, it contains metadata about three things:
- The Clients (i.e. streams) that are storing data in this log,
- The Containers in this log (which, remember, is where actual log messages are kept)
- The Security Descriptors of each Container

The Base Record also stores information about these things -- how many Clients are present, how many Containers, etc. -- in a header called the Base Record Header. The Base Record Header of the Base Record of the Base Metadata Block of the Base Log File of a CLFS log. Isn't that great?

If you're getting confused, don't worry: so is Microsoft. In fact, we already know almost all we need to know to understand the vulnerability. Basically, all we have to do is lay out the Base Record Header, ask the most obvious security question that the structure presents to us, and be rewarded with a dirt simple privilege escalation that's been hiding since Windows Vista. Take heart: the hard part is almost done.
