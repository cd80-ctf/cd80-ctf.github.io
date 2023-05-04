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

## The Base Metadata Block

All Log Blocks contain Records. The Base Metadata Block of the Base Metadata File of a CLFS log contains one Record, fittingly dubbed the Base Record.

The Base Record of the Base Metadata Block of the Base Log File of a CLFS log (don't worry, it gets worse) contains metadata about the log itself. Specifically, it contains metadata about three things:
- The Clients (i.e. streams) that are storing data in this log,
- The Containers in this log (which, remember, is where actual log messages are kept)
- The Security Descriptors of each Container

The Base Record also stores information about these things -- how many Clients are present, how many Containers, etc. -- in a header called the Base Record Header. The Base Record Header of the Base Record of the Base Metadata Block of the Base Log File of a CLFS log. Isn't that great?

If you're getting confused, don't worry: so is Microsoft. In fact, we already know almost all we need to know to understand the vulnerability. Basically, all we have to do is lay out the Base Record Header, ask the most obvious security question that the structure presents to us, and be rewarded with a dirt simple privilege escalation that's been hiding since Windows Vista. Take heart: the hard part is almost done.

## The Base Record Header

The Base Record Header is where CVE-2022-24481 sleeps. Since we've already done our homework on the Base Record, we should be able to sightread the struct pretty easily. Here it is, annotated where necessary:

```c
struct _CLFS_BASE_RECORD_HEADER {
  ulongulong DumpCount;  // essentially an update count with a fancy name
  uchar LogId[16];
  ulonglong ClientSymbolHashTable[11];  // hash table for looking up client metadata
  ulonglong ContainerSymbolHashTable[11];  // " for container metadata
  ulonglong SecuritySymbolHashTable[11];  // " for security context metadata
  ulong NextAvailableContainerIndex;
  ulong NextAvailableClientIndex;
  ulong NumFreeContainers;  // unused(?)
  ulong NumActiveContainers;  // unused(?)
  ulonglong Unused;
  ulong ClientMetadataOffsets[124];  // offsets to each client metadata struct
  ulong ContainerMetadataOffsets[1024];  // offsets to each container metadata struct
  ulong NextAvailableSymbolOffset;  // next available offset for some client, container, or security metadata
  ulong Unused;
  ushort Unused;
  uchar LogState;
  uchar NextContainerUsn;  // next unique sequence number (basically, a UUID) for a container
  uchar NumClients;
}
```

There is some complexity hiding in this struct. For example, the hash tables for looking up different types of metadata might deserve a deeper dive in another writeup. Thankfully for us, this is entirely unnecessary, because the bug is already hiding right under our nose.

Consider this struct for a second. Suppose we were an attacker with full control of this struct (which we are). What is the first tricky thing we might do to see if we could confuse the kernel?

The first thought that might come to mind is type confusion. We have two arrays (`ClientMetadataOffsets` and `ContainerMetadataOffsets`) which contain the offsets of two different types of structs (client metadata and container metadata). What if we could make two of those offsets overlap? Could we line up
a sensitive field of one struct (say, a kernel pointer) with an easily controllable field of another (say, the creation time)?

There's no way that's the bug, is there?

## That's Literally The Bug

Remember when I said simple bugs? I wasn't kidding. In the official parlance, **CVE-2022-24481 is a type confusion vulnerability in CLFS due to insufficient offset validation in the Base Record Header.** In the common parlance, no one at Microsoft looked at this struct for the five seconds necessary to realize
that we could create horrible *The Fly*-style conglomerations of client and container metadata. Doing so allows us to fake any field in either struct, which, inevitably, will lead to privilege escalation.

# Simple Bug, Complex Exploit

So we know where CVE-2022-24481 lives. In modern Windows exploitation, this is commonly known as "the easy part." We know that we can create overlapping client and container metadata structs. Great. Now, how do we use that to elevate to SYSTEM?

## The Target Structs

Before we make horrifying mutants out of these client and container structs, we need to understand what they look like. We'll be looking for two types of fields: fields that would be interesting to overwrite (like kernel pointers), and fields that we can easily control. Our goal is to overlap a controllable field of one struct with an interesting field of another.

We'll start with the container struct, since it's the simpler of the two:

```c
struct _CLFS_CONTAINER_CONTEXT {
  CLFS_NODE_ID NodeId;  // a tiny struct that mostly functions as a "type tag" (remember this)
  ulonglong ContainerSize;
  ulong ContainerId;
  ulong QueueId;  // if this container is in a "container queue," this is the ID of that
  union {
    CClfsContainer* pContainer;  // pointer to the container class in memory (!!!)
    ulonglong Alignment;  // or a padding field, to ensure the kernel pointer never touches the disk
  };
  uchar Usn;
  uchar ContainerState;
  ushort Padding;  // i think?
  ulong PreviousContainerOffset;  // doesn't seem like this is ever used
  ulong NextContainerOffset;  // ditto
}
```

Recall the two types of fields we're looking for. As far as controllable fields, this struct is pretty barren. The only one we *might* be able to control is the size, and it's unlikely we could make a size large enough to fake a kernel pointer (which, remember, start at `0x800000000000`). Thus the container metadata is barren in terms of controllable fields.
However, it *does* contain a kernel pointer. The `pContainer` field, in memory, points to a more detailed container struct. Thus if we can overwrite that field, we can potentially fake a container struct. We might also be able to trick the kernel into doing certain operations on that address; for example "freeing" the (overwritten) pointer might decrement a "reference counter" at a fixed offset from the overwritten pointer.
In either case, there is potential for shenanigans here. We will therefore mark the container struct as a "no" for controllable fields, but a "yes" for interesting fields.

Next, let's look at the client struct (remember, a client represents a stream that is using this log). We'll be on special lookout for controllable fields, since the container struct didn't have any.

```c
struct _CLFS_CLIENT_CONTEXT {
  CLFS_NODE_ID NodeId; // the same "type tag" struct as the container context, but with a different value(?)
  uchar ClientId;
  uchar Unknown;
  ushort FileAttributes;  // Windows File Attributes associated with the BLF (why is this here?)
  ulong FlushThreshold;  // number of log bytes in memory before this stream flushes them to disk
  ulong NumShadowSectors;  // unused
  ulong Padding;
  ulonglong UndoCommitment;  // max number of bytes the stream will ask to undo (?)
  ulonglong CreateTime;
  ulonglong LastAccessTime;
  ulonglong LastWriteTime;
  CLFS_LSN lsnOwnerPage;  // Log Sequence Numbers (identifiers) of certain Records from this client
  CLFS_LSN lsnArchiveTail;
  CLFS_LSN lsnBase;
  CLFS_LSN lsnLast;
  CLFS_LSN lsnRestart;
  CLFS_LSN lsnPhysicalBase;
  CLFS_LSN lsnUnused1;
  CLFS_LSN lsnUnused2;
  CLFS_LOG_STATE eState;  // current log state (for this client?)
  union
  {
      HANDLE hSecurityContext;  // in-memory security context associated with this client...
      ULONGLONG ullAlignment;  // or nothing on disk
  };
}
```
