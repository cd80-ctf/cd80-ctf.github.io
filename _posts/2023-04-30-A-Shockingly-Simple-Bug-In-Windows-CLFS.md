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
However, it *does* contain a kernel pointer. The `pContainer` field, in memory, points to a more detailed container struct. Thus if we can overwrite that field, we can potentially fake a container struct. We will therefore mark the container struct as a "no" for controllable fields, but a "yes" for interesting fields.

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
      ULONGLONG ullAlignment;  // ...or nothing on disk
  };
}
```

A few fields jump out at us. Things like `CreateTime` and `LastAccessTime` might not be arbitrarily settable in memory, but we might be able to lie about them on disk. In a dream world, this might look something like this:

1. We create an evil CLFS Base Log File with overlapping offsets
2. The CLFS driver reads the container metadata into memory first, then the client metadata. This is where we overwrite `pContainer`.
3. We call some function that uses this our custom `pContainer` for interesting things.

Alternatively, if the client metadata is read before the container metadata, we might try something like this:

1. Create evil Base Log File
2. Read the evil client metadata, which is then stored in some other object.
3. Write the metadata from that other object back to the client metadata struct, overwriting `pContainer`
4. Shenanigans with `pContainer`.

As it so happens, when a Base Log File is parsed, the client metadata is read first. Thus we will adopt the second battle plan.

## Creating an Evil `pContainer`

Our goal in this section is to overwrite the `pContainer` field of a container context. If we can do this, we can fake a `CClfsContainer` object. Our plan from that point forward is along the lines of ???? -> Profit. This is how exploit development works in practice: one step at a time, with frequent setbacks. Faking a kernel object like `pContainer` seems like it might lead to shenanigans -- let's try it and see what falls out.

We will follow our battle plan from the previous section. Assuming we've created the evil Base Log File, the first step is to find an "intermediate" object that can hold our evil client metadata. Doing this amounts to searching Ghidra for instances of `CLFS_CLIENT_CONTEXT`. For once, the exploit gods are on our side and we find one rather quickly:

```c
long CClfsLogFcbPhysical::Initialize(CClfsLogFcbPhysical* this, [many parameters]) {
  [lots of code]
  CClfsBaseFile::AcquireClientContext(*(CClfsBaseFile **)(this + 0x2b0),'\0',&local_a0);  [1]
  [more code] 
  *(ushort *)(this + 0x170) = local_a0->FileAttributes;
  *(ulong *)(this + 0x4f4) = local_a0->FlushThreshold;
  if (((*(byte *)&local_a0->LogState & 0x20) == 0) ||
     (cVar10 = _guard_dispatch_icall(this), cVar10 != '\0')) {
    *(ulonglong *)(this + 0x1a8) = local_a0->CreateTime;  [2]
    *(ulonglong *)(this + 0x1b0) = local_a0->LastAccessTime;
    *(ulonglong *)(this + 0x1b8) = local_a0->LastWriteTime;
    *(undefined8 *)(this + 0x1d0) = 0;
    *(ulonglong *)(this + 0x538) = local_a0->OwnerPageLsn;
    *(ulonglong *)(this + 0x1e8) = local_a0->ArchiveTailLsn;
    *(ulonglong *)(this + 0x1e0) = local_a0->BaseLsn;
    *(ulonglong *)(this + 0x1f0) = local_a0->LastLsn;
    *(ulonglong *)(this + 0x1f8) = local_a0->RestartLsn;
    *(ulong *)(this + 0x174) = local_a0->ShadowSectors;
  [yet more code]
}
```

This function is called when a Base Log File is read in from memory. We can see a client context is read in at `[1]`, and several fields are assigned to fields of the `CClfsLogFcbPhysical` object at `[2]`. Since these files are read straight from disk, we have full control over them. Thus we can use a `CClfsLogFcbPhysical` object to hold our evil values.

How about writing them back to disk? This time, we'll look through all functions that use a `CClfsLogFcbPhysical` object. Pretty quickly, we find what we're looking for:

```c
long CClfsLogFcbPhysical::FlushMetadata(CClfsLogFcbPhysical *this) {
  local_res8 = (_CLFS_CLIENT_CONTEXT *)0x0;
  lVar3 = CClfsBaseFile::AcquireClientContext(*(CClfsBaseFile **)(this + 0x2b0),'\0',&local_res8);
  [heaps of code]
  local_res8->CreateTime = *(ulonglong *)(this + 0x1a8);
  local_res8->LastAccessTime = *(ulonglong *)(this + 0x1b0);
  local_res8->LastWriteTime = *(ulonglong *)(this + 0x1b8);
  local_res8->OwnerPageLsn = *(ulonglong *)(this + 0x538);
  local_res8->ArchiveTailLsn = *(ulonglong *)(this + 0x1e8);
  local_res8->BaseLsn = *(ulonglong *)(this + 0x1e0);
  local_res8->LastLsn = *(ulonglong *)(this + 0x1f0);
  local_res8->RestartLsn = *(ulonglong *)(this + 0x1f8);
  local_res8->ShadowSectors = *(ulong *)(this + 0x174);
  local_res8->FileAttributes = *(ushort *)(this + 0x170);
  [code code code]
}
```

Perfect! This function does exactly what we're looking for; it dumps the stored (evil) client metadata back into the client context struct. If this struct is overlapping with a container context, **this will allow us to overwrite `pContainer` with an arbitrary value.**

Step one is done. We have a way to corrupt the `pContainer` field of a container context. Now we start the *real* tricky part: finding sneaky things we can do with this corrupted pointer. If this post were written five years ago, we would have two obvious solutions. A year ago, we would have one -- the one used in the ransomware where this exploit was discovered. As of today, Microsoft has patched both of those methods. We will have to improvise.

## What Can We Do With `pContainer`?

At this point, let's assume we've faked a Container Context's `pContainer` field. We now have to find a function that does interesting (read: abusable) things with `pContainer`. Ideally, we'd like to find functions that write to, or read from, some offset of our fake `pContainer` object.
Doing this will allow us to further corrupt kernel memory, ideally leading to a state where we can read/write to/from any kernel address we want. If we can do that, we'll be out of the woods -- arbitrary kernel R/W on Windows is a free ticket to SYSTEM.

To start, let's find all the functions that use a Container Context's `pContainer` field. Thanks to the American taxpayer, this is very simple. We can simply fill out the struct in Ghidra, right-click, and hit "Find Uses By Field." Doing so will give us a list of every time the `pContainer` field is accessed.

If we do this, we end up with the following list of functions:
- `CClfsLogFcbPhysical::GetContainer`
- `CClfsLogFcbPhysical::FlushLog`
- `CClfsLogFcbPhysical::CloseContainers`
- `CClfsLogFcbPhysical::GetArchiveDescriptors`
- `CClfsLogFcbPhysical::WrapDeletePendingContainer`
- `CClfsLogFcbPhysical::DeleteContainer` (several times)
- `CClfsBaseFilePersisted::WriteMetadataBlock`
- `CClfsBaseFilePersisted::CheckSecureAccess`
- `CClfsBaseFilePersisted::LoadContainerQ` (this uses `pContainer` a *lot*)
- `CClfsBaseFilePersisted::UnoadContainerQ`
- `CClfsBaseFilePersisted::MarkContainerQ`
- `CClfsBaseFilePersisted::UnmarkContainerQ`
- `CClfsBaseFilePersisted::RemoveContainer`
- `CClfsBaseFile::ScanContainerInfo`

This might seem like a lot. It is. Don't worry. We'll go through these options one by one, starting with the simplest and eliminating functions that we conclude aren't useful. By the end, hopefully, we'll have something with which to do evil.

## Gadgets

### `CClfsLogFcbPhysical::GetContainer`
By a bessing of the exploit gods, we find something (potentially) useful in our first target, `CClfsLogFcbPhysical::GetContainer`:

```
CClfsContainer* CClfsLogFcbPhysical::GetContainer(CClfsLogFcbPhysical *this,ulong param_1)
{
  CClfsContainer *pCVar1;
  _CLFS_CONTAINER_CONTEXT *local_res18 [2];
  
  pCVar1 = (CClfsContainer *)0x0;
  local_res18[0] = (_CLFS_CONTAINER_CONTEXT *)0x0;
  if (param_1 == 0xffffffff) {
    pCVar1 = (CClfsContainer *)0x0;
  }
  else {
    CClfsBaseFile::AcquireContainerContext
              (*(CClfsBaseFile **)(this + 0x2b0),
               *(ulong *)(this + (ulonglong)(param_1 & 0x3ff) * 4 + 0x558),local_res18);
    if (local_res18[0] != (_CLFS_CONTAINER_CONTEXT *)0x0) {
      pCVar1 = local_res18[0]->pContainer;
      _guard_dispatch_icall(pCVar1); // [3]
      CClfsBaseFile::ReleaseContainerContext(*(CClfsBaseFile **)(this + 0x2b0),local_res18);
    }
  }
  return pCVar1;
}
```

This is a very simple function. That's good. We want our exploit primitives to be as simple as possible. And, in fact, this function is about as simple as possible: it just gets the `pContainer` of a Container Context, *calls a virtual function on it* (`[3]`), and returns it.

Five years ago, this would practically be game over. Since we control `pContainer`, we control the virtual function table of `pContainer`. Thus this function straight-up hands us control of execution on a silver platter. We could not call a function in user-space (due to SMEP), but we could probably find a useful gadget somewhere in kernel space to do pseudo-ROP on, and we would be golden.

However, in CFG's world, no such fun is allowed. If we try to call any address that isn't pre-marked as a function entry point, Windows will take its ball and go home (to a bluescreen). This severely cripples our ability to exploit this primitive. This is actually quite remarkable. Ten years ago, an arbitrary call primitive like this would be an immediate exploit. Now it's an open question whether it can be exploited at all.

In short, `CClfsLogFcbPhysical::GetContainer` gives us the ability to call an arbitrary kernel function with a single controlled argument. We will put this primitive in our bucket and keep going.

### Other Arbitrary Call Primitives

As it turns out, almost all of our gadgets contain arbitrary call primitives. In the source code, these will usually be calls to `CClfsContainer::AddRef` or `CClfsContainer::Remove`. The second call is more interesting for one reason: it resides at offset `0x8` in the virtual function table, rather than offset `0x0` like `AddRef`.
This means that the arbitrary argument we pass to our arbitrary call (which must be the `CClfsContainer` itself) can have a controlled value at it. As such, we will group our arbitrary call primitives by whether they call `AddRef` or `Remove`:

Basic `AddRef` primitives (offset `0x0`):
- `CClfsLogFcbPhysical::GetContainer`
- `CClfsLogFcbPhysical::FlushLog`

Multiple call primitives:
- `CClfsBaseFilePersisted::CheckSecureAccess` (`0x0` and `0x8`)
- `CClfsBaseFilePersisted::RemoveContainer` (`0x8` and `0x18`)

Several functions are more complex, and deserve research of their own:

### `CClfsLogFcbPhysical::CloseContainers`

This is the simplest of the complex primitives, and is thus a good place to start. Cutting out the crap, it looks like this:

```c
long __thiscall CClfsLogFcbPhysical::CloseContainers(CClfsLogFcbPhysical *this)

{
  _CLFS_CONTAINER_CONTEXT *p_Var1;
  long result;
  uint uVar3;
  _CLFS_CONTAINER_CONTEXT *local_res8;
  
  containerContext = (_CLFS_CONTAINER_CONTEXT *)0x0;
  result = 0;
  uVar3 = *(uint *)(this + 0x554);
  if (uVar3 < *(uint *)(this + 0x550)) {
    do {
      result = CClfsBaseFile::AcquireContainerContext
                        (*(CClfsBaseFile **)(this + 0x2b0),
                         *(ulong *)(this + (ulonglong)(uVar3 & 0x3ff) * 4 + 0x558),&containerContext);
      containerContextMirror = containerContext;
      if ((result < 0) || (local_res8 == (_CLFS_CONTAINER_CONTEXT *)0x0)) {
        return -0x3fe5fff3;
      }
      if (containerContext->pContainer != (CClfsContainer *)0x0) {
        CClfsContainer::Close(containerContext->pContainer);  // [4]
        _guard_dispatch_icall();   // [5] | calls pContainer + 0x8
        containerContextMirror->pContainer = (CClfsContainer *)0x0;
      }
      CClfsBaseFile::ReleaseContainerContext(*(CClfsBaseFile **)(this + 0x2b0),&containerContext);
      uVar3 = uVar3 + 1;
    } while (uVar3 < *(uint *)(this + 0x550));
  }
  return lVar2;
}
```

This is a fairly simple function. It seems to just loop over and release containers stored in the `CClfsLogFcbPhysical`. Just like in the basic hooks, we see that we get an arbitrary call primitive at `[5]`. However, our evil `pContainer` is also passed to another function: `CClfsContainer::Close()`.
Here the hydra of exploit development rears its head as primitives beget primitives. To fully explore our playground, we must now look find out whether these two functions are condusive to shenanigans as well.

Thankfully, we don't have to look far, as `CClfsContainer::Close()` is both short and immediately interesting:

```c
long __thiscall CClfsContainer::Close(CClfsContainer *this)
{
  int iVar1;
  
  if (*(longlong *)(this + 0x20) == 0) {
    iVar1 = -0x3ffffff8;
  }
  else {
    iVar1 = ZwClose();
    if (-1 < iVar1) {
      *(undefined8 *)(this + 0x20) = 0;
      *(undefined8 *)(this + 8) = 0;
    }
    ObfDereferenceObject(*(undefined8 *)(this + 0x30));
    *(undefined8 *)(this + 0x30) = 0;
  }
  return iVar1;
}
```

Right away, we have a slew of interesting primitives. First, we see that several offsets from our controlled `pContainer` are set to zero (remember, we control `this`). Thus this call path gives us a new primitive: several **arbitrary offset uncontrolled writes**. These are difficult to exploit, but not impossible (I believe there are some Linux kernel exploits that use these to corrupt verified eBPF code and whatnot).
Unfortunately, this overwrites *several* offsets from our evil pointer, not just one. This is unfortunate because when we're doing memory corruption, we usually want to tweak an object just slightly, overwriting maybe one or two core fields. A scattershot approach like this is more likely to lead to a crash than anything interesting. Thus these writes are interesting, but probably a last resort.

Other than those writes, we also see that the value `this + 0x30` is passed to `ObfDereferenceObject`. Another head sprouts on the hydra: what does *this* function do?

To find the answer, as is often the case in exploit development, we turn to a [shady site on the second page of the Google results](https://laravel.wiki/obcreateobject-and-obdereferenceobject-and-obremoveobjectroutine.html). This page purports to offer the source code of this undocumented function:

```c
LONG_PTRObfDereferenceObject (__ in PVOID Object / / our evil pContainer) {
    [code code code...]
    // Directly subtract 0x18 from the object body to be the object header
    ObjectHeader = OBJECT_TO_OBJECT_HEADER( Object );

    [shitty kernel code...]

    // Simple decreasing PointerCount field
    Result = ObpDecrPointerCount( ObjectHeader );

    // Decrement to 0 will be deleted
    if (Result == 0) {
        [do more stuff to destroy the object]
    }

    return Result;
}
```

Turning to [yet another shady site](https://systemroot.gitee.io/pages/apiexplorer/d5/d1/obp_8h.html), we find that `OBJECT_TO_OBJECT_HEADER` and `ObpDecrPointerCount` are both macros:

```c
#define OBJECT_TO_OBJECT_HEADER( o ) CONTAINING_RECORD( (o), OBJECT_HEADER, Body )  // returns some fixed, negative offset from x
#define ObpDecrPointerCount(np)   InterlockedDecrement( &np->PointerCount )
```

Finally, somehow, we end up back in documented code and on websites that aren't dropping exploit kits on me. The function [`InterlockedDecrement`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockeddecrement) is defined to simply subtract 1 from the pointed-to value.

That was a *lot* of nonsense. Let's take a step back and sketch out the pseudocode of what happens here, from an exploit development viewpoint:

```c
function DoEvilWithPointer(CClfsContainer* evilPointer) {
    void* secondEvilPointer = *(void*)(evilPointer + 0x30);
    void* secondEvilPointerHeader = secondEvilPointer - 0x18;  // OBJECT_TO_OBJECT_HEADER basically just subtracts 0x18
    void* secondEvilPointerPointerCount = evilPointerHeader;  // PointerCount is the first element of the object, so &secondEvilPointerHeader->PointerCount is a no-op
    *secondEvilPointerPointerCount -= 1;
}
```

Now *this* is interesting. This code path reads a pointer from our controlled pointer, finds a value at some fixed offset from the second pointer, and decreases it by 1. That is, **this code path lets us decrement the value at a single arbitrary address by 1**.

This primitive is often called **arbitrary address decrement**, and until five months ago, it was free privilege escalation on Windows 11 (and still is on Windows 10). Basically, there was a boolean in kernel space called `bannedFromReadingAndWritingKernelMemory` (technically, it was called `PreviousMode`) that functioned exactly as described. This is how the in-the-wild ransomware sample worked: it would use this arbitrary address decrement to set `bannedFromReadingAndWritingKernelMemory = 0`, then proceeded to etc. etc.

Unfortunately, Microsoft made it much harder to abuse this value in November 2022. It still might be possible to bypass the patch via a race condition, but it's pretty messy. Fortunately, there are other ways to turn an arbitrary address decrement into privilege escalation. One is to decrement the reference counter of an object, essentially allowing a use-after-free.
This would probably work eventually, but would require thoroughly ugly heap feng shui. As such, we will attempt another method which has been used to weaponize arbitrary decrement in the past. As with many *interesting features* of Windows, it targets the window subsystem.

## One Bit to Rule them All: `bServerSideWindowProc`

Deep within the core of windows lies the WND structure. As the name suggests, WND is used to represent a window, such as the browser window you're currently reading this writeup in (well, if you're on Windows). The mere existence of WND should not come as a surprise: every modern operating system has a similar window object. However, uniquely to Windows, a large portion of a WND object's functionality is
handled via **user-mode callbacks from kernel mode**.

Specifically, when we create a window on Windows using `CreateWindowEx`, we have the option to provide a callback via the parameter `lpfnWndProc`:

```c
LRESULT CALLBACK windowCallback(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    printf("Shenanigans!\n");
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wc;
    const wchar_t windowClassName[]  = L"EvilWindow"

    //Step 1: Register a custom window class "EvilWindow"
    wc.hInstance     = hInstance;
    wc.lpszClassName = windowClassName;
    wc.lpfnWndProc   = windowCallback;

    if(!RegisterClassEx(&wc))
    {
        return 0;
    }

    // Step 2: Create a window of class "EvilWindow"
    HWND hwnd = CreateWindowEx(
      0,                         // Optional window styles.
      windowClassName,           // Window class
      L"Wherein Shenanigans",    // Window text
      [more parameters]
    );
    
    return 0;
}
```

Once we have registered this window, our function `windowCallback` will be called from kernel mode whenever something happens to the window!

"But wait," you may ask, and rightly so. "Isn't this a gaping security flaw?"

Almost. Of course, the kernel will not blindly execute a user function with kernel privileges. Before calling the user-mode callback, it will drop its privileges to user mode. Thus `windowCallback` will not actually be executed with kernel privileges.

That is, unless one specific bit is set.

As it turns out, every WND structure has a bit called `bServerSideWindowProc`. This bit indicates whether the callback function is from the kernel (1), or the user (0). If the callback is from the kernel (`bServerSideWindowProc = 1`), then **the callback function will be invoked without dropping privileges!**

This may seem confusing. After all, our primitive is to **decrement** a value by one, not increment it. But recall: our primitive decrements a **four-byte integer**, not a single byte! This means that if we decrement an "integer" whose last byte is `bServerSideWindowProc = 0`, that decrement will bring the value of `bServerSideWindowProc` to 1!

Thus, our path to victory becomes clearer:

1) Create a WND object
2) Assign an evil callback to the WND object
3) Leak the address of the WND object (!)
4) Use our arbitrary decrement to decrement the integer based at `bServerSideWindowProc`
5) Trigger the callback
6) Profit

## Turning Arbitrary Decrement into Use-After-Free

### `CClfsBaseFilePersisted::UnloadContainerQ`

### `CClfsBaseFilePersisted::LoadContainerQ`

### `CClfsBaseFilePersisted::UnmarkContainerQ`

### `CClfsBaseFilePersisted::WriteMetadataBlock`

### `CClfsContainer::QueryContainerInfo`

### `CClfsLogFcbPhysical::DeleteContainer`

### `CClfsLogFcbPhysical::WrapDeletePendingContainer`
