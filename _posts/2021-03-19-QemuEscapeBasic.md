---
title:  "QemuEscapeBasic"
layout: post
---

Today, we are going to learn more about qemu escape. Although we have tried it once on XMAN 2019, but that is not enough.  
Nowadays, more and more qemu escape challenges are coming out. So we should be well prepared in case we facing it one day.  

We will start from this repo.  
Finish all the challenges in it.  
```
git clone https://github.com/w0lfzhang/vmescape
```

# babyqemu
Usually, we will be provided with a compiled qemu file named `qemu-system-x86_64`  
The organizer will preset some **vulnerable functions** in it.  
In most of the situation, these vulnerable functions have the same prefix, and the `qemu-system-x86_64` is not stripped.  
We can easily find them in IDA.  

```bash
#!/bin/sh
./qemu-system-x86_64 \
-initrd ./rootfs.cpio \
-kernel ./vmlinuz-4.8.0-52-generic \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm \
-monitor /dev/null \
-m 64M --nographic  -L ./dependency/usr/local/share/qemu \
-L pc-bios \
-device hitb,id=vda
```
We can check the launch.sh file, and find the device name is **hitb**. So we search `hitb` in IDA. 

![image.png](https://i.loli.net/2021/03/19/6fgiFKOeD2zmCJv.png)

Basically, we just need to reverse these functions, unless the organizer sucks.    
Check `pci_hitb_register_types` to get all `TypeInfo`.  

![image.png](https://i.loli.net/2021/03/19/UnEWtpydKk96Bre.png)

Now, we know that the class_init function is `hitb_class_init` and the instance_init function is `hitb_instance_init`.  
We can check the `hitb_class_init` function first.  
```C
void __fastcall hitb_class_init(ObjectClass_0 *a1, void *data)
{
  PCIDeviceClass *v2; // rax

  v2 = (PCIDeviceClass *)object_class_dynamic_cast_assert(
                           a1,
                           "pci-device",
                           "/mnt/hgfs/eadom/workspcae/projects/hitbctf2017/babyqemu/qemu/hw/misc/hitb.c",
                           469,
                           "hitb_class_init");
  v2->revision = 16;
  v2->class_id = 255;
  v2->realize = (void (*)(PCIDevice_0 *, Error_0 **))pci_hitb_realize;
  v2->exit = (PCIUnregisterFunc *)pci_hitb_uninit;
  v2->vendor_id = 0x1234;
  v2->device_id = 0x2333;
}
```
Then we know the device_id is 0x2333 and the vendor_id is 0x1234, we can check the pci device in qemu VM.  
```
# [  550.402757] random: crng init done
lspci
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:03.0 Class 0200: 8086:100e
00:01.1 Class 0101: 8086:7010
00:02.0 Class 0300: 1234:1111
00:01.0 Class 0601: 8086:7000
00:04.0 Class 00ff: 1234:2333
```
the hitb device is `00：04.0`, check the `resource` file to read I/O information.  
```
# cat /sys/devices/pci0000\:00/0000\:00\:04.0/resource
0x00000000fea00000 0x00000000feafffff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
```
the format of this file is  
```
start_address end_address flag
```










