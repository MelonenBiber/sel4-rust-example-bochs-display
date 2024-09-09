Minimal x86_64 seL4 root task (in rust!) [that outputs to bochs-display]
====================
I felt like information about seL4 with rust is sparse at best and exploration is hard, so I decided to make this.
I tried to make it as straightforward to compile and modify as I could, so you can play around and get a feel for rust+seL4.

Setup & Build
---------------
Debug build is very, very, very slow here
```
git clone https://github.com/MelonenBiber/sel4-rust-example-bochs-display --recursive
cd sel4-rust-example-bochs-display
./build.sh release
```

How to Run
---------------
Do not change vgamem or add other devices or remove -nodefaults because the framebuffer address is hardcoded and will move.<br />
Alternatively the framebuffer address can be found using the "info pci" command when inside qemu monitor (Ctrl-x + c in stdout or sometimes under "View" in the qemu window)
```
qemu-system-x86_64 \
-nodefaults \
-cpu Haswell,+fsgsbase,+pdpe1gb,+xsave \
-device bochs-display,vgamem=4M \
-serial mon:stdio \
-m 128M \
-kernel target/out/kernel32.elf \
-initrd target/out/sel4-rust-example-bochs-display.elf
```
alternatively on any modern cpu with virtualization support enabled you can use
```
qemu-system-x86_64 \
-nodefaults \
-accel kvm \
-cpu host,+fsgsbase,+pdpe1gb,+xsave \
-device bochs-display,vgamem=4M \
-serial mon:stdio \
-m 128M \
-kernel target/out/kernel32.elf \
-initrd target/out/sel4-rust-example-bochs-display.elf
```
