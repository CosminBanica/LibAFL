#!/bin/bash

for i in {1..50}
do
    cp ./fuzzers/binary_only/qemu_launcher/target/x86_64/release/qemu_launcher-vm_server ./fuzzers/binary_only/qemu_launcher/target/x86_64/release/qemu_launcher-vm_server-$i
done