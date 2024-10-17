#!/bin/bash

for i in {1..15}
do
    cp ./fuzzers/binary_only/qemu_launcher/target/x86_64/release/qemu_launcher-development ./fuzzers/binary_only/qemu_launcher/target/x86_64/release/qemu_launcher-development-$i
done