#!/bin/bash

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_libpng
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_libpng
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_libpng
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_libtiff
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_libtiff
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_libtiff
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_libjpeg
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_libjpeg
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_libjpeg

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_0
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_10
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_20
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_30
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_40
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_50
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_60
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_70
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_80
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_90
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/block_test_libpng_100

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_0
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_10
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_20
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_30
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_40
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_50
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_60
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_70
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_80
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_90
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ratio_test_libpng_100

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_0
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_10
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_20
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_30
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_40
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_50
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_60
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_70
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_80
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_90
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_crash_100

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_0
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_10
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_20
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_30
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_40
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_50
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_60
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_70
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_80
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_90
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_crash_100

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_manual_0
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_manual_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_manual_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_manual_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/normal_manual_4
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_1_manual_0
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_1_manual_1
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_1_manual_2
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_1_manual_3
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_1_manual_4
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_7_manual_5
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_7_manual_6
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_7_manual_7
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_7_manual_8
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asan_7_manual_9
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_1_manual_0
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_1_manual_1
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_1_manual_2
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_1_manual_3
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_1_manual_4
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_7_manual_5
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_7_manual_6
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_7_manual_7
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_7_manual_8
mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ad_7_manual_9

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/conf
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asn1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/asn1parse
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/bignum
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/client
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/cms
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/crl
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/ct
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/server
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/x509

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_normal_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_normal_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_asan_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_asan_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_asan_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_ad_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_ad_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_ad_3

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_asan_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_asan_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_asan_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_asan_4
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_asan_5
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_ad_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_ad_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_ad_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_ad_4
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug5_ad_5
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_asan_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_asan_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_asan_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_asan_4
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_asan_5
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_ad_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_ad_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_ad_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_ad_4
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug7_ad_5

# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug2_normal_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug2_normal_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug2_normal_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug2_normal_4
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug2_normal_5
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug3_normal_1
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug3_normal_2
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug3_normal_3
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug3_normal_4
# mkdir ./fuzzers/binary_only/qemu_launcher/target/x86_64/output/sqlite3_bug3_normal_5