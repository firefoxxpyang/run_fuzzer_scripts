afl_types = ["single-process", "multi-process"]




progs = ["c-ares", "freetype2", "json", "libpng", "libxml2", "openssl-1.0.2d", "woff2", "boringssl", "harfbuzz", "libjpeg", "pcre2", "re2", "guetzli", "libpng-yang", "libxml-yang"]
    
prog_list = ["freetype2", "guetzli", "harfbuzz", "json", "libjpeg", "openssl-1.0.2d"]
fuzz_cmds = [
"./c-ares-CVE-2016-5180-aflgo @@",
"./freetype2-2017-aflgo @@",
"./json-2017-02-12-aflgo @@",
"./libpng-1.2.56-aflgo @@",
"./libxml2-v2.9.2-aflgo @@",
"./openssl-1.0.2d-aflgo @@",
"./woff2-2016-05-06-aflgo @@",
"./boringssl-2016-02-12-aflgo @@",
"./harfbuzz-1.3.2-aflgo @@",
"./libjpeg-turbo-07-2017-aflgo @@",
"./pcre2-10.00-aflgo @@",
"./re2-2014-12-09-aflgo @@",
"./guetzli-2017-3-30-aflgo @@",
"./readpng ",
"./xmllint @@",
]

cxxfilt_cves =[
    "cxxfilt_4487",
    "cxxfilt_4489",
    "cxxfilt_4490",
    "cxxfilt_4491",
    "cxxfilt_4492_1",
    "cxxfilt_4492_2",
    "cxxfilt_4492_3",
    "cxxfilt_6131"
]

#objdump_misc            = " -f -a -C -g -D -x --ctf=.ctf "
#objdump_misc            = " -f -a -C -g -x --ctf=.ctf "
objdump_misc = " -C -x "
objdump_monitor_type = "file"


xmllint_misc = ""
xmllint_monitor_type = "file"
xmllint_window_name = "xmllint"

gif2tga_misc = " --outbase /dev/null "
gif2tga_monitor_type = "file"
gif2tga_window_name = "gif2tga"

ffjpeg_misc = " -d "
ffjpeg_monitor_type = "file"
ffjpeg_window_name = "ffjpeg"

readpng_misc = ""
readpng_monitor_type = "stdin"
readpng_window_name = "readpng"

cxxfilt_misc = ""
cxxfilt_monitor_type = "stdin"
cxxfilt_window_name = "cxxfilt"
cxxfilt_binary_name = "cxxfilt"

# boringssl-2016-02-12-binary
boringssl_misc = ""
boringssl_monitor_type = "file"
boringssl_window_name = "boringssl"

# c-ares-CVE-2016-5180-binary
cares_misc = ""
cares_monitor_type = "file"
cares_window_name = "cares"

# freetype2-2017
freetype_misc = ""
freetype_monitor_type = "file"
freetype_window_name = "freetype"

# guetzli-2017-3-30
guetzli_misc = ""
guetzli_monitor_type = "file"
guetzli_window_name = "guetzli"

# harfbuzz-1.3.2
harfbuzz_misc = ""
harfbuzz_monitor_type = "file"
harfbuzz_window_name = "harfbuzz"

# json-2017-02-12
json_misc = ""
json_monitor_type = "file"
json_window_name = "json"

# lcms-2017-03-21
lcms_misc = ""
lcms_monitor_type = "file"
lcms_window_name = "lcms"

# libarchive-2017-01-04
libarchive_misc = ""
libarchive_monitor_type = "file"
libarchive_window_name = "libarchive"

# libjpeg-turbo-07-2017
libjpeg_misc = ""
libjpeg_monitor_type = "file"
libjpeg_window_name = "libjpeg"

# libpng-1.2.56
libpng_misc = ""
libpng_monitor_type = "file"
libpng_window_name = "libpng"

# libssh-2017-1272
libssh_misc = ""
libssh_monitor_type = "file"
libssh_window_name = "libssh"

# libxml2-v2.9.2
libxml2_misc = ""
libxml2_monitor_type = "file"
libxml2_window_name = "libxml2"

# openssl-1.0.1f
openssl101f_misc = ""
openssl101f_monitor_type = "file"
openssl101f_window_name = "openssl101f"

# openssl-1.0.2d
openssl102d_misc = ""
openssl102d_monitor_type = "file"
openssl102d_window_name = "openssl102d"

# pcre2-10.00
pcre2_misc = ""
pcre2_monitor_type = "file"
pcre2_window_name = "pcre2"

# proj4-2017-08-14
proj4_misc = ""
proj4_monitor_type = "file"
proj4_window_name = "proj4"

# re2-2014-12-09
re2_misc = ""
re2_monitor_type = "file"
re2_window_name = "re2"

# woff2-2016-05-06
woff2_misc = ""
woff2_monitor_type = "file"
woff2_window_name = "woff2"
