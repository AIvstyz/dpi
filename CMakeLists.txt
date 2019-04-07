#控制CMAKE最低版本号
cmake_minimum_required(VERSION 3.2)
#将当前目录的所有.c文件都存到srcs这个变量里边
file(GLOB srcs ./*.c ./protocol/*.c)

include_directories(./)

add_library(dpi_static ${srcs})
#添加一个 -lpcap 编译参数
target_link_libraries(dpi_static pcap)

add_executable(dpi ./sample/main.c)
target_link_libraries(dpi dpi_static)

