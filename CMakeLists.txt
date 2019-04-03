add_executable(dpi ./main.c)
#添加一个 -lpcap 编译参数
target_link_libraries(dpi pcap)

