cmake_minimum_required(VERSION 2.6)
project(snmp_test)

add_subdirectory(snmp)
aux_source_directory(. DIR_SRCS)
add_executable(snmp_test ${DIR_SRCS})

target_link_libraries(snmp_test mysnmp pthread)
#target_link_libraries(snmp_test snmp )

install(TARGETS snmp_test RUNTIME DESTINATION bin)
