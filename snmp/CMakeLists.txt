aux_source_directory(./ DIR_LIB_SRC)
#add_executable(
add_library(mysnmp ${DIR_LIB_SRC})
target_link_libraries(mysnmp  snmp rt)