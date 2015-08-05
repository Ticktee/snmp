aux_source_directory(./ DIR_LIB_SRC)
add_library(mysnmp ${DIR_LIB_SRC})
target_link_libraries(mysnmp  snmp rt)