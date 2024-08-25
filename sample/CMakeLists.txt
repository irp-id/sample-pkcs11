add_library(p11sample STATIC
        P11Sample.cpp
)

target_include_directories(
    p11sample 
        PRIVATE 
            ${CMAKE_SOURCE_DIR}/include/sample
            ${CMAKE_SOURCE_DIR}/include/softhsm
)

target_link_libraries(
    p11sample
        PRIVATE
            ${CMAKE_DL_LIBS}   
)