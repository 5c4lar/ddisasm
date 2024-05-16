# Add all subdirectories in the current folder
include_directories(${PROJECT_SOURCE_DIR}/src)
file(GLOB SUBDIRS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/*)
foreach(SUBDIR ${SUBDIRS})
    if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${SUBDIR})
        add_subdirectory(${SUBDIR})
    endif()
endforeach()
