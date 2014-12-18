PROJECT(LIBGIT2-sqlitepp CXX)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

set(CMAKE_CXX_FLAGS "-g -std=c++11")

INCLUDE(../CMake/FindLibgit2.cmake)
INCLUDE(../CMake/FindSQLite3.cmake)

# Build options
OPTION(BUILD_SHARED_LIBS "Build Shared Library (OFF for Static)" ON)
OPTION(BUILD_TESTS "Build Tests" ON)

# Build Release by default
IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF()

SET(SOURCES
    odb.cpp
    refdb.cpp)

SET(HEADERS
    sqlite.hpp)

IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(git2-sqlitepp SHARED ${SOURCES})
ELSE()
    ADD_LIBRARY(git2-sqlitepp STATIC ${SOURCES})
ENDIF()

# Compile and link LIBGIT2
INCLUDE_DIRECTORIES(${LIBGIT2_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(git2-sqlitepp ${LIBGIT2_LIBRARIES} ${SQLITE3_LIBRARIES})

INSTALL(FILES ${HEADERS} DESTINATION include/git2-sqlitepp)
INSTALL(TARGETS git2-sqlitepp DESTINATION lib)
