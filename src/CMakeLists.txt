add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)

if(APPLE)
    add_definitions(-D_DARWIN_C_SOURCE)
endif()

find_program(LINT "clang-tidy")
IF (LINT)
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*,-llvmlibc-restrict-system-libc-headers,-cppcoreguidelines-init-variables,-clang-analyzer-security.insecureAPI.strcpy,-concurrency-mt-unsafe,-android-cloexec-accept,-android-cloexec-dup,-google-readability-todo,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-cert-dcl03-c,-hicpp-static-assert,-misc-static-assert,-altera-struct-pack-align,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling;--quiet")
ENDIF ()

# Make an executable
add_executable(client ${COMMON_SOURCE_LIST}  ${CLIENT_SOURCE_LIST} ${CLIENT_MAIN_SOURCE} ${HEADER_LIST})
add_executable(server ${COMMON_SOURCE_LIST}  ${SERVER_SOURCE_LIST} ${SERVER_MAIN_SOURCE} ${HEADER_LIST})

# We need this directory, and users of our library will need it too
target_include_directories(client PRIVATE ../include)
target_include_directories(client PRIVATE /usr/include)
target_include_directories(client PRIVATE /usr/local/include)
target_link_directories(client PRIVATE /usr/lib)
target_link_directories(client PRIVATE /usr/local/lib)
target_include_directories(server PRIVATE ../include)
target_include_directories(server PRIVATE /usr/include)
target_include_directories(server PRIVATE /usr/local/include)
target_link_directories(server PRIVATE /usr/lib)
target_link_directories(server PRIVATE /usr/local/lib)

# All users of this library will need at least C11
target_compile_features(client PUBLIC c_std_11)
target_compile_options(client PRIVATE -g)
target_compile_options(client PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(client PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(client PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)
target_compile_features(server PUBLIC c_std_11)
target_compile_options(server PRIVATE -g)
target_compile_options(server PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(server PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(server PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)

find_library(LIBM m REQUIRED)
find_library(LIBSOCKET socket)
find_library(LIBDC_ERROR dc_error REQUIRED)
find_library(LIBDC_POSIX dc_posix REQUIRED)
find_library(LIBDC_UTIL dc_util REQUIRED)
find_library(LIBDC_FSM dc_fsm REQUIRED)
find_library(LIBDC_APPLICATION dc_application REQUIRED)
find_library(LIBDC_NETWORK dc_network REQUIRED)

target_link_libraries(client PRIVATE ${LIBM})
target_link_libraries(client PRIVATE ${LIBDC_ERROR})
target_link_libraries(client PRIVATE ${LIBDC_POSIX})
target_link_libraries(client PRIVATE ${LIBDC_UTIL})
target_link_libraries(client PRIVATE ${LIBDC_FSM})
target_link_libraries(client PRIVATE ${LIBDC_APPLICATION})
target_link_libraries(client PRIVATE ${LIBDC_NETWORK})

target_link_libraries(server PRIVATE ${LIBM})
target_link_libraries(server PRIVATE ${LIBDC_ERROR})
target_link_libraries(server PRIVATE ${LIBDC_POSIX})
target_link_libraries(server PRIVATE ${LIBDC_UTIL})
target_link_libraries(server PRIVATE ${LIBDC_FSM})
target_link_libraries(server PRIVATE ${LIBDC_APPLICATION})
target_link_libraries(server PRIVATE ${LIBDC_NETWORK})

set_target_properties(client PROPERTIES OUTPUT_NAME "client")
set_target_properties(server PROPERTIES OUTPUT_NAME "server")
install(TARGETS client DESTINATION bin)
install(TARGETS server DESTINATION bin)

# IDEs should put the headers in a nice place
source_group(
        TREE "${PROJECT_SOURCE_DIR}/include"
        PREFIX "Header Files"
        FILES ${HEADER_LIST}
)

add_custom_target(
        format
        COMMAND clang-format
        -i
        ${HEADER_LIST}
        ${COMMON_SOURCE_LIST}
        ${CLIENT_SOURCE_LIST}
        ${SERVER_SOURCE_LIST}
        ${CLIENT_MAIN_SOURCE}
        ${SERVER_MAIN_SOURCE}
)
