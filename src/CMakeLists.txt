add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)

if(APPLE)
    add_definitions(-D_DARWIN_C_SOURCE)
endif()

find_program(LINT "clang-tidy")
IF (LINT)
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*,-llvmlibc-restrict-system-libc-headers,-cppcoreguidelines-init-variables,-clang-analyzer-security.insecureAPI.strcpy,-concurrency-mt-unsafe,-android-cloexec-accept,-android-cloexec-dup,-google-readability-todo,-cppcoreguidelines-avoid-magic-numbers,-readability-magic-numbers,-cert-dcl03-c,-hicpp-static-assert,-misc-static-assert,-altera-struct-pack-align,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling;--quiet")
ENDIF ()

# Make an executable
add_executable(prog1 ${COMMON_SOURCE_LIST}  ${PROG1_SOURCE_LIST} ${PROG1_MAIN_SOURCE} ${HEADER_LIST})
add_executable(prog2 ${COMMON_SOURCE_LIST}  ${PROG2_SOURCE_LIST} ${PROG2_MAIN_SOURCE} ${HEADER_LIST})

# We need this directory, and users of our library will need it too
target_include_directories(prog1 PRIVATE ../include)
target_include_directories(prog1 PRIVATE /usr/include)
target_include_directories(prog1 PRIVATE /usr/local/include)
target_link_directories(prog1 PRIVATE /usr/lib)
target_link_directories(prog1 PRIVATE /usr/local/lib)
target_include_directories(prog2 PRIVATE ../include)
target_include_directories(prog2 PRIVATE /usr/include)
target_include_directories(prog2 PRIVATE /usr/local/include)
target_link_directories(prog2 PRIVATE /usr/lib)
target_link_directories(prog2 PRIVATE /usr/local/lib)

# All users of this library will need at least C11
target_compile_features(prog1 PUBLIC c_std_11)
target_compile_options(prog1 PRIVATE -g)
target_compile_options(prog1 PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(prog1 PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(prog1 PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)
target_compile_features(prog2 PUBLIC c_std_11)
target_compile_options(prog2 PRIVATE -g)
target_compile_options(prog2 PRIVATE -fstack-protector-all -ftrapv)
target_compile_options(prog2 PRIVATE -Wpedantic -Wall -Wextra)
target_compile_options(prog2 PRIVATE -Wdouble-promotion -Wformat-nonliteral -Wformat-security -Wformat-y2k -Wnull-dereference -Winit-self -Wmissing-include-dirs -Wswitch-default -Wswitch-enum -Wunused-local-typedefs -Wstrict-overflow=5 -Wmissing-noreturn -Walloca -Wfloat-equal -Wdeclaration-after-statement -Wshadow -Wpointer-arith -Wabsolute-value -Wundef -Wexpansion-to-defined -Wunused-macros -Wno-endif-labels -Wbad-function-cast -Wcast-qual -Wwrite-strings -Wconversion -Wdangling-else -Wdate-time -Wempty-body -Wsign-conversion -Wfloat-conversion -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Winvalid-pch -Wlong-long -Wvariadic-macros -Wdisabled-optimization -Wstack-protector -Woverlength-strings)

find_library(LIBM m REQUIRED)
find_library(LIBSOCKET socket)
find_library(LIBDC_ERROR dc_error REQUIRED)
find_library(LIBDC_POSIX dc_posix REQUIRED)
find_library(LIBDC_UTIL dc_util REQUIRED)
find_library(LIBDC_FSM dc_fsm REQUIRED)
find_library(LIBDC_APPLICATION dc_application REQUIRED)
target_link_libraries(prog1 PRIVATE ${LIBM})
target_link_libraries(prog1 PRIVATE ${LIBDC_ERROR})
target_link_libraries(prog1 PRIVATE ${LIBDC_POSIX})
target_link_libraries(prog1 PRIVATE ${LIBDC_UTIL})
target_link_libraries(prog1 PRIVATE ${LIBDC_FSM})
target_link_libraries(prog1 PRIVATE ${LIBDC_APPLICATION})
target_link_libraries(prog2 PRIVATE ${LIBM})
target_link_libraries(prog2 PRIVATE ${LIBDC_ERROR})
target_link_libraries(prog2 PRIVATE ${LIBDC_POSIX})
target_link_libraries(prog2 PRIVATE ${LIBDC_UTIL})
target_link_libraries(prog2 PRIVATE ${LIBDC_FSM})
target_link_libraries(prog2 PRIVATE ${LIBDC_APPLICATION})

set_target_properties(prog1 PROPERTIES OUTPUT_NAME "prog1")
set_target_properties(prog2 PROPERTIES OUTPUT_NAME "prog2")
install(TARGETS prog1 DESTINATION bin)
install(TARGETS prog2 DESTINATION bin)

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
        ${PROG1_SOURCE_LIST}
        ${PROG2_SOURCE_LIST}
        ${PROG1_MAIN_SOURCE}
        ${PROG2_MAIN_SOURCE}
)
