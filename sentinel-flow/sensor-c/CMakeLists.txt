cmake_minimum_required(VERSION 3.16)
project(sentinel_flow_sensor C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Compiler flags ───────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wpedantic -O2)

# ── nDPI (built from source at ~/nDPI) ──────────────────────────────
set(NDPI_ROOT "$ENV{HOME}/nDPI" CACHE PATH "Path to nDPI source tree")
set(NDPI_INCLUDE_DIR     "${NDPI_ROOT}/src/include")
set(NDPI_THIRD_PARTY_DIR "${NDPI_ROOT}/src/lib/third_party/include")
set(NDPI_LIB_DIR         "${NDPI_ROOT}/src/lib")

if(NOT EXISTS "${NDPI_INCLUDE_DIR}/ndpi_api.h")
    message(FATAL_ERROR
        "nDPI headers not found at ${NDPI_INCLUDE_DIR}\n"
        "Set -DNDPI_ROOT=/path/to/nDPI if built elsewhere.")
endif()

find_library(NDPI_LIBRARY
    NAMES ndpi
    PATHS "${NDPI_LIB_DIR}"
    NO_DEFAULT_PATH
)
if(NOT NDPI_LIBRARY)
    message(FATAL_ERROR "libndpi not found in ${NDPI_LIB_DIR}")
endif()

# ── System libraries ─────────────────────────────────────────────────
find_library(PCAP_LIBRARY pcap REQUIRED)
find_library(ZMQ_LIBRARY  zmq  REQUIRED)

# ── cJSON: ALWAYS use the embedded copy ──────────────────────────────
# Linking both src/cJSON.c (compiled in) AND the system libcjson.so
# causes ABI mismatches when the struct layouts differ between versions.
# The embedded copy is the single source of truth; do not link the
# system library even when it is present on this machine.
message(STATUS "cJSON: using embedded src/cJSON.c (system libcjson NOT linked)")

# ── Source files ─────────────────────────────────────────────────────
set(SENSOR_SOURCES
    src/main.c
    src/flow_table.c
    src/ndpi_wrapper.c
    src/zmq_publisher.c
    src/stats.c
    src/cJSON.c       # always compile embedded cJSON
)

# ── Sensor executable ────────────────────────────────────────────────
add_executable(sensor ${SENSOR_SOURCES})

target_include_directories(sensor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
    ${NDPI_THIRD_PARTY_DIR}
)

target_link_libraries(sensor PRIVATE
    ${NDPI_LIBRARY}
    ${PCAP_LIBRARY}
    ${ZMQ_LIBRARY}
    m           # sqrt for Welford stddev
    pthread     # nDPI internals
    # NOTE: libcjson intentionally omitted — embedded cJSON.c is used
)

# ── ZMQ sink (standalone C consumer for end-to-end test) ─────────────
add_executable(zmq_sink src/zmq_sink.c)

target_include_directories(zmq_sink PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(zmq_sink PRIVATE
    ${ZMQ_LIBRARY}
)

# ── Stats unit test ──────────────────────────────────────────────────
add_executable(test_stats src/test_stats.c)

target_include_directories(test_stats PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(test_stats PRIVATE m)

# ── Flow direction / byte-accounting unit test ───────────────────────
#   Uses flow_entry_t declared in flow_table.h; does not call
#   flow_table_* (so does not need libndpi at link time).  The nDPI
#   include path is needed because flow_table.h pulls in <ndpi_api.h>.
add_executable(test_flow src/test_flow.c)

target_include_directories(test_flow PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${NDPI_INCLUDE_DIR}
    ${NDPI_THIRD_PARTY_DIR}
)

# ── Install ──────────────────────────────────────────────────────────
install(TARGETS sensor zmq_sink RUNTIME DESTINATION bin)

# ── Summary ──────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "╔══════════════════════════════════════════╗")
message(STATUS "║   SentinelFlow Sensor — Build Config     ║")
message(STATUS "╠══════════════════════════════════════════╣")
message(STATUS "║  nDPI root:    ${NDPI_ROOT}")
message(STATUS "║  nDPI lib:     ${NDPI_LIBRARY}")
message(STATUS "║  libpcap:      ${PCAP_LIBRARY}")
message(STATUS "║  libzmq:       ${ZMQ_LIBRARY}")
message(STATUS "║  cJSON:        embedded src/cJSON.c")
message(STATUS "╚══════════════════════════════════════════╝")
message(STATUS "")
