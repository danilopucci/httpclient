cmake_minimum_required(VERSION 3.0)

project(example_httpclient)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(Boost_USE_STATIC_LIBS ON)

# Find the Boost library and specify the required components (Boost.Beast)
#find_package(Boost REQUIRED COMPONENTS beast)
find_package(OpenSSL)

include_directories( ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Add your source files
set(SOURCE_FILES
    main.cpp
)

# Create the executable
add_executable(example_httpclient ${SOURCE_FILES})

# Include the header from the 'src' directory using a relative path
target_include_directories(example_httpclient PRIVATE src)

# Link the Boost.Beast library to your executable
target_link_libraries(example_httpclient 
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
)