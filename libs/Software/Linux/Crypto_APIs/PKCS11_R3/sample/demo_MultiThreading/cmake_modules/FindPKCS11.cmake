if(CMAKE_HOST_LINUX)
    find_path(PKCS11_INCLUDE_DIR
            NAMES pkcs11.h
            PATHS /Utimaco/CryptoServer/Software/Linux/Crypto_APIs/PKCS11_R3/include
            REQUIRED)
    find_library(PKCS11_LIBRARY
            NAMES libcs_pkcs11_R3.so
            PATHS /Utimaco/CryptoServer/Software/Linux/Crypto_APIs/PKCS11_R3/lib
            REQUIRED)
elseif(CMAKE_HOST_WIN32)
    find_path(PKCS11_INCLUDE_DIR
            NAMES pkcs11.h
            PATHS "C:/Program Files/Utimaco/SecurityServer/Software/PKCS11_R3/include"
            REQUIRED)
    find_library(PKCS11_LIBRARY
            NAMES cs_pkcs11_R3.lib
            PATHS "C:/Program Files/Utimaco/SecurityServer/Lib"
            REQUIRED)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PKCS11
        REQUIRED_VARS PKCS11_LIBRARY PKCS11_INCLUDE_DIR)

if(PKCS11_FOUND)
    set(PKCS11_LIBRARIES ${PKCS11_LIBRARY})
    set(PKCS11_INCLUDE_DIRS ${PKCS11_INCLUDE_DIR})
    if(NOT TARGET PKCS11::PKCS11)
        add_library(PKCS11::PKCS11 UNKNOWN IMPORTED)
        set_target_properties(PKCS11::PKCS11 PROPERTIES
                IMPORTED_LOCATION "${PKCS11_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${PKCS11_INCLUDE_DIR}")
    endif()
endif()

mark_as_advanced(PKCS11_INCLUDE_DIR
        PKCS11_LIBRARY)
