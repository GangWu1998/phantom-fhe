#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "phantom::Phantom" for configuration ""
set_property(TARGET phantom::Phantom APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(phantom::Phantom PROPERTIES
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libPhantom.so"
  IMPORTED_SONAME_NOCONFIG "libPhantom.so"
  )

list(APPEND _IMPORT_CHECK_TARGETS phantom::Phantom )
list(APPEND _IMPORT_CHECK_FILES_FOR_phantom::Phantom "${_IMPORT_PREFIX}/lib/libPhantom.so" )

# Import target "phantom::Boot" for configuration ""
set_property(TARGET phantom::Boot APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(phantom::Boot PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CUDA"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libBoot.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS phantom::Boot )
list(APPEND _IMPORT_CHECK_FILES_FOR_phantom::Boot "${_IMPORT_PREFIX}/lib/libBoot.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
