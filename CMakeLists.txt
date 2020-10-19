set(TARGET_NAME tea-protocol-plugin)
setup_hifi_client_server_plugin()
link_hifi_libraries(shared plugins networking)

target_openssl()

# if (NOT TEA_PROTOCOL_VERSION)
# 	if (RELEASE_TYPE STREQUAL "PRODUCTION")
# 		message(FATAL_ERROR "TEA_PROTOCOL_VERSION not set in a ${RELEASE_TYPE} build!")
# 	else ()
# 		message(WARNING "TEA_PROTOCOL_VERSION not set in a ${RELEASE_TYPE} build!")
# 		endif()
# else ()
# 	message(STATUS "The TEA_PROTOCOL_VERSION variable is: ${TEA_PROTOCOL_VERSION}")
# 	set_target_properties(${TARGET_NAME} PROPERTIES
# 		VERSION "${TEA_PROTOCOL_VERSION}"
# 		SOVERSION "${TEA_PROTOCOL_VERSION}"
# 	)
# endif ()