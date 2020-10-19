set(TARGET_NAME tea-protocol-plugin)
setup_hifi_client_server_plugin()
link_hifi_libraries(shared plugins networking)

target_openssl()
