idf_component_register(SRCS
    "flag_generator_main.c"
    "chall_usb.c"
    "chall_webserver.c"
    "chall_decrypt.c"
    "chall_ulp_fsm.c"
    "chall_ulp_riscv.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_eth esp_http_server esp_netif mbedtls
    REQUIRES driver soc ulp
    EMBED_FILES "www/index.html" "www/simple.min.css" "www/favicon.ico" "www/sha256.min.js"
)

# ULP support additions to component CMakeLists.txt.

# ULP fsm
# 1. The ULP app name must be unique (if multiple components use ULP).
set(ulp_fsm_app_name ulp_fsm_${COMPONENT_NAME})
#
# 2. Specify all assembly source files.
#    Files should be placed into a separate directory (in this case, ulp/),
#    which should not be added to COMPONENT_SRCS.
set(ulp_fsm_s_sources "ulp-fsm/decrypt.S")
#
# 3. List all the component source files which include automatically
#    generated ULP export file, ${ulp_app_name}.h:
set(ulp_fsm_exp_dep_srcs "ulp_example_main.c")
#
# 4. Call function to build ULP binary and embed in project using the argument
#    values above.
ulp_embed_binary(${ulp_fsm_app_name} "${ulp_fsm_s_sources}" "${ulp_fsm_exp_dep_srcs}")

# ULP RISCV
# 1. The ULP app name must be unique (if multiple components use ULP).
set(ulp_riscv_app_name ulp_riscv_${COMPONENT_NAME})
#
# 2. Specify all assembly source files.
#    Files should be placed into a separate directory (in this case, ulp/),
#    which should not be added to COMPONENT_SRCS.
set(ulp_riscv_s_sources "ulp-riscv/main.c")
#
# 3. List all the component source files which include automatically
#    generated ULP export file, ${ulp_app_name}.h:
set(ulp_riscv_exp_dep_srcs "ulp_example_main.c")
#
# 4. Call function to build ULP binary and embed in project using the argument
#    values above.
ulp_embed_binary(${ulp_riscv_app_name} "${ulp_riscv_s_sources}" "${ulp_riscv_exp_dep_srcs}")
