inherit kernel_filter_cve_path

python do_clean:append() {
    import os
    kernel_filter_cve_path = d.getVar("KERNEL_FILTER_CVE_PATH")
    config_file = os.path.join(kernel_filter_cve_path, 'defconfig')
    if os.path.isfile(config_file):
        bb.note("Removing " + config_file)
        os.remove(config_file)
}

do_saveconfig(){
    if [ ! -d "${KERNEL_FILTER_CVE_PATH}" ]; then
        mkdir -p ${KERNEL_FILTER_CVE_PATH}
    fi
    if [ -f "${KERNEL_FILTER_CVE_PATH}/defconfig" ]; then
        bbwarn "Kernel .config was already saved in kernel-filter-cve, overwriting..."
        rm -f ${KERNEL_FILTER_CVE_PATH}/defconfig
    fi
    cp ${B}/.config ${KERNEL_FILTER_CVE_PATH}/defconfig
    bbplain "Kernel .config file saved at: ${KERNEL_FILTER_CVE_PATH}/defconfig"
}
addtask saveconfig