inherit kernel_filter_cve_path

python do_clean:append() {
    import os, glob
    deploy_dir = d.expand('${DEPLOY_DIR_IMAGE}')
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_filtered.json')):
        bb.note("Removing " + f)
        os.remove(f)
    for f in glob.glob(os.path.join(deploy_dir, '*kernel_remaining_cves_map.json')):
        bb.note("Removing " + f)
        os.remove(f)
}

python do_get_kernel_mainline() {
    import subprocess
    import shutil, os
    kernel_filter_cve_path = d.getVar("KERNEL_FILTER_CVE_PATH")
    git_kernel_org_path = os.path.join(kernel_filter_cve_path,"git.kernel.org")
    if os.path.exists(git_kernel_org_path):
        shutil.rmtree(git_kernel_org_path)
    if not os.path.exists(kernel_filter_cve_path):
        os.makedirs(kernel_filter_cve_path)
    d.setVar("SRC_URI", "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git;branch=master;protocol=https")
    d.setVar("SRCREV", "${AUTOREV}")
    src_uri = (d.getVar('SRC_URI') or "").split()
    fetcher = bb.fetch2.Fetch(src_uri, d)
    fetcher.download()
    fetcher.unpack(git_kernel_org_path)
    # Remove the folder ${PN} set by unpack (like core-image-minimal)
    subdirs = [d for d in os.listdir(git_kernel_org_path) if os.path.isdir(os.path.join(git_kernel_org_path, d))]
    if len(subdirs) == 1:
        srcdir = os.path.join(git_kernel_org_path, subdirs[0])
        for f in os.listdir(srcdir):
            shutil.move(os.path.join(srcdir, f), git_kernel_org_path)
        shutil.rmtree(srcdir)
}
do_get_kernel_mainline[network] = "1"
do_get_kernel_mainline[nostamp] = "1"
do_get_kernel_mainline[doc] = "Clone the latest kernel mainline from https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
addtask get_kernel_mainline after do_fetch before do_kernel_filter_cve

do_kernel_filter_cve() {
    original_cve_check_file="${DEPLOY_DIR_IMAGE}/${IMAGE_LINK_NAME}.json"
    new_cve_report_file="${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_filtered.json"
    new_kernel_remaining_cves_maps_file="${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves_map.json"
    kernel_filter_cve_script=$(find ${COREBASE}/.. -name "kernel_filter_cve.py")
    kernel_filter_cve_config_file="${KERNEL_FILTER_CVE_PATH}/defconfig"

    if [ ! -f "${original_cve_check_file}" ]; then
        bbwarn "Kernel_filter_cve: cve-check file not found: ${original_cve_check_file}"
        return 0
    fi

    if [ ! -f "${kernel_filter_cve_config_file}" ]; then
        bbwarn "Kernel_filter_cve: .config file not found: ${kernel_filter_cve_config_file}"
        return 0
    fi

    if [ -z "${NVD_API_KEY}" ]; then
        bbwarn "Kernel_filter_cve: NVD_API_KEY is not set, skipping kernel CVE filtering."
        return 0
    fi

    if [ ! -f "${kernel_filter_cve_script}" ]; then
        bbwarn "Kernel_filter_cve: kernel_filter_cve.py script not found: ${kernel_filter_cve_script}"
        return 0
    fi

    #Launch the kernel filtering script
    python3 "${kernel_filter_cve_script}" \
        --cve-check-input "${original_cve_check_file}" \
        --output-files-name "${IMAGE_LINK_NAME}" \
        --output-path "${DEPLOY_DIR_IMAGE}" \
        --nvd-api-key "${NVD_API_KEY}" \
        --git-kernel-org-path "${KERNEL_FILTER_CVE_PATH}/git.kernel.org" \
        --nvd-cache-path "${KERNEL_FILTER_CVE_PATH}/nvd_cache.json" \
        --kernel-path "${STAGING_KERNEL_DIR}" \
        --config-path "${kernel_filter_cve_config_file}"

    bbplain "New cve-check generated report with kernel cves filtered: ${new_cve_report_file}"

    #Create a symlink as every other JSON file in tmp/deploy/images
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_remaining_cves_map.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_remaining_cves_map.json
    ln -sf ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.kernel_filtered.json ${DEPLOY_DIR_IMAGE}/${IMAGE_BASENAME}${IMAGE_MACHINE_SUFFIX}${IMAGE_NAME_SUFFIX}.kernel_filtered.json
}
do_kernel_filter_cve[nostamp] = "1"
do_kernel_filter_cve[doc] = "Run kernel filtering on the specified CVE"
addtask kernel_filter_cve
#addtask kernel_filter_cve after do_image_complete