#!/bin/bash

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No color

# Function to display success messages in green
function success {
    echo -e "${GREEN}$1${NC}"
}

# Function to display failure messages in red
function fail {
    echo -e "${RED}$1${NC}"
}

# Function to display warning messages in yellow
function warn {
    echo -e "${YELLOW}$1${NC}"
}

# Function to display warning messages in yellow
function info {
    echo -e "${BLUE}$1${NC}"
}

# Banner to show at the start of the script
function banner {
    echo -e "${BLUE}====================================="
    echo -e "      cscrta_recon - Linux Recon"
    echo -e "=====================================${NC}"

}

# Kernel Information
function kernel_info {
    echo -e "\n${YELLOW}Checking Kernel Information...${NC}"
    uname -a
}

# Architecture & OS Info
function os_info {
    echo -e "\n${YELLOW}Checking Architecture & OS Info...${NC}"
    uname -m
    lsb_release -a 2>/dev/null || echo "No lsb_release found, trying /etc/os-release..."
    cat /etc/os-release 2>/dev/null
}

# Running Processes
function running_processes {
    echo -e "\n${YELLOW}Checking Running Processes...${NC}"
    ps aux --sort=-%cpu | head -n 20
}

# SUID/SGID Files
function suid_sgid_files {
    echo -e "\n${YELLOW}Checking for SUID/SGID Files...${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read file; do
        fail "$file"
    done
}

# World Writable Files
function world_writable_files {
    echo -e "\n${YELLOW}Checking for World Writable Files...${NC}"
    find / -type f -writable -exec ls -l {} \; 2>/dev/null | while read file; do
        fail "$file"
    done
}

# Cron Jobs
function cron_jobs {
    echo -e "\n${YELLOW}Checking for Cron Jobs...${NC}"
    crontab -l 2>/dev/null
    ls -la /etc/cron* 2>/dev/null
}

# Network Information
function network_info {
    echo -e "\n${YELLOW}Checking Network Information...${NC}"
    ifconfig -a
    ip addr show
    netstat -tulnp
}

# SSH Configurations
function ssh_config {
    echo -e "\n${YELLOW}Checking SSH Configurations...${NC}"
    cat /etc/ssh/sshd_config 2>/dev/null
    echo "Checking for SSH key files:"
    ls -la /root/.ssh 2>/dev/null
}

# Sudo Caching & Sudoers
function sudo_caching {
    echo -e "\n${YELLOW}Checking Sudo Caching & Sudoers Config...${NC}"
    sudo -l 2>/dev/null
    cat /etc/sudoers 2>/dev/null
    ls -la /etc/sudoers.d 2>/dev/null
}

# Writable Directories
function writable_directories {
    echo -e "\n${YELLOW}Checking Writable Directories...${NC}"
    echo "$PATH" | tr ':' '\n' | while read dir; do
        if [ -w "$dir" ]; then
            fail "Writable directory found in PATH: $dir"
        fi
    done
}

# Unusual Environment Variables
function unusual_env_vars {
    echo -e "\n${YELLOW}Checking Unusual Environment Variables...${NC}"
    env | grep -i "http_proxy" && info "Found http_proxy variable"
    env | grep -i "ftp_proxy" && info "Found ftp_proxy variable"
    env | grep -i "user" && info "Found user environment variable"
    env | grep -i "http_proxy" && info "Found http_proxy variable"
    env | grep -i "https_proxy" && info "Found https_proxy variable"
    env | grep -i "ftp_proxy" && info "Found ftp_proxy variable"
    env | grep -i "user" && info "Found user environment variable"
    env | grep -i "LD_PRELOAD" && info "Found LD_PRELOAD variable"
    env | grep -i "PATH" && info "Found PATH environment variable"
    env | grep -i "SUDO_ASKPASS" && info "Found SUDO_ASKPASS variable"
    env | grep -i "HISTFILE" && info "Found HISTFILE variable"
    env | grep -i "IFS" && info "Found IFS environment variable"
    env | grep -i "TMPDIR" && info "Found TMPDIR environment variable"
    env | grep -i "TEMP" && info "Found TEMP environment variable"
    env | grep -i "MAIL" && info "Found MAIL environment variable"
    env | grep -i "PS1" && info "Found PS1 environment variable"
    env | grep -i "USER" && info "Found USER environment variable"
    env | grep -i "LOGNAME" && info "Found LOGNAME environment variable"
    env | grep -i "LD_LIBRARY_PATH" && info "Found LD_LIBRARY_PATH variable"
    env | grep -i "EDITORS" && info "Found EDITORS environment variable"
    env | grep -i "ALIAS" && info "Found ALIAS environment variable"

}

# Path Variable & Abuses
function path_abuses {
    echo -e "\n${YELLOW}Checking Path Variable & Abuses...${NC}"
    echo "$PATH" | tr ':' '\n' | while read dir; do
        if [ -w "$dir" ]; then
            fail "Writable directory found in PATH: $dir"
        fi
    done
}

# File Permissions & Ownership
function file_permissions {
    echo -e "\n${YELLOW}Checking File Permissions & Ownership...${NC}"

    # Buscar archivos con permisos 0777 en directorios críticos como /etc, /bin, /usr, /lib, /home
    echo -e "${YELLOW}Searching for world-writable files in critical directories...${NC}"
    find /etc /bin /usr /lib /home -type f -perm 0777 2>/dev/null | while read file; do
        fail "World-writable file found: $file"
    done

    # Buscar archivos sin propietario o grupo en directorios críticos
    echo -e "${YELLOW}Searching for files with no owner/group in critical directories...${NC}"
    find /etc /bin /usr /lib /home -nouser -o -nogroup 2>/dev/null | while read file; do
        fail "File with no owner/group: $file"
    done
}


# Running Services
function running_services {
    echo -e "\n${YELLOW}Checking Running Services...${NC}"
    systemctl list-units --type=service --state=running --no-pager  # Avoid pager explicitly
}


# Installed Packages & Vulnerabilities
function installed_packages {
    echo -e "\n${YELLOW}Checking Installed Packages & Vulnerabilities...${NC}"
    dpkg-query -l 2>/dev/null | cat  # Usar dpkg-query en lugar de dpkg
    rpm -qa 2>/dev/null | cat  # Redirige la salida de rpm para evitar el pager
}


# Capabilities of Binaries
function capabilities {
    echo -e "\n${YELLOW}Checking Capabilities of Binaries...${NC}"
    getcap -r / 2>/dev/null | while read cap; do
        fail "Binary with capabilities: $cap"
    done
}

# Checking for kernel exploits
function kernel_exploits {
    echo -e "\n${YELLOW}Checking for Kernel Exploits...${NC}"
    dmesg | grep -i exploit && fail "Possible kernel exploit found"
    cat /proc/version
}

# Misconfigurations in Security Tools
function security_misconfig {
    echo -e "\n${YELLOW}Checking for Misconfigurations in Security Tools...${NC}"
    echo -e "\n${BLUE}--------------------/etc/security/limits.conf--------------------${NC}"
    cat /etc/security/limits.conf 2>/dev/null
    echo -e "\n${BLUE}--------------------/etc/pam.d--------------------${NC}"
    cat /etc/pam.d/* 2>/dev/null
}

# Sensitive Files (e.g., password, shadow, etc.)
function sensitive_files {
    echo -e "\n${YELLOW}Checking Sensitive Files...${NC}"

    # Check if /etc/shadow and /etc/passwd have insecure permissions
    echo -e "\n${YELLOW}Checking /etc/shadow and /etc/passwd permissions...${NC}"
    ls -la /etc/shadow 2>/dev/null | grep -q "^-rw" && fail "/etc/shadow is world-readable or owned by wrong user"
    ls -la /etc/passwd 2>/dev/null | grep -q "^-rw" && fail "/etc/passwd is world-readable or owned by wrong user"

    # Check for files containing 'password' in their name in critical directories
    echo -e "\n${YELLOW}Searching for files containing 'password' in their name...${NC}"
    find /etc /home /root /usr  -type f -iname "*password*" 2>/dev/null | while read file; do
        echo -e "Found sensitive file: ${YELLOW}$file${NC}"
        ls -la "$file" 2>/dev/null
    done

    # Check for sensitive files with extensions like .key, .cert, .rsa
    echo -e "\n${YELLOW}Searching for sensitive files (.key, .cert, .rsa)...${NC}"
    find /etc /home /root /usr  -type f \( -iname "*.key" -o -iname "*.cert" -o -iname "*.rsa" \) 2>/dev/null | while read file; do
        echo -e "Found sensitive file: ${YELLOW}$file${NC}"
        ls -la "$file" 2>/dev/null
    done
}




# NFS Shares
function nfs_shares {
    echo -e "\n${YELLOW}Checking NFS Shares...${NC}"
    exportfs -v 2>/dev/null
}




# Log Files
function log_files {
    echo -e "\n${YELLOW}Checking Log Files...${NC}"
    echo -e "\n${BLUE}------------------------var/log/auth.log-------------------------${NC}"
    tail -n 20 /var/log/auth.log 2>/dev/null
    echo -e "\n${BLUE}------------------------/var/log/syslog-------------------------${NC}"
    tail -n 20 /var/log/syslog 2>/dev/null
}


# History Files (e.g., bash, zsh, etc.)
function history_files {
    echo -e "\n${YELLOW}Checking History Files...${NC}"
    cat ~/.bash_history 2>/dev/null
    cat ~/.zsh_history 2>/dev/null
}

# Audit Logs
function audit_logs {
    echo -e "\n${YELLOW}Checking Audit Logs...${NC}"
    echo -e "\n${BLUE}------------------------/var/log/audit/audit.log-------------------------${NC}"
    tail -n 20 /var/log/audit/audit.log 2>/dev/null
}

# Cron Job Permissions
function cron_permissions {
    echo -e "\n${YELLOW}Checking Cron Job Permissions...${NC}"
    ls -la /etc/cron* 2>/dev/null
}

# Rootkits
function rootkits {
    echo -e "\n${YELLOW}Checking for Rootkits...${NC}"
    chkrootkit 2>/dev/null
    rkhunter --check 2>/dev/null
}

# System Misconfigurations
function system_misconfig {
    echo -e "\n${YELLOW}Checking for System Misconfigurations...${NC}"
    sysctl -a 2>/dev/null
}

# Docker Configuration (if applicable)
function docker_config {
    echo -e "\n${YELLOW}Checking Docker Configuration...${NC}"
    docker info 2>/dev/null
    docker ps 2>/dev/null
}

# Virtualization (VM & Container Info)
function virtualization_info {
    echo -e "\n${YELLOW}Checking Virtualization Info...${NC}"
    dmidecode -t system 2>/dev/null
    lscpu 2>/dev/null
    cat /proc/cpuinfo 2>/dev/null
}

# User Permissions & Groups INCLUDES LDAP
function user_permissions {
    echo -e "\n${YELLOW}Checking User Permissions & Groups...${NC}"
    id
    getent passwd
    getent group
}

# Command History
function command_history {
    echo -e "\n${YELLOW}Checking Command History...${NC}"
    cat ~/.bash_history 2>/dev/null
    cat ~/.zsh_history 2>/dev/null
}

# System Binaries
function system_binaries {
    echo -e "\n${YELLOW}Checking System Binaries...${NC}"
    which sudo
    which python
    which bash
}

# Vulnerabilities in Binaries & Libraries
function binary_vulnerabilities {
    echo -e "\n${YELLOW}Checking Vulnerabilities in Binaries & Libraries...${NC}"
    ldd --version 2>/dev/null
    ldd /bin/* /usr/bin/* 2>/dev/null
}

# Main function to run all checks
function main {
    banner
    kernel_info
    os_info
    running_processes
    suid_sgid_files
   # world_writable_files
    cron_jobs
    network_info
    ssh_config
    sudo_caching
    writable_directories
    unusual_env_vars
    path_abuses
    file_permissions
    running_services
    installed_packages
    capabilities
    kernel_exploits
    security_misconfig
    sensitive_files
   # nfs_shares
    log_files
   # history_files
    audit_logs
    cron_permissions
    rootkits
   # system_misconfig
    docker_config
    virtualization_info
    user_permissions
   # command_history
    system_binaries
   # binary_vulnerabilities
}

# Run the main function
main

