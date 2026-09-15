#!/bin/bash
# Module: Node Security & Hardening Suite
# Features: Geosite.dat, UFW, SSH (Port 22222, Keys only), BBR, Sysctl, Fail2ban, Chrony, Unattended-upgrades, Disk monitor, WARP, Psiphon

HARDENING_DEFAULT_PANEL_IP="45.39.241.238"
HARDENING_PUB_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKXURtqsK6e4jhZ8HkF0TvfQLqVADBrmCTSrpGa8/Tjh lightbeam-vps"

# 1. Geosite.dat passthrough + Cron auto-update
harden_geosite_cron() {
    local target_dir=""
    if [ -d "/opt/remnanode" ]; then
        target_dir="/opt/remnanode"
    elif [ -d "/opt/remnawave" ]; then
        target_dir="/opt/remnawave"
    else
        target_dir="/opt/remnanode"
        mkdir -p "$target_dir"
    fi

    echo -e "${COLOR_YELLOW}[1/15] Настройка Geosite.dat и автообновления в Cron...${COLOR_RESET}"
    cd "$target_dir" || return 1
    mkdir -p assets

    echo -e "  - Скачивание актуального geosite.dat..."
    curl -sL -o ./assets/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    if [ ! -s ./assets/geosite.dat ]; then
        echo -e "${COLOR_RED}  ✗ Ошибка скачивания geosite.dat${COLOR_RESET}"
        return 1
    fi
    echo -e "${COLOR_GREEN}  ✓ geosite.dat успешно загружен${COLOR_RESET}"

    if [ -f docker-compose.yml ]; then
        if ! grep -q "geosite.dat" docker-compose.yml; then
            echo -e "  - Добавление проброса geosite.dat в docker-compose.yml..."
            sed -i '/container_name: remnanode/,/volumes:/ s|volumes:|volumes:\n      - ./assets/geosite.dat:/usr/local/share/xray/geosite.dat:ro\n      - ./assets/geosite.dat:/usr/share/xray/geosite.dat:ro|' docker-compose.yml
            docker compose up -d --force-recreate >/dev/null 2>&1 || true
        else
            echo -e "${COLOR_GREEN}  ✓ Проброс geosite.dat уже настроен в docker-compose.yml${COLOR_RESET}"
        fi
    fi

    echo -e "  - Настройка еженедельного обновления в cron (Пн, 04:00)..."
    (crontab -l 2>/dev/null | grep -v "geosite.dat"; echo "0 4 * * 1 curl -sL -o ${target_dir}/assets/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat && docker restart remnanode >/dev/null 2>&1") | crontab -
    echo -e "${COLOR_GREEN}  ✓ Geosite.dat настроен!${COLOR_RESET}"
    return 0
}

# 2 & 13. Clean UFW firewall configuration for Node
harden_ufw_firewall() {
    local panel_ip="${1:-$HARDENING_DEFAULT_PANEL_IP}"
    echo -e "${COLOR_YELLOW}[2/15] Чистая настройка UFW для Ноды (Мастер-панель IP: ${panel_ip})...${COLOR_RESET}"

    if ! command -v ufw >/dev/null 2>&1; then
        apt update -qq && apt install -y ufw >/dev/null 2>&1
    fi

    echo -e "  - Сброс правил UFW..."
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    echo -e "  - Открытие портов: 22222 (SSH), 22 (временный), 443 TCP/UDP, 80 TCP..."
    ufw allow 22/tcp comment 'SSH temporary' >/dev/null 2>&1 || true
    ufw allow 22222/tcp comment 'Custom SSH' >/dev/null 2>&1
    ufw allow 443/tcp comment 'VLESS Reality / Nginx' >/dev/null 2>&1
    ufw allow 443/udp comment 'Hysteria / QUIC' >/dev/null 2>&1
    ufw allow 80/tcp comment 'Certbot / HTTP' >/dev/null 2>&1

    echo -e "  - Разрешение порта 2222 строго для IP панели ${panel_ip}..."
    ufw allow from "$panel_ip" to any port 2222 proto tcp comment 'Remnawave Master Panel' >/dev/null 2>&1

    ufw --force enable >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ UFW успешно включен и сконфигурирован${COLOR_RESET}"
    ufw status numbered
    return 0
}

# 3. Hide Nginx version + Kernel Sysctl (BBR) + Fail2ban
harden_nginx_and_kernel() {
    echo -e "${COLOR_YELLOW}[3/15] Скрытие версии Nginx + Тюнинг ядра (Sysctl/BBR) + Fail2ban...${COLOR_RESET}"

    # Nginx server_tokens off
    for conf in /opt/remnanode/nginx.conf /opt/remnawave/nginx.conf; do
        if [ -f "$conf" ]; then
            if ! grep -q "server_tokens off;" "$conf"; then
                sed -i '1i server_tokens off;' "$conf"
                docker restart remnawave-nginx >/dev/null 2>&1 || true
                echo -e "${COLOR_GREEN}  ✓ Добавлен server_tokens off в $conf${COLOR_RESET}"
            fi
        fi
    done

    # Sysctl network and security tuning
    echo -e "  - Применение оптимизаций sysctl и BBR..."
    cat > /etc/sysctl.d/99-node-security.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl --system >/dev/null 2>&1

    # Fail2ban install
    echo -e "  - Установка Fail2ban..."
    apt update -qq && apt install -y fail2ban >/dev/null 2>&1
    systemctl enable --now fail2ban >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Nginx скрыт, sysctl BBR применен, fail2ban активен${COLOR_RESET}"
    return 0
}

# 4 & 8. SSH on port 22222 + Key-only login + Hardened SSH daemon
harden_ssh() {
    echo -e "${COLOR_YELLOW}[4/15] Перевод SSH на порт 22222 + Вход строго по Ключам + Тюнинг демона SSH...${COLOR_RESET}"

    # Setup authorized_keys
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    if ! grep -qxF "$HARDENING_PUB_KEY" /root/.ssh/authorized_keys 2>/dev/null; then
        echo "$HARDENING_PUB_KEY" >> /root/.ssh/authorized_keys
    fi
    chmod 600 /root/.ssh/authorized_keys
    echo -e "${COLOR_GREEN}  ✓ Публичный ключ lightbeam-vps добавлен в authorized_keys${COLOR_RESET}"

    # Update UFW for custom SSH port 22222 and remove default 22
    ufw allow 22222/tcp comment 'Custom SSH' >/dev/null 2>&1
    ufw delete allow 22/tcp >/dev/null 2>&1 || true
    ufw reload >/dev/null 2>&1

    # Write hardened sshd config
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-hardened-ssh.conf << 'EOF'
Port 22222
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin prohibit-password
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
EOF

    # Prevent cloud-init from overriding PasswordAuthentication
    if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
        sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config.d/50-cloud-init.conf
    fi

    # Disable password auth in main sshd_config as well
    if [ -f /etc/ssh/sshd_config ]; then
        sed -i -E 's/^#?PasswordAuthentication\s+yes/PasswordAuthentication no/g' /etc/ssh/sshd_config 2>/dev/null || true
    fi

    # Verify sshd syntax before restarting
    if sshd -t; then
        systemctl daemon-reload >/dev/null 2>&1
        (systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1)
        echo -e "${COLOR_GREEN}  ✓ SSH успешно переведен на порт 22222 (вход только по ключам)${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}  ✗ Ошибка синтаксиса sshd_config! Откат изменений...${COLOR_RESET}"
        rm -f /etc/ssh/sshd_config.d/99-hardened-ssh.conf
        return 1
    fi
    return 0
}

# 5. Precise time synchronization (Chrony / NTP)
harden_chrony() {
    echo -e "${COLOR_YELLOW}[5/15] Настройка синхронизации времени Chrony (NTP)...${COLOR_RESET}"
    apt update -qq && apt install -y chrony >/dev/null 2>&1
    systemctl enable --now chrony >/dev/null 2>&1
    timedatectl set-ntp on >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Chrony установлен и запущен. Статус синхронизации:${COLOR_RESET}"
    timedatectl status 2>/dev/null | grep -E "Time zone|Local time|Universal time|System clock synchronized|NTP service" || timedatectl status
    return 0
}

# 6. Automatic security patches (Unattended-Upgrades)
harden_unattended_upgrades() {
    echo -e "${COLOR_YELLOW}[6/15] Настройка автоматических патчей безопасности (Unattended-Upgrades)...${COLOR_RESET}"
    apt install -y unattended-upgrades >/dev/null 2>&1
    systemctl enable --now unattended-upgrades >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Unattended-Upgrades активен${COLOR_RESET}"
    return 0
}

# 7. Fail2ban jail for SSH on port 22222
harden_fail2ban_sshd() {
    echo -e "${COLOR_YELLOW}[7/15] Конфигурация Fail2ban для SSH (порт 22222)...${COLOR_RESET}"
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled = true
port = 22222
backend = systemd
mode = aggressive
maxretry = 3
findtime = 600
bantime = 86400
EOF
    systemctl restart fail2ban >/dev/null 2>&1
    sleep 2
    if fail2ban-client status sshd >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}  ✓ Jail [sshd] в Fail2ban активен на порту 22222${COLOR_RESET}"
    else
        echo -e "${COLOR_YELLOW}  ! Jail [sshd] сконфигурирован, сервис перезапущен${COLOR_RESET}"
    fi
    return 0
}

# 9. Hide OS banners
harden_hide_banners() {
    echo -e "${COLOR_YELLOW}[8/15] Скрытие системных баннеров ОС (/etc/issue)...${COLOR_RESET}"
    truncate -s 0 /etc/issue /etc/issue.net 2>/dev/null || true
    echo -e "${COLOR_GREEN}  ✓ Баннеры /etc/issue и /etc/issue.net очищены${COLOR_RESET}"
    return 0
}

# 10. Memory hardening, DNS via systemd-resolved, network blacklist, docker prune
harden_additional_security() {
    echo -e "${COLOR_YELLOW}[9/15] Дополнительная защита: память, DNS, blacklist протоколов, Docker prune...${COLOR_RESET}"

    # Memory hardening
    cat > /etc/sysctl.d/99-memory-hardening.conf << 'EOF'
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
EOF
    sysctl --system >/dev/null 2>&1
    echo -e "  - Memory hardening применен"

    # DNS configuration
    cat > /etc/systemd/resolved.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
FallbackDNS=1.0.0.1 8.8.4.4
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
EOF
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
    echo -e "  - Безопасные DNS-резолверы (1.1.1.1, 8.8.8.8, 9.9.9.9) настроены"

    # Network blacklist
    cat > /etc/modprobe.d/blacklist-network.conf << 'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    echo -e "  - Редкие сетевые протоколы (dccp, sctp, rds, tipc) заблокированы"

    # Docker image prune weekly
    (crontab -l 2>/dev/null | grep -v "docker image prune"; echo "0 3 * * 0 docker image prune -a --force --filter 'until=168h' && apt-get clean >/dev/null 2>&1") | crontab -
    echo -e "${COLOR_GREEN}  ✓ Дополнительные политики защиты успешно активированы${COLOR_RESET}"
    return 0
}

# 11. Lock root password hash
harden_lock_root_password() {
    echo -e "${COLOR_YELLOW}[10/15] Блокировка парольной аутентификации root на уровне системы...${COLOR_RESET}"
    passwd -l root >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Хеш пароля root заблокирован (passwd -l root)${COLOR_RESET}"
    return 0
}

# 12. Disk space control via Cron (>90% cleanup)
harden_disk_monitor_cron() {
    echo -e "${COLOR_YELLOW}[11/15] Настройка контроля свободного места на диске в Cron (>90%)...${COLOR_RESET}"
    (crontab -l 2>/dev/null | grep -v "docker system prune -af"; echo "0 */6 * * * [ \$(df / | awk 'NR==2 {print \$5}' | tr -d '%') -gt 90 ] && docker system prune -af >/dev/null 2>&1") | crontab -
    echo -e "${COLOR_GREEN}  ✓ Автоматическая очистка Docker при заполнении диска >90% добавлена в cron${COLOR_RESET}"
    return 0
}

# 13. Restrict port 2222 strictly to Master Panel IP
harden_restrict_panel_port() {
    local panel_ip="${1:-$HARDENING_DEFAULT_PANEL_IP}"
    echo -e "${COLOR_YELLOW}[12/15] Ограничение доступа к порту 2222 только для Master Panel IP (${panel_ip})...${COLOR_RESET}"
    ufw delete allow 2222/tcp >/dev/null 2>&1 || true
    ufw allow from "$panel_ip" to any port 2222 proto tcp comment 'Remnawave Master Panel' >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Порт 2222 открыт ТОЛЬКО для IP ${panel_ip}${COLOR_RESET}"
    return 0
}

# Master check and cleanup
harden_master_check() {
    echo -e "\n${COLOR_GREEN}====================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}          [15/15] МАСТЕР-ЧЕК БЕЗОПАСНОСТИ          ${COLOR_RESET}"
    echo -e "${COLOR_GREEN}====================================================${COLOR_RESET}"

    # Stop and disable iperf3 if running
    systemctl stop iperf3 2>/dev/null || killall -9 iperf3 2>/dev/null || true
    systemctl disable iperf3 2>/dev/null || true

    echo -e "\n=== 1. Проверка авторизации SSH (должно быть: no) ==="
    local pwd_auth
    pwd_auth=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" || echo "not found")
    echo -e "Результат: ${COLOR_YELLOW}$pwd_auth${COLOR_RESET}"

    if echo "$pwd_auth" | grep -qi "yes"; then
        echo -e "${COLOR_RED}  Обнаружен PasswordAuthentication yes! Принудительно исправляем...${COLOR_RESET}"
        if [ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]; then
            sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config.d/50-cloud-init.conf
        fi
        sed -i -E 's/^#?PasswordAuthentication\s+yes/PasswordAuthentication no/g' /etc/ssh/sshd_config 2>/dev/null || true
        sshd -t && (systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null)
        echo -e "Повторная проверка: ${COLOR_GREEN}$(sshd -T 2>/dev/null | grep -i "^passwordauthentication")${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}  ✓ Парольная авторизация по SSH успешно отключена!${COLOR_RESET}"
    fi

    echo -e "\n=== 2. Проверка внешних портов (только 80, 443, 22222, 2222 для панели) ==="
    ss -tulpn | grep LISTEN | grep -v "127.0.0.1" || echo "Нет открытых внешних сокетов"

    echo -e "\n=== 3. Проверка фонового iperf3 (должен отсутствовать) ==="
    if pgrep -a iperf3 >/dev/null 2>&1; then
        echo -e "${COLOR_RED}  Внимание: процесс iperf3 обнаружен, завершаем...${COLOR_RESET}"
        killall -9 iperf3 2>/dev/null || true
    else
        echo -e "${COLOR_GREEN}  ✓ iperf3 не запущен (OK)${COLOR_RESET}"
    fi

    echo -e "\n=== 4. Статус правил UFW ==="
    ufw status numbered

    echo -e "\n${COLOR_GREEN}✓ Комплекс тюнинга и защиты сервера ноды успешно применен!${COLOR_RESET}\n"
    return 0
}

# Run all hardening steps in order

# 13. Cloudflare WARP in SOCKS5 proxy mode (127.0.0.1:40000)
harden_install_warp() {
    echo -e "${COLOR_YELLOW}[13/15] Установка и настройка Cloudflare WARP (SOCKS5 Proxy mode)...${COLOR_RESET}"

    apt update -qq && apt install -y curl gpg lsb-release >/dev/null 2>&1

    local codename
    codename=$(lsb_release -cs 2>/dev/null)
    if [ -z "$codename" ]; then
        codename=$(grep -oP '(?<=VERSION_CODENAME=)[a-z]+' /etc/os-release 2>/dev/null || echo "bookworm")
    fi

    mkdir -p /usr/share/keyrings
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${codename} main" | tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null

    apt update -qq
    if ! apt install -y cloudflare-warp >/dev/null 2>&1; then
        echo -e "${COLOR_RED}  ✗ Ошибка установки пакета cloudflare-warp!${COLOR_RESET}"
        return 1
    fi

    systemctl enable --now warp-svc >/dev/null 2>&1 || true
    sleep 2

    echo -e "  - Регистрация и перевод WARP в режим proxy (SOCKS5)..."
    warp-cli --accept-tos registration new >/dev/null 2>&1 || warp-cli registration new >/dev/null 2>&1 || warp-cli register >/dev/null 2>&1 || true
    warp-cli --accept-tos mode proxy >/dev/null 2>&1 || warp-cli mode proxy >/dev/null 2>&1 || warp-cli set-mode proxy >/dev/null 2>&1 || true
    warp-cli --accept-tos connect >/dev/null 2>&1 || warp-cli connect >/dev/null 2>&1 || true

    sleep 3
    local warp_status
    warp_status=$(warp-cli --accept-tos status 2>/dev/null || warp-cli status 2>/dev/null || echo "Unknown")
    echo -e "  - Статус Cloudflare WARP: ${COLOR_YELLOW}${warp_status}${COLOR_RESET}"

    local warp_check
    warp_check=$(curl -s --socks5 127.0.0.1:40000 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "warp=" || echo "")
    if [[ "$warp_check" == *"warp=on"* || "$warp_check" == *"warp=plus"* ]]; then
        echo -e "${COLOR_GREEN}  ✓ Cloudflare WARP успешно подключен и работает в режиме SOCKS5 (127.0.0.1:40000)!${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}  ✓ Cloudflare WARP установлен и запущен (SOCKS5 127.0.0.1:40000). Статус: ${warp_status}${COLOR_RESET}"
    fi
    return 0
}

manage_warp_menu() {
    while true; do
        echo -e ""
        echo -e "${COLOR_GREEN}=== Cloudflare WARP (SOCKS5 Proxy) ===${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}1. Установить и настроить Cloudflare WARP (SOCKS5 127.0.0.1:40000)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}2. Проверить статус WARP и тест подключения${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}3. Переподключить WARP (reconnect)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}4. Отключить и удалить Cloudflare WARP${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}0. Назад в меню тюнинга${COLOR_RESET}"
        echo -e ""
        read -rp "Выберите действие (0-4): " WARP_CHOICE
        case $WARP_CHOICE in
            1)
                harden_install_warp
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            2)
                echo -e "\n--- Статус службы warp-svc ---"
                systemctl status warp-svc --no-pager -l 2>/dev/null || echo "Служба не найдена"
                echo -e "\n--- Статус warp-cli ---"
                warp-cli --accept-tos status 2>/dev/null || warp-cli status 2>/dev/null || true
                echo -e "\n--- Тест SOCKS5 через 127.0.0.1:40000 ---"
                local trace
                trace=$(curl -s --socks5 127.0.0.1:40000 https://cloudflare.com/cdn-cgi/trace 2>/dev/null || echo "curl error")
                echo "$trace"
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            3)
                warp-cli --accept-tos disconnect 2>/dev/null || warp-cli disconnect 2>/dev/null || true
                sleep 1
                warp-cli --accept-tos connect 2>/dev/null || warp-cli connect 2>/dev/null || true
                echo -e "${COLOR_GREEN}Команда переподключения отправлена${COLOR_RESET}"
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            4)
                echo -e "${COLOR_RED}Вы уверены, что хотите удалить Cloudflare WARP? (y/n)${COLOR_RESET}"
                read -r cf_rm
                if [[ "$cf_rm" == "y" || "$cf_rm" == "Y" ]]; then
                    warp-cli --accept-tos disconnect 2>/dev/null || warp-cli disconnect 2>/dev/null || true
                    systemctl disable --now warp-svc >/dev/null 2>&1 || true
                    apt purge -y cloudflare-warp >/dev/null 2>&1 || true
                    rm -f /etc/apt/sources.list.d/cloudflare-client.list
                    rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
                    echo -e "${COLOR_GREEN}✓ Cloudflare WARP удален${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${COLOR_RED}Неверный выбор!${COLOR_RESET}"
                sleep 1
                ;;
        esac
    done
}

# 14. Psiphon egress tunnel (vps-psiphon via Docker)
harden_install_psiphon() {
    local region="$1"
    if [ -z "$region" ]; then
        echo -e "${COLOR_YELLOW}Доступные регионы Psiphon: AT, AU, BE, CA, CH, CZ, DE, DK, ES, FR, GB, IE, IT, JP, NL, NO, PL, SE, US и др.${COLOR_RESET}"
        read -rp "Введите двухбуквенный код страны для Psiphon [по умолчанию: DE]: " input_region
        region="${input_region:-DE}"
    fi
    region=$(echo "$region" | tr '[:lower:]' '[:upper:]' | tr -d ' ')

    echo -e "${COLOR_YELLOW}[14/15] Установка и настройка Psiphon tunnel (vps-psiphon, регион: ${region})...${COLOR_RESET}"

    if ! command -v docker >/dev/null 2>&1; then
        echo -e "  - Установка docker..."
        apt update -qq && apt install -y curl docker.io >/dev/null 2>&1
        systemctl enable --now docker >/dev/null 2>&1
    else
        systemctl enable --now docker >/dev/null 2>&1
    fi

    echo -e "  - Запуск скрипта установки vps-psiphon (--region ${region})..."
    bash <(curl -fsSL https://raw.githubusercontent.com/Chara-Freedom/vps-psiphon/main/psiphon_install.sh) --region "$region"

    if command -v vps-psiphon >/dev/null 2>&1; then
        echo -e "${COLOR_GREEN}  ✓ vps-psiphon успешно установлен!${COLOR_RESET}"
        vps-psiphon status || true
    else
        echo -e "${COLOR_YELLOW}  ! Установка завершена, проверьте статус командой vps-psiphon status${COLOR_RESET}"
    fi
    return 0
}

manage_psiphon_menu() {
    while true; do
        echo -e ""
        echo -e "${COLOR_GREEN}=== Psiphon Egress Tunnel (vps-psiphon) ===${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}1. Установить / переустановить Psiphon (выбор региона)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}2. Статус туннеля Psiphon (vps-psiphon status)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}3. Сменить регион выхода (vps-psiphon region <CC>)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}4. Принудительная ротация туннеля (vps-psiphon rotate)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}5. Тест скорости Psiphon (vps-psiphon speed)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}6. Просмотр логов контейнера Psiphon (vps-psiphon logs)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}7. Удалить Psiphon (vps-psiphon uninstall)${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}0. Назад в меню тюнинга${COLOR_RESET}"
        echo -e ""
        read -rp "Выберите действие (0-7): " PSI_CHOICE
        case $PSI_CHOICE in
            1)
                harden_install_psiphon
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            2)
                if command -v vps-psiphon >/dev/null 2>&1; then
                    vps-psiphon status
                else
                    echo -e "${COLOR_RED}Команда vps-psiphon не найдена! Psiphon еще не установлен.${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            3)
                if command -v vps-psiphon >/dev/null 2>&1; then
                    read -rp "Введите новый код страны (DE, SE, US, AT, NL...): " new_cc
                    if [ -n "$new_cc" ]; then
                        vps-psiphon region "$new_cc"
                    fi
                else
                    echo -e "${COLOR_RED}Команда vps-psiphon не найдена!${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            4)
                if command -v vps-psiphon >/dev/null 2>&1; then
                    vps-psiphon rotate
                else
                    echo -e "${COLOR_RED}Команда vps-psiphon не найдена!${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            5)
                if command -v vps-psiphon >/dev/null 2>&1; then
                    vps-psiphon speed
                else
                    echo -e "${COLOR_RED}Команда vps-psiphon не найдена!${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            6)
                if command -v vps-psiphon >/dev/null 2>&1; then
                    vps-psiphon logs 50
                else
                    echo -e "${COLOR_RED}Команда vps-psiphon не найдена!${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            7)
                if command -v vps-psiphon >/dev/null 2>&1; then
                    vps-psiphon uninstall
                else
                    echo -e "${COLOR_RED}Команда vps-psiphon не найдена!${COLOR_RESET}"
                fi
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${COLOR_RED}Неверный выбор!${COLOR_RESET}"
                sleep 1
                ;;
        esac
    done
}

apply_all_node_hardening() {
    local panel_ip="$1"
    local psiphon_reg="$2"

    if [ -z "$panel_ip" ]; then
        if [ -n "$PANEL_IP" ]; then
            panel_ip="$PANEL_IP"
        else
            echo -e "${COLOR_YELLOW}Введите IP-адрес мастер-панели для разрешения порта 2222 [по умолчанию: ${HARDENING_DEFAULT_PANEL_IP}]:${COLOR_RESET}"
            read -r input_ip
            panel_ip="${input_ip:-$HARDENING_DEFAULT_PANEL_IP}"
        fi
    fi

    if [ -z "$psiphon_reg" ]; then
        if [ -t 0 ]; then
            echo -e "${COLOR_YELLOW}Введите регион для Psiphon (DE, SE, US, NL и т.д.) [по умолчанию: DE]:${COLOR_RESET}"
            read -r input_psi
            psiphon_reg="${input_psi:-DE}"
        else
            psiphon_reg="DE"
        fi
    fi

    echo -e "\n${COLOR_GREEN}==============================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}  Запуск полного комплекса тюнинга и защиты сервера ноды      ${COLOR_RESET}"
    echo -e "${COLOR_GREEN}==============================================================${COLOR_RESET}\n"

    harden_geosite_cron
    harden_ufw_firewall "$panel_ip"
    harden_nginx_and_kernel
    harden_ssh
    harden_chrony
    harden_unattended_upgrades
    harden_fail2ban_sshd
    harden_hide_banners
    harden_additional_security
    harden_lock_root_password
    harden_disk_monitor_cron
    harden_restrict_panel_port "$panel_ip"
    harden_install_warp
    harden_install_psiphon "$psiphon_reg"
    harden_master_check

    echo -e "${COLOR_YELLOW}ВАЖНО: Ваш SSH переведен на порт 22222.${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Для следующего входа используйте:${COLOR_RESET}"
    echo -e "${COLOR_WHITE}ssh -p 22222 root@<IP_НОДЫ>${COLOR_RESET}\n"
}

# Interactive sub-menu
manage_node_hardening() {
    while true; do
        echo -e ""
        echo -e "${COLOR_GREEN}=== Тюнинг и защита сервера ноды (Hardening Suite) ===${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}1. Полный комплекс тюнинга и защиты (Все шаги 1-15: Hardening + WARP + Psiphon) [Рекомендуется]${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}2. Проброс Geosite.dat + автообновление в Cron${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}3. Настройка UFW для ноды (Порт 2222 только для Панели, 443, 22222)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}4. Скрытие версии Nginx (server_tokens off) + Sysctl (BBR) + Fail2ban${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}5. Перевод SSH на порт 22222 + Вход строго по ключам (lightbeam-vps)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}6. Синхронизация времени Chrony (NTP)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}7. Автоматические патчи безопасности (Unattended-Upgrades)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}8. Конфигурация Fail2ban jail для SSH (порт 22222)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}9. Скрытие системных баннеров ОС (/etc/issue)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}10. Дополнительная защита (Memory, DNS, Blacklist, Prune cron)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}11. Блокировка пароля root (passwd -l root)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}12. Контроль свободного места на диске в Cron (>90%)${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}13. Ограничить порт 2222 только для Master Panel IP${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}14. Cloudflare WARP (SOCKS5 proxy: 127.0.0.1:40000) — установка и управление${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}15. Psiphon egress tunnel (vps-psiphon SOCKS5: 1080) — установка и управление${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}16. Запустить мастер-чек безопасности и проверку портов/служб${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}0. Назад в главное меню${COLOR_RESET}"
        echo -e ""

        read -rp "Выберите действие (0-16): " HARDEN_CHOICE

        case $HARDEN_CHOICE in
            1)
                apply_all_node_hardening
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            2)
                harden_geosite_cron
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            3)
                read -rp "Введите IP мастер-панели [$HARDENING_DEFAULT_PANEL_IP]: " p_ip
                harden_ufw_firewall "${p_ip:-$HARDENING_DEFAULT_PANEL_IP}"
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            4)
                harden_nginx_and_kernel
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            5)
                harden_ssh
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            6)
                harden_chrony
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            7)
                harden_unattended_upgrades
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            8)
                harden_fail2ban_sshd
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            9)
                harden_hide_banners
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            10)
                harden_additional_security
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            11)
                harden_lock_root_password
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            12)
                harden_disk_monitor_cron
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            13)
                read -rp "Введите IP мастер-панели [$HARDENING_DEFAULT_PANEL_IP]: " p_ip
                harden_restrict_panel_port "${p_ip:-$HARDENING_DEFAULT_PANEL_IP}"
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            14)
                manage_warp_menu
                ;;
            15)
                manage_psiphon_menu
                ;;
            16)
                harden_master_check
                read -rp "Нажмите Enter для продолжения..." _
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${COLOR_RED}Неверный выбор!${COLOR_RESET}"
                sleep 1
                ;;
        esac
    done
}
