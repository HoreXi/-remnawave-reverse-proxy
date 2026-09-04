#!/bin/bash
# Module: Node Security & Hardening Suite
# Features: Geosite.dat, UFW, SSH (Port 22222, Keys only), BBR, Sysctl, Fail2ban, Chrony, Unattended-upgrades, Disk monitor

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

    echo -e "${COLOR_YELLOW}[1/13] Настройка Geosite.dat и автообновления в Cron...${COLOR_RESET}"
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
    echo -e "${COLOR_YELLOW}[2/13] Чистая настройка UFW для Ноды (Мастер-панель IP: ${panel_ip})...${COLOR_RESET}"

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
    echo -e "${COLOR_YELLOW}[3/13] Скрытие версии Nginx + Тюнинг ядра (Sysctl/BBR) + Fail2ban...${COLOR_RESET}"

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
    echo -e "${COLOR_YELLOW}[4/13] Перевод SSH на порт 22222 + Вход строго по Ключам + Тюнинг демона SSH...${COLOR_RESET}"

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
    echo -e "${COLOR_YELLOW}[5/13] Настройка синхронизации времени Chrony (NTP)...${COLOR_RESET}"
    apt update -qq && apt install -y chrony >/dev/null 2>&1
    systemctl enable --now chrony >/dev/null 2>&1
    timedatectl set-ntp on >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Chrony установлен и запущен. Статус синхронизации:${COLOR_RESET}"
    timedatectl status 2>/dev/null | grep -E "Time zone|Local time|Universal time|System clock synchronized|NTP service" || timedatectl status
    return 0
}

# 6. Automatic security patches (Unattended-Upgrades)
harden_unattended_upgrades() {
    echo -e "${COLOR_YELLOW}[6/13] Настройка автоматических патчей безопасности (Unattended-Upgrades)...${COLOR_RESET}"
    apt install -y unattended-upgrades >/dev/null 2>&1
    systemctl enable --now unattended-upgrades >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Unattended-Upgrades активен${COLOR_RESET}"
    return 0
}

# 7. Fail2ban jail for SSH on port 22222
harden_fail2ban_sshd() {
    echo -e "${COLOR_YELLOW}[7/13] Конфигурация Fail2ban для SSH (порт 22222)...${COLOR_RESET}"
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
    echo -e "${COLOR_YELLOW}[8/13] Скрытие системных баннеров ОС (/etc/issue)...${COLOR_RESET}"
    truncate -s 0 /etc/issue /etc/issue.net 2>/dev/null || true
    echo -e "${COLOR_GREEN}  ✓ Баннеры /etc/issue и /etc/issue.net очищены${COLOR_RESET}"
    return 0
}

# 10. Memory hardening, DNS via systemd-resolved, network blacklist, docker prune
harden_additional_security() {
    echo -e "${COLOR_YELLOW}[9/13] Дополнительная защита: память, DNS, blacklist протоколов, Docker prune...${COLOR_RESET}"

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
    echo -e "${COLOR_YELLOW}[10/13] Блокировка парольной аутентификации root на уровне системы...${COLOR_RESET}"
    passwd -l root >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Хеш пароля root заблокирован (passwd -l root)${COLOR_RESET}"
    return 0
}

# 12. Disk space control via Cron (>90% cleanup)
harden_disk_monitor_cron() {
    echo -e "${COLOR_YELLOW}[11/13] Настройка контроля свободного места на диске в Cron (>90%)...${COLOR_RESET}"
    (crontab -l 2>/dev/null | grep -v "docker system prune -af"; echo "0 */6 * * * [ \$(df / | awk 'NR==2 {print \$5}' | tr -d '%') -gt 90 ] && docker system prune -af >/dev/null 2>&1") | crontab -
    echo -e "${COLOR_GREEN}  ✓ Автоматическая очистка Docker при заполнении диска >90% добавлена в cron${COLOR_RESET}"
    return 0
}

# 13. Restrict port 2222 strictly to Master Panel IP
harden_restrict_panel_port() {
    local panel_ip="${1:-$HARDENING_DEFAULT_PANEL_IP}"
    echo -e "${COLOR_YELLOW}[12/13] Ограничение доступа к порту 2222 только для Master Panel IP (${panel_ip})...${COLOR_RESET}"
    ufw delete allow 2222/tcp >/dev/null 2>&1 || true
    ufw allow from "$panel_ip" to any port 2222 proto tcp comment 'Remnawave Master Panel' >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
    echo -e "${COLOR_GREEN}  ✓ Порт 2222 открыт ТОЛЬКО для IP ${panel_ip}${COLOR_RESET}"
    return 0
}

# Master check and cleanup
harden_master_check() {
    echo -e "\n${COLOR_GREEN}====================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}          [13/13] МАСТЕР-ЧЕК БЕЗОПАСНОСТИ          ${COLOR_RESET}"
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
apply_all_node_hardening() {
    local panel_ip="$1"
    if [ -z "$panel_ip" ]; then
        if [ -n "$PANEL_IP" ]; then
            panel_ip="$PANEL_IP"
        else
            echo -e "${COLOR_YELLOW}Введите IP-адрес мастер-панели для разрешения порта 2222 [по умолчанию: ${HARDENING_DEFAULT_PANEL_IP}]:${COLOR_RESET}"
            read -r input_ip
            panel_ip="${input_ip:-$HARDENING_DEFAULT_PANEL_IP}"
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
        echo -e "${COLOR_YELLOW}1. Полный комплекс тюнинга и защиты (Все шаги 1-13) [Рекомендуется]${COLOR_RESET}"
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
        echo -e "${COLOR_YELLOW}14. Запустить мастер-чек безопасности и проверку портов${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}0. Назад в главное меню${COLOR_RESET}"
        echo -e ""

        read -rp "Выберите действие (0-14): " HARDEN_CHOICE

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
