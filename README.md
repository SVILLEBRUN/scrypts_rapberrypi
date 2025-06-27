# Fail2Ban Log Monitoring Guide

**Fail2Ban** is a security tool that helps protect servers by banning IP addresses that attempt brute-force attacks.

This guide provides useful commands and tips for monitoring Fail2Ban activity and managing ban history.

---

## 1. View Logs

- **Complete Fail2Ban log history** (including bans and unbans):
  ```bash
  cat /var/log/fail2ban.log
  ```
- **View only banned IP addresses:**
  ```bash
  grep 'Ban' /var/log/fail2ban.log
  ```
- **View only unbanned IP addresses:**
  ```bash
  grep 'Unban' /var/log/fail2ban.log
  ```

---

## 2. Log history over multiple days

- **Check archived logs:**
  ```bash
  ls /var/log/fail2ban.log*
  ```
You will typically see:
- `/var/log/fail2ban.log` — *active log*
- `/var/log/fail2ban.log.1` — *yesterday's log*
- `/var/log/fail2ban.log.2.gz` — *compressed log from two days ago*

- **Check archived logs:**
  ```bash
  zgrep 'Ban' /var/log/fail2ban.log.2.gz
  ```

---

## 3. Optional: Create a Custom Ban History File
To maintain a personalized log of banned IPs:
- **Refer to the file: bans-historique.log**
- **Use the script: archiver_bans.sh**

This script helps you archive ban history for easier tracking and reporting.
