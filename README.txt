Admintool — мониторинг и аудит РЕД ОС

Требования
  Linux, Bash, Python 3.9+, jq, ping, df, free, ss, chage, ps, flock,
  journalctl и firewalld. У Python-модулей нет сторонних зависимостей.
  Для полного доступа к журналу, shadow и firewalld нужен root.

Тесты из корня проекта
  PYTHONPATH=py python3 -m unittest discover -s py/tests -v
  Проверка логики реагирования использует подмену firewall-cmd и временные
  файлы. На РЕД ОС дополнительно проверяется реальное правило и его откат.

Пробный запуск
  sudo bash bin/admintool.sh --all --dry-run --format html
  sudo bash bin/admintool.sh --report --format json
  По умолчанию журналы и отчёты создаются в logs/. Для отдельного прогона
  укажите ADMINTOOL_LOG_DIR через sudo env. --dry-run выводит план
  реагирования. Без флага правило применяется на время из порогов.

Коды и настройки
  0 — штатный результат, 1 — предупреждение, 2 — критичная находка.
  Код 2 у отдельного logwatch означает ошибку входного источника, а у
  report — отсутствие данных или ошибку чтения. Оркестратор завершает
  такой прогон с кодом 3 и записывает этап в admintool.err.
  Пороги задаются в conf/thresholds.json. Для health WARN начинается
  с порога, CRIT — на десять процентных пунктов выше либо при 100%.
  unexpected_ports формирует предупреждение для проверки администратором.
  Список ожидаемых портов и защищённых IP следует сверить со стендом.

Установка на выделенной ВМ
  sudo install -d -m 0755 /opt/admintool
  sudo cp -R bin conf py /opt/admintool/
  sudo install -m 0644 systemd/admintool-*.service systemd/admintool-*.timer /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemd-analyze verify /etc/systemd/system/admintool-{health,logs,report}.{service,timer}
  sudo systemctl start admintool-health.service
  sudo systemctl start admintool-logs.service
  sudo systemctl start admintool-report.service
  sudo systemctl enable --now admintool-{health,logs,report}.timer
  systemctl list-timers 'admintool-*'
  sudo journalctl -u admintool-logs.service --no-pager -n 20
  sudo tail -n 20 /var/log/admintool/systemd.log

Откат временных правил
  sudo env ADMINTOOL_LOG_DIR=/var/log/admintool bash /opt/admintool/bin/respond.sh --unblock-all
  Для ручного запуска из исходников используется его каталог logs/.
