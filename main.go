// Command speedtest is a CLI network toolkit:
//   - internet: measure internet speed via the Yandex Internetometer API
//   - lan:      measure throughput to another host on the local network
//   - scan:     scan TCP ports on a single IP
//   - discover: sweep a subnet and report which hosts have which ports open
package main

import (
	"fmt"
	"os"

	"speedtest/internal/audit"
	"speedtest/internal/bwmon"
	"speedtest/internal/capture"
	"speedtest/internal/history"
	"speedtest/internal/lan"
	"speedtest/internal/menu"
	"speedtest/internal/monitor"
	"speedtest/internal/ping"
	"speedtest/internal/portscan"
	"speedtest/internal/speedtest"
	"speedtest/internal/trace"
	"speedtest/internal/tui"
	"speedtest/internal/webspeed"
	"speedtest/internal/wifi"
)

const usage = `speedtest - сетевой инструмент (CLI)

Запустите без аргументов, чтобы открыть полноэкранную панель (TUI).
Команда 'menu' открывает простое текстовое меню (без графики).

Использование:
  speedtest internet [--json] [--attempts N]
        Замер интернета (загрузка/отдача/пинг) через Yandex Интернетометр.

  speedtest lan server [--addr :5201]
        Запустить сервер LAN-теста (запускается на другой машине).

  speedtest lan client <host[:port]> [--bytes 100MB] [--json]
        Замер загрузки/отдачи/задержки до сервера LAN-теста.

  speedtest ping <host[:port]> [--count 5] [--port 80] [--timeout 2s]
        Замер задержки TCP-подключения до любого устройства (без агента).

  speedtest trace <host> [--max 30] [--rounds N] [--json]
        Трассировка пути до цели + непрерывный пинг каждого узла: потери и
        задержка по хопам (mtr-style). Работает без прав администратора.

  speedtest httpdl <url|host[:port]> [--duration 10s] [--json]
        Download-тест по HTTP до устройства без агента (качает с его
        HTTP-сервера). Точен только при крупном ответе; upload недоступен.

  speedtest scan <ip> [--ports 1-1024] [--timeout 500ms] [--workers 500]
                      [--banner]
        Скан TCP-портов одного хоста и список открытых. С --banner
        снимает баннер сервиса с каждого открытого порта (версия ПО).

  speedtest discover [--cidr 192.168.1.0/24[,10.0.0.0/24,...]] [--ports 22,80,...]
                     [--timeout 400ms] [--workers 1000] [--all] [--json]
                     [--all-subnets] [--expand [--expand-depth 2] [--snmp-community public]]
        Обзор подсети: проверка живых хостов, затем открытые порты по каждому,
        плюс имя (обратный DNS), MAC и производитель (из таблицы ARP).
        Без --cidr подсеть определяется автоматически; --cidr принимает список
        через запятую.
        --all сканирует все адреса (без проверки на живость).
        --all-subnets обходит все подсети машины (все интерфейсы + маршруты).
        --expand авто-обнаруживает подсети (traceroute + SNMP) и сканирует их
        рекурсивно до --expand-depth хопов; --snmp-community включает опрос
        таблицы маршрутов шлюзов (без него — только traceroute).

  speedtest wifi [--json]
        Обзор Wi-Fi: текущее подключение (SSID, сигнал, канал), сети поблизости
        и совет по наименее загруженному каналу 2.4 ГГц. Трафик отдельных
        клиентов не показывается (нужен режим монитора адаптера).

  speedtest bwmon [--interval 2s] [--count N] [--json]
        Живая пропускная способность интерфейсов ЭТОЙ машины (приём/передача
        по каждому адаптеру). Показывает только собственный трафик хоста.

  speedtest sniff [--iface NAME] [--top 15] [--resolve] [--list] [--json]
        Пассивный топ собеседников по объёму трафика (кто больше «общается»).
        Требует сборки с -tags pcap и установленного Npcap (Windows) / libpcap.
        В коммутируемой сети виден в основном свой трафик + широковещание;
        для полной картины нужен SPAN-порт или режим монитора Wi-Fi.

  speedtest monitor init [--config monitor.yaml]
        Создать пример конфига мониторинга (проверки + получатели алертов).

  speedtest monitor check [--config monitor.yaml]
        Один проход всех проверок из конфига; алерты в stdout/webhook/
        десктоп/историю. Ненулевой код возврата при нарушении порога
        (удобно для cron/CI).

  speedtest monitor run [--config monitor.yaml]
        Непрерывный мониторинг: каждая проверка (ping/portdrift/auditgrade/
        bandwidth) опрашивается по своему интервалу; алерт при превышении
        порога, изменении набора портов или падении оценки. Ctrl-C — стоп.

  speedtest audit <host> [--timeout 8s] [--json] [--export html] [--dns]
        Полный аудит хоста: находит ВСЕ веб-сервисы (80/443/3000/8000/8080/
        9000/... а не только 443) и по каждому — TLS, HTTP-заголовки, открытые
        пути; плюс чувствительные порты (telnet/SMB/RDP/БД). Оценка A–F.
        --export html выводит автономный HTML-отчёт. Прогоны пишутся в history.
        --dns добавляет проверку DNS: открытый резолвер и перенос зоны (AXFR).
        --i-have-authorization включает АКТИВНЫЕ проверки (дефолт-креды,
        незащищённые сервисы Redis/Mongo/FTP, CVE по баннеру) — только для
        систем, которые вам разрешено тестировать.

  speedtest tlsaudit <host[:443]> [--port 443] [--timeout 8s] [--json]
        Аудит TLS: версии протокола (TLS 1.0/1.1 небезопасны), срок и
        доверие сертификата, совпадение имени хоста, слабые подписи.
        Итог — оценка A–F и список находок по важности.

  speedtest httpaudit <url> [--timeout 10s] [--json]
        Аудит HTTP-заголовков безопасности: HSTS, CSP, X-Frame-Options,
        X-Content-Type-Options, Referrer-Policy, флаги cookie и утечка
        версии в Server. Итог — оценка A–F.

  speedtest history [--export csv|json]
        Показать историю замеров (сохраняется автоматически) или выгрузить
        её в CSV/JSON.

Большинство команд принимают --json для машинного вывода.

Общее:
  -h, --help    Показать эту справку.
`

func main() {
	// No arguments -> launch the full-screen TUI dashboard.
	if len(os.Args) < 2 {
		if err := tui.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			os.Exit(1)
		}
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "internet":
		err = speedtest.RunInternet(args)
	case "lan":
		err = lan.Run(args)
	case "ping":
		err = ping.RunPing(args)
	case "trace":
		err = trace.RunTrace(args)
	case "httpdl":
		err = webspeed.RunHTTPDL(args)
	case "scan":
		err = portscan.RunScan(args)
	case "discover":
		err = portscan.RunDiscover(args)
	case "wifi":
		err = wifi.RunWiFi(args)
	case "bwmon":
		err = bwmon.RunBWMon(args)
	case "sniff":
		err = capture.RunSniff(args)
	case "monitor":
		err = monitor.RunMonitor(args)
	case "audit":
		err = audit.RunAudit(args)
	case "tlsaudit":
		err = audit.RunTLSAudit(args)
	case "httpaudit":
		err = audit.RunHTTPAudit(args)
	case "history":
		err = history.RunHistory(args)
	case "menu":
		err = menu.Run()
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n%s", cmd, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}
