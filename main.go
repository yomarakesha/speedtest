// Command speedtest is a CLI network toolkit:
//   - internet: measure internet speed via the Yandex Internetometer API
//   - lan:      measure throughput to another host on the local network
//   - scan:     scan TCP ports on a single IP
//   - discover: sweep a subnet and report which hosts have which ports open
package main

import (
	"fmt"
	"os"

	"speedtest/internal/bloat"
	"speedtest/internal/dnsbench"
	"speedtest/internal/dnssec"
	"speedtest/internal/history"
	"speedtest/internal/httphdr"
	"speedtest/internal/lan"
	"speedtest/internal/menu"
	"speedtest/internal/netinfo"
	"speedtest/internal/ping"
	"speedtest/internal/portscan"
	"speedtest/internal/speedtest"
	"speedtest/internal/timing"
	"speedtest/internal/tlsaudit"
	"speedtest/internal/tlsinfo"
	"speedtest/internal/trace"
	"speedtest/internal/tui"
	"speedtest/internal/webspeed"
	"speedtest/internal/wol"
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

  speedtest wol <mac> [--ip 255.255.255.255] [--port 9]
        Разбудить устройство по сети (Wake-on-LAN): отправить magic-пакет
        на MAC-адрес по UDP-broadcast.

  speedtest tls <host[:port]> [--timeout 5s] [--json]
        Разбор TLS-сертификата: издатель, субъект, срок действия, версия
        TLS, набор шифров, SAN-имена, время рукопожатия.

  speedtest timing <url> [--timeout 10s] [--json]
        Разбивка времени HTTP-запроса по этапам: DNS, TCP-подключение,
        TLS handshake, время до первого байта, итог.

  speedtest info [--json]
        Внешний IP и провайдер, локальные интерфейсы (IP/MAC), шлюз по
        умолчанию, DNS-серверы системы, поддержка IPv6.

  speedtest dns [--domains d1,d2,...] [--servers label=ip,...] [--json]
        Сравнить скорость ответа нескольких DNS-резолверов (системный,
        1.1.1.1, 8.8.8.8, 9.9.9.9, 77.88.8.8, AdGuard, OpenDNS) на наборе
        доменов.

  speedtest bloat <host> [--download-host H] [--duration 10s] [--json]
        Bufferbloat-тест: задержка в покое и под одновременной
        HTTP-закачкой, прирост задержки и оценка A-F.

  speedtest scan <ip> [--ports 1-1024] [--timeout 500ms] [--workers 500]
        Скан TCP-портов одного хоста и список открытых.

  speedtest discover [--cidr 192.168.1.0/24] [--ports 22,80,443,...]
                     [--timeout 400ms] [--workers 1000] [--all] [--json]
        Обзор подсети: проверка живых хостов, затем открытые порты по каждому,
        плюс имя (обратный DNS), MAC и производитель (из таблицы ARP).
        Без --cidr подсеть определяется автоматически.
        --all сканирует все адреса (без проверки на живость).

  speedtest headers <url> [--timeout 10s] [--json] [--wazuh]
        Аудит HTTP-заголовков безопасности (HSTS, CSP, X-Frame-Options,
        X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie)
        с оценкой A-F. --wazuh пишет находку в лог для Wazuh.

  speedtest dnssec <domain> [--timeout 8s] [--json] [--wazuh]
        Аудит DNS-безопасности домена: SPF, DMARC, DKIM, DNSSEC, CAA и
        проверка разрешённой передачи зоны (AXFR) на NS-серверах.

  speedtest tlsaudit <host[:port]> [--timeout 6s] [--json] [--wazuh]
        Глубокий TLS-аудит: поддерживаемые версии (с пометкой устаревших
        TLS 1.0/1.1), слабые шифры, срок/самоподпись/слабая подпись
        сертификата, оценка A-F.

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
	case "wol":
		err = wol.RunWOL(args)
	case "tls":
		err = tlsinfo.RunTLS(args)
	case "timing":
		err = timing.RunTiming(args)
	case "info":
		err = netinfo.RunInfo(args)
	case "dns":
		err = dnsbench.RunDNS(args)
	case "bloat":
		err = bloat.RunBloat(args)
	case "scan":
		err = portscan.RunScan(args)
	case "discover":
		err = portscan.RunDiscover(args)
	case "history":
		err = history.RunHistory(args)
	case "headers":
		err = httphdr.RunHeaders(args)
	case "dnssec":
		err = dnssec.RunDNSSEC(args)
	case "tlsaudit":
		err = tlsaudit.RunTLSAudit(args)
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
