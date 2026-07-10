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
	"speedtest/internal/history"
	"speedtest/internal/lan"
	"speedtest/internal/menu"
	"speedtest/internal/ping"
	"speedtest/internal/portscan"
	"speedtest/internal/speedtest"
	"speedtest/internal/trace"
	"speedtest/internal/tui"
	"speedtest/internal/webspeed"
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
        Скан TCP-портов одного хоста и список открытых.

  speedtest discover [--cidr 192.168.1.0/24] [--ports 22,80,443,...]
                     [--timeout 400ms] [--workers 1000] [--all] [--json]
        Обзор подсети: проверка живых хостов, затем открытые порты по каждому,
        плюс имя (обратный DNS), MAC и производитель (из таблицы ARP).
        Без --cidr подсеть определяется автоматически.
        --all сканирует все адреса (без проверки на живость).

  speedtest tlsaudit <host[:443]> [--port 443] [--timeout 8s] [--json]
        Аудит TLS: версии протокола (TLS 1.0/1.1 небезопасны), срок и
        доверие сертификата, совпадение имени хоста, слабые подписи.
        Итог — оценка A–F и список находок по важности.

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
	case "tlsaudit":
		err = audit.RunTLSAudit(args)
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
