// Package menu provides an interactive text menu shown when speedtest is
// launched with no arguments. It gathers parameters, then calls the same
// command entrypoints the flags-based CLI uses.
package menu

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"speedtest/internal/lan"
	"speedtest/internal/ping"
	"speedtest/internal/portscan"
	"speedtest/internal/speedtest"
	"speedtest/internal/webspeed"
)

const banner = `
  ███ speedtest — сетевой инструмент
  ────────────────────────────────`

const menu = `
  1) Скорость интернета          (загрузка / отдача / пинг)
  2) Скорость по локалке - клиент (замер до другой машины, нужен сервер)
  3) Скорость по локалке - сервер (запустить здесь, к вам подключаются)
  4) HTTP-download до устройства  (по адресу, без агента на цели)
  5) Пинг любого устройства       (любой IP, без агента)
  6) Скан портов - один IP        (какие порты открыты)
  7) Скан сети (IP + порты) - все хосты локалки и их открытые порты
  8) Справка
  0) Выход
`

var in = bufio.NewScanner(os.Stdin)

// Run shows the interactive loop until the user exits.
func Run() error {
	fmt.Println(banner)
	for {
		fmt.Print(menu)
		choice, ok := prompt("Выбор", "")
		if !ok { // stdin closed / EOF
			fmt.Println("\nПока.")
			return nil
		}
		if choice == "" {
			continue
		}
		fmt.Println()

		var err error
		switch choice {
		case "1":
			err = speedtest.RunInternet(nil)
		case "2":
			err = lanClient()
		case "3":
			err = lanServer()
		case "4":
			err = httpDL()
		case "5":
			err = pingHost()
		case "6":
			err = scan()
		case "7":
			err = discover()
		case "8":
			printHelp()
		case "0", "q", "quit", "exit", "выход":
			fmt.Println("Пока.")
			return nil
		default:
			fmt.Printf("Неизвестный пункт %q\n", choice)
			continue
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
		}
		pause()
	}
}

func lanClient() error {
	host, _ := prompt("IP сервера (на нём должен идти 'speedtest lan server')", "")
	if host == "" {
		return fmt.Errorf("нужен адрес хоста")
	}
	bytes, _ := prompt("Объём в каждую сторону (напр. 100MB, 1GB)", "100MB")
	return lan.Run([]string{"client", host, "--bytes", bytes})
}

func lanServer() error {
	addr, _ := prompt("Адрес прослушивания", ":5201")
	fmt.Println("Запуск сервера. Ctrl+C — остановить.")
	return lan.Run([]string{"server", "--addr", addr})
}

func httpDL() error {
	addr, _ := prompt("Адрес (напр. http://192.168.1.10:8080/big.iso или 192.168.1.10)", "")
	if addr == "" {
		return fmt.Errorf("нужен адрес")
	}
	return webspeed.RunHTTPDL([]string{addr})
}

func pingHost() error {
	host, _ := prompt("Хост/IP цели", "")
	if host == "" {
		return fmt.Errorf("нужен адрес хоста")
	}
	port, _ := prompt("Порт для проверки", "80")
	count, _ := prompt("Число попыток", "5")
	return ping.RunPing([]string{host, "--port", port, "--count", count})
}

func scan() error {
	ip, _ := prompt("IP цели", "")
	if ip == "" {
		return fmt.Errorf("нужен IP")
	}
	ports, _ := prompt("Порты (напр. 22,80,443 или 1-1024)", "1-1024")
	return portscan.RunScan([]string{ip, "--ports", ports})
}

func discover() error {
	cidr, _ := prompt("Подсеть CIDR (пусто = авто)", "")
	ports, _ := prompt("Порты (пусто = частые сервисы)", "")
	args := []string{}
	if cidr != "" {
		args = append(args, "--cidr", cidr)
	}
	if ports != "" {
		args = append(args, "--ports", ports)
	}
	return portscan.RunDiscover(args)
}

func printHelp() {
	fmt.Print(`
  Интернет   Меряет ваш канал в интернет через узлы Yandex CDN.
  Локалка-клиент  Подключается к "серверу локалки" на другой машине и
             гоняет TCP-данные в обе стороны.
  Локалка-сервер  Сначала запустите его на целевой машине, затем с другой
             машины запустите клиент, указав IP этой машины.
  HTTP-download  Качает с HTTP-сервера цели по адресу (протокол/хост/порт/путь)
             и меряет download. БЕЗ агента на цели, но точно только при
             крупном ответе; upload и полный throughput так не измерить.
  Пинг       Задержка TCP-подключения до ЛЮБОГО устройства (мин/сред/макс,
             потери). На цели ничего ставить не нужно — в отличие от локалки.
  Скан портов  TCP-скан одного хоста; показывает принимающие порты.
  Скан сети  Находит все IP-адреса подсети (Wi-Fi или Ethernet) и показывает
             открытые порты, имя, MAC и производителя по каждому хосту.

  Совет: команды можно запускать напрямую, напр.:
       speedtest internet
       speedtest scan 192.168.1.1 --ports 1-65535
       speedtest discover --cidr 192.168.1.0/24
`)
}

// prompt prints "label [def]: " and returns (value, ok). ok is false when
// stdin is closed (EOF), so callers can stop instead of looping forever.
// An empty entry yields def.
func prompt(label, def string) (string, bool) {
	if def != "" {
		fmt.Printf("  %s [%s]: ", label, def)
	} else {
		fmt.Printf("  %s: ", label)
	}
	if !in.Scan() {
		return def, false
	}
	// Strip a leading UTF-8 BOM (piped input on Windows often prepends one).
	v := strings.TrimPrefix(in.Text(), string(rune(0xFEFF)))
	v = strings.TrimSpace(v)
	if v == "" {
		return def, true
	}
	return v, true
}

func pause() {
	fmt.Print("\n  -- Enter — вернуться в меню --")
	in.Scan()
	fmt.Println()
}
