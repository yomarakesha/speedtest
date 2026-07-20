package monitor

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// buildProbes turns each CheckSpec into its Probe. Unknown types are skipped
// (validate already rejects them at load time).
func buildProbes(cfg Config) []Probe {
	var probes []Probe
	for _, ch := range cfg.Checks {
		switch ch.Type {
		case "ping":
			probes = append(probes, newPingProbe(ch))
		case "portdrift":
			probes = append(probes, newPortdriftProbe(ch))
		case "auditgrade":
			probes = append(probes, newAuditgradeProbe(ch))
		case "bandwidth":
			probes = append(probes, newBandwidthProbe(ch))
		}
	}
	return probes
}

// RunMonitor is the CLI entry point for `speedtest monitor <check|run>`.
func RunMonitor(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("использование: speedtest monitor <check|run> [--config monitor.yaml]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	configPath := fs.String("config", "monitor.yaml", "путь к YAML-конфигу проверок")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch sub {
	case "check":
		return runCheck(*configPath)
	case "run":
		return runLoop(*configPath)
	case "init":
		return writeSample(*configPath)
	default:
		return fmt.Errorf("неизвестная подкоманда %q (check|run|init)", sub)
	}
}

// loadOrHint loads the config, or returns a friendly error pointing at
// `monitor init` when the file is missing.
func loadOrHint(path string) (Config, error) {
	cfg, err := LoadConfig(path)
	if os.IsNotExist(err) {
		return Config{}, fmt.Errorf("конфиг %s не найден — создайте его командой:\n  speedtest monitor init --config %s", path, path)
	}
	return cfg, err
}

// runCheck does one pass of every check and exits non-zero (via error) if
// anything is currently breaching.
func runCheck(path string) error {
	cfg, err := loadOrHint(path)
	if err != nil {
		return err
	}
	probes := buildProbes(cfg)
	d := NewDispatcher(BuildSinks(cfg.Sinks, os.Stdout)...)

	breached := Check(context.Background(), probes, d)
	if breached {
		return fmt.Errorf("обнаружены нарушения порогов")
	}
	fmt.Println("Все проверки в норме.")
	return nil
}

// runLoop polls every check on its interval until interrupted (Ctrl-C).
func runLoop(path string) error {
	cfg, err := loadOrHint(path)
	if err != nil {
		return err
	}
	probes := buildProbes(cfg)
	d := NewDispatcher(BuildSinks(cfg.Sinks, os.Stdout)...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("Мониторинг запущен: %d проверок. Ctrl-C для остановки.\n", len(probes))
	Run(ctx, probes, d)
	fmt.Println("\nМониторинг остановлен.")
	return nil
}

// writeSample writes the example config, refusing to overwrite an existing file.
func writeSample(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("файл %s уже существует — не перезаписываю", path)
	}
	if err := os.WriteFile(path, []byte(SampleConfig), 0o644); err != nil {
		return err
	}
	fmt.Printf("Создан пример конфига: %s\nОтредактируйте его и запустите: speedtest monitor run --config %s\n", path, path)
	return nil
}
