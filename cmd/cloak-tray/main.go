// cloak-tray is a menu bar / system tray app that toggles redaction on an
// already-running cloak instance. It doesn't manage cloak's process
// lifecycle at all - that's `cloak service install`'s job - it's purely a
// thin GUI client on top of the same control API that `cloak toggle`
// drives from the terminal, so the two can never fall out of sync.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"fyne.io/systray"
)

var listenAddr = flag.String("listen", "127.0.0.1:8787", "address cloak serve is listening on")

func main() {
	flag.Parse()
	systray.Run(onReady, func() {})
}

type status struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
}

func onReady() {
	systray.SetTitle("cloak: checking...")
	systray.SetTooltip("cloak - secrets/PII firewall for AI coding agents")

	statusItem := systray.AddMenuItem("Checking status...", "")
	statusItem.Disable()
	systray.AddSeparator()
	toggleItem := systray.AddMenuItem("Toggle protection", "Enable or disable redaction")
	quitItem := systray.AddMenuItem("Quit cloak-tray", "Quits this tray icon only - cloak serve keeps running")

	refreshStatus(statusItem)
	go pollLoop(statusItem)

	for {
		select {
		case <-toggleItem.ClickedCh:
			callControl("toggle")
			refreshStatus(statusItem)
		case <-quitItem.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func pollLoop(item *systray.MenuItem) {
	for {
		time.Sleep(3 * time.Second)
		refreshStatus(item)
	}
}

func refreshStatus(item *systray.MenuItem) {
	st, err := fetchStatus()
	switch {
	case err != nil:
		systray.SetTitle("cloak ⚠") // warning sign
		item.SetTitle("cloak not reachable - is `cloak serve` running?")
	case st.Enabled:
		systray.SetTitle("cloak \U0001F6E1") // shield
		item.SetTitle(fmt.Sprintf("Protection: ON (%s)", st.Provider))
	default:
		systray.SetTitle("cloak ⏸") // pause
		item.SetTitle(fmt.Sprintf("Protection: OFF (%s)", st.Provider))
	}
}

func fetchStatus() (status, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s/__cloak__/status", *listenAddr))
	if err != nil {
		return status{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return status{}, err
	}
	var st status
	if err := json.Unmarshal(body, &st); err != nil {
		return status{}, err
	}
	return st, nil
}

func callControl(action string) {
	url := fmt.Sprintf("http://%s/__cloak__/%s", *listenAddr, action)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
