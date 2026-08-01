package main

import (
	"embed"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"example.com/guardian/guardian"
	plugin "example.com/guardian/mod/zoraxy_plugin"
)

const (
	PluginID              = "com.guardian.zoraxy"
	UIPath                = "/ui"
	DynamicSniffIngress   = "/d_sniff"
	DynamicCaptureIngress = "/d_capture"
	ConfigPath            = "config.json"
	BlockLogPath          = "blocklog.jsonl"
)

//go:embed www/*
var content embed.FS

func main() {
	runtime, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            PluginID,
		Name:          "Guardian",
		Author:        "6unsatiable",
		AuthorContact: "articrevised@gmail.com",
		Description:   "Dynamic-capture security plugin: IP allow/block lists, UA blocklist, WAF payload patterns, per-IP rate limiting. Host-scopable rules.",
		URL:           "https://github.com/6unsatiable/zoraxy-guardian",
		Type:          plugin.PluginType_Router,
		VersionMajor:  0,
		VersionMinor:  2,
		VersionPatch:  2,

		DynamicCaptureSniff:   DynamicSniffIngress,
		DynamicCaptureIngress: DynamicCaptureIngress,
		UIPath:                UIPath,

		SubscriptionPath:    guardian.SubscriptionPath,
		SubscriptionsEvents: guardian.EventDescriptors,
	})
	if err != nil {
		panic(err)
	}

	store, err := guardian.LoadState(ConfigPath, BlockLogPath)
	if err != nil {
		panic(err)
	}

	router := plugin.NewPathRouter()
	router.SetDebugPrintMode(false)

	router.RegisterDynamicSniffHandler(DynamicSniffIngress, http.DefaultServeMux, func(req *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
		decision := store.Evaluate(req)
		if decision.Block {
			store.RecordDecision(req.GetRequestUUID(), decision)
			store.LogBlock(req, decision)
			return plugin.SniffResultAccept
		}
		return plugin.SniffResultSkip
	})

	router.RegisterDynamicCaptureHandle(DynamicCaptureIngress, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		uuid := r.Header.Get("X-Zoraxy-RequestID")
		decision, ok := store.TakeDecision(uuid)
		if !ok {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		guardian.WriteBlockResponse(w, decision)
	})

	store.RegisterEventRoutes(http.DefaultServeMux)

	ui := plugin.NewPluginEmbedUIRouter(PluginID, &content, "/www", UIPath)
	ui.RegisterTerminateHandler(func() {
		_ = store.Save()
		fmt.Println("Guardian: shutting down")
	}, nil)

	api := guardian.NewAPI(store)
	api.RegisterRoutes(ui, http.DefaultServeMux)

	http.Handle(UIPath+"/", ui.Handler())

	addr := "127.0.0.1:" + strconv.Itoa(runtime.Port)
	fmt.Println("Guardian listening on", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
