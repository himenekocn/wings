package router

import (
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/pterodactyl/wings/router/downloader"
	"github.com/pterodactyl/wings/router/middleware"
	"github.com/pterodactyl/wings/router/tokens"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// handleDownloadProgressWebSocket handles WebSocket connections for download progress tracking
func handleDownloadProgressWebSocket(c *gin.Context) {
	manager := middleware.ExtractManager(c)

	// Parse the token to get server UUID
	token := tokens.FilePayload{}
	if err := tokens.ParseToken([]byte(c.Query("token")), &token); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Verify server exists
	s, ok := manager.Get(token.ServerUuid)
	if !ok {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "Server not found",
		})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.WithError(err).Error("failed to upgrade websocket connection")
		return
	}
	defer conn.Close()

	// Get download ID from query parameter
	downloadID := c.Query("download_id")
	if downloadID == "" {
		// If no download_id provided, send all active downloads for this server
		downloads := downloader.ByServer(s.ID())
		for _, dl := range downloads {
			progress := downloader.GetProgress(dl.Identifier)
			if progress != nil {
				if err := conn.WriteJSON(progress); err != nil {
					log.WithError(err).Debug("failed to write progress update")
					return
				}
			}
		}
		return
	}

	// Subscribe to progress updates for specific download
	progressChan := downloader.Subscribe(downloadID)
	if progressChan == nil {
		conn.WriteJSON(gin.H{
			"error": "Download not found",
		})
		return
	}

	// Send initial progress if available
	if progress := downloader.GetProgress(downloadID); progress != nil {
		if err := conn.WriteJSON(progress); err != nil {
			log.WithError(err).Debug("failed to write initial progress")
			return
		}
	}

	// Listen for progress updates
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	done := make(chan struct{})
	defer close(done)

	// Handle incoming messages (ping/pong)
	go func() {
		defer func() {
			downloader.Unsubscribe(downloadID, progressChan)
		}()

		for {
			select {
			case <-done:
				return
			default:
				_, msg, err := conn.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						log.WithError(err).Debug("websocket error")
					}
					return
				}

				// Handle ping message
				if string(msg) == "ping" {
					if err := conn.WriteMessage(websocket.TextMessage, []byte("pong")); err != nil {
						return
					}
				}
			}
		}
	}()

	// Send progress updates
	for {
		select {
		case progress, ok := <-progressChan:
			if !ok {
				return
			}
			if err := conn.WriteJSON(progress); err != nil {
				log.WithError(err).Debug("failed to write progress update")
				return
			}
		case <-ticker.C:
			// Send ping to keep connection alive
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.WithError(err).Debug("failed to send ping")
				return
			}
		}
	}
}
