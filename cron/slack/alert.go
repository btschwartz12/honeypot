package slack

import (
	"context"
	"time"

	"go.uber.org/zap"
)

func SendAlert(webhookUrl string, logger *zap.SugaredLogger, title string, blocks []Block) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		errChan := make(chan error, 1)

		err := sendToSlack(webhookUrl, title, blocks)
		errChan <- err

		select {
		case err := <-errChan:
			if err != nil {
				logger.Errorw("failed to send message to Slack", "error", err, "blocks", blocks)
			} else {
				logger.Infow("sent message to slack")
			}
		case <-ctx.Done():
			logger.Errorw("timed out sending message to slack", "error", ctx.Err())
		}
	}()
}
