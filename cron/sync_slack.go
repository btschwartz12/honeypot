package cron

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btschwartz12/honeypot/cron/slack"
	"github.com/btschwartz12/honeypot/repo"
	"github.com/samber/mo"
	"go.uber.org/zap"
)

func SyncSlack(slackWebhook string, logger *zap.SugaredLogger, rpo *repo.Repo) {
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-ticker.C:
			go func() {
				ctx := context.Background()
				lastUpdate, err := rpo.GetLastSlackUpdate(ctx)
				if err != nil {
					if !errors.Is(err, sql.ErrNoRows) {
						logger.Errorw("failed to get last slack update", "error", err)
						return
					}
				}
				sessions, err := rpo.GetSessions(ctx, &repo.GetSessionsFilter{
					StartTimeGt:     mo.Some(lastUpdate),
					SuccessfulLogin: mo.Some(true),
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						logger.Infow("no new sessions")
						return
					}
					logger.Errorw("failed to get sessions", "error", err)
					return
				}
				for _, session := range sessions {
					alreadySynced, err := rpo.AlreadySyncedInSlack(ctx, session.ID)
					if err != nil {
						logger.Errorw("failed to check if already synced", "error", err)
						continue
					}
					if alreadySynced {
						continue
					}
					blocks, err := getBlocksForSession(&session)
					if err != nil {
						logger.Errorw("failed to get blocks for session", "error", err)
						continue
					}
					slack.SendAlert(slackWebhook, logger, "successful login ✅", blocks)
				}
				// the first of the session is the earliest
				if len(sessions) > 0 {
					lastUpdate = sessions[len(sessions)-1].StartTime.Time
					_, err := rpo.UpdateLastSlackUpdate(ctx, lastUpdate)
					if err != nil {
						logger.Errorw("failed to update last slack update", "error", err)
						return
					}
				}
				if len(sessions) > 0 {
					logger.Infow("synced slack", "numSynced", len(sessions))
				}
			}()
		}
	}
}

func getBlocksForSession(session *repo.Session) ([]slack.Block, error) {
	blocks := []slack.Block{
		{
			Type: "header",
			Text: &slack.Element{
				Type:  "plain_text",
				Text:  "successful login ✅",
				Emoji: true,
			},
		},
		{
			Type: "context",
			Elements: []slack.Element{
				{
					Type: "mrkdwn",
					Text: session.StartTime.In(repo.EstTimezone).Format("Monday, January 2 2006, 15:04:05.000 EST"),
				},
			},
		},
		{
			Type: "context",
			Elements: []slack.Element{
				{
					Type: "mrkdwn",
					Text: fmt.Sprintf("session_id: %s", session.ID),
				},
				{
					Type: "mrkdwn",
					Text: fmt.Sprintf("ip: %s", session.Ip),
				},
			},
		},
	}
	loginBlock := slack.Block{
		Type:     "context",
		Elements: []slack.Element{},
	}
	for _, auth := range session.Auths {
		if !auth.Success {
			loginBlock.Elements = append(loginBlock.Elements, slack.Element{
				Type: "mrkdwn",
				Text: fmt.Sprintf("failed credentials: `%s:%s`\n", auth.Username, auth.Password),
			})

		} else {
			loginBlock.Elements = append(loginBlock.Elements, slack.Element{
				Type: "mrkdwn",
				Text: fmt.Sprintf("successful credentials: `%s:%s`\n", auth.Username, auth.Password),
			})
		}
	}
	blocks = append(blocks, loginBlock)
	return blocks, nil
}
