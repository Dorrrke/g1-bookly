package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Dorrrke/g1-bookly/internal/config"
	"github.com/Dorrrke/g1-bookly/internal/logger"
	"github.com/Dorrrke/g1-bookly/internal/repository"
	"github.com/Dorrrke/g1-bookly/internal/server"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

		<-c
		cancel()
	}()
	cfg := config.ReadConfig()
	zlog := logger.SetupLogger(cfg.DebugFlag)
	zlog.Info().Msg("Start server")
	zlog.Debug().Any("config", cfg).Msg("Check cfg value")

	err := repository.Migrations(cfg.DBAddr, cfg.MPath, zlog)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Init migrations failed")
	}
	conn, err := initDB(cfg.DBAddr)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Connections db failed")
	}
	storage, err := repository.NewDB(conn)
	if err != nil {
		panic(err)
	}
	if err = storage.CheckDBConnect(context.Background()); err != nil {
		panic(err)
	}
	group, gCtx := errgroup.WithContext(ctx)
	srv := server.New(gCtx, &storage, zlog)
	group.Go(func() error {
		router := gin.Default()
		router.GET("/getusers", srv.GetUsersHandler)
		router.POST("/register", srv.RegisterHandler)
		router.POST("/login", srv.LoginHandler)
		router.POST("/addbook", srv.AddBook)
		router.GET("/allbooks", srv.GetAllBooks)
		router.GET("/userbooks", srv.GetBooksByUser)
		router.POST("/addbooks", srv.AddBooks)
		router.DELETE("/deletebook/:id", srv.DeleteBook)

		zlog.Debug().Msg("Server started")
		if err = router.Run(cfg.Addr); err != nil {
			return err
		}
		return nil
	})

	group.Go(func() error {
		err = <-srv.ErrorChan
		return err
	})
	group.Go(func() error {
		<-gCtx.Done()
		return gCtx.Err()
	})

	if err = group.Wait(); err != nil {
		panic(err)
	}
}

func initDB(addr string) (*pgx.Conn, error) {
	for i := 0; i < 7; i++ {
		time.Sleep(time.Second + time.Second)
		conn, err := pgx.Connect(context.Background(), addr)
		if err == nil {
			return conn, nil
		}
	}
	conn, err := pgx.Connect(context.Background(), addr)
	if err != nil {
		return nil, fmt.Errorf("database initialization error: %w", err)
	}
	return conn, nil
}
