package integration

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/testcontainers/testcontainers-go"
)

type testContainer struct {
	testcontainers.Container
	URI string
}

func setupTestContainer(ctx context.Context, testContainerName string, reusableContainerName string) (*testContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:      testContainerName,
		Name:       reusableContainerName,
		SkipReaper: true,
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Reuse:            true,
	})
	if err != nil {
		return nil, err
	}

	log.Infof("Successfully setup %v image", testContainerName)

	return &testContainer{Container: container}, nil
}
