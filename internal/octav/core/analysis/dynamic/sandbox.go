package dynamic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OctAVProject/OctAV/internal/octav/core/analysis"
	"github.com/OctAVProject/OctAV/internal/octav/logger"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"mime/multipart"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func IsSandBoxUp() (bool, error) {

	cli, err := client.NewClientWithOpts(client.WithAPIVersionNegotiation())
	if err != nil {
		return false, err
	}

	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return false, err
	}

	var lisaContainersUp [5]bool // nginx, api, worker, mariadb, rabbitmq

	for _, c := range containers {
		if strings.Contains(c.Names[0], "lisa_nginx") {
			lisaContainersUp[0] = true
		} else if strings.Contains(c.Names[0], "lisa_api") {
			lisaContainersUp[1] = true
		} else if strings.Contains(c.Names[0], "lisa_worker") {
			lisaContainersUp[2] = true
		} else if strings.Contains(c.Names[0], "lisa_mariadb") {
			lisaContainersUp[3] = true
		} else if strings.Contains(c.Names[0], "lisa_rabbitmq") {
			lisaContainersUp[4] = true
		}
	}

	for _, isup := range lisaContainersUp {
		if !isup {
			return false, nil
		}
	}

	return true, nil
}

func StartSandBox() error {

	// Makes sure changes to LiSa's config are applied
	logger.Debug("Building docker images...")
	cmd := exec.Command("docker-compose", "-f", "files/LiSa/docker-compose.yml", "build")

	if err := cmd.Run(); err != nil {
		return err
	}

	logger.Debug("Sandbox built !")

	cmd = exec.Command("docker-compose", "-f", "files/LiSa/docker-compose.yml", "up", "-d")

	if err := cmd.Run(); err != nil {
		return err
	}

	logger.Info("The sandbox is up !")
	return nil
}

func SendFileToSandBox(exe *analysis.Executable) (map[string]interface{}, error) {
	var requestBody bytes.Buffer

	writer := multipart.NewWriter(&requestBody)

	fieldWriter, err := writer.CreateFormFile("file", filepath.Base(exe.Filename))
	if err != nil {
		return nil, err
	}

	_, err = fieldWriter.Write(exe.Content)
	if err != nil {
		return nil, err
	}

	fieldWriter, err = writer.CreateFormField("exec_time")
	if err != nil {
		return nil, err
	}

	_, err = fieldWriter.Write([]byte("10"))
	if err != nil {
		return nil, err
	}

	writer.Close()

	request, err := http.NewRequest("POST", "http://localhost:4242/api/tasks/create/file", &requestBody)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())

	httpClient := &http.Client{}
	resp, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("create file request returned code %v", resp.StatusCode))
	}

	var jsonResponse map[string]interface{}
	var taskID string

	if resp.StatusCode == http.StatusOK {
		logger.Debug("Binary has been submitted to the LiSa Sandbox")

		if json.NewDecoder(resp.Body).Decode(&jsonResponse) != nil {
			return nil, err
		}

		taskID = jsonResponse["task_id"].(string)
	}

	logger.Debug(fmt.Sprintf("LiSa Task ID: %v", taskID))

	for {
		resp, err = http.Get(fmt.Sprintf("http://localhost:4242/api/report/%v", taskID))
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			break
		}

		logger.Debug("Waiting for the report...")

		resp.Body.Close()
		time.Sleep(2 * time.Second)
	}

	logger.Debug("Report ready !")
	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		return nil, err
	}

	return jsonResponse, nil
}
