package services

import (
	"errors"
	"io"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

func SaveFile(file *multipart.FileHeader) (string, error) {
	if file == nil {
		return "", errors.New("No file to save.")
	}

	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	ext := filepath.Ext(file.Filename)
	filename := strings.TrimSuffix(file.Filename, ext) + uuid.NewString() + ext
	filepath := filepath.Join(os.Getenv("STATIC_DIR"), filename)
	dst, err := os.Create(filepath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err = io.Copy(dst, src); err != nil {
		return "", err
	}

	fileurl, err := url.JoinPath(os.Getenv("STATIC_PATH"), filename)
	if err != nil {
		return "", err
	}

	return fileurl, nil

}
