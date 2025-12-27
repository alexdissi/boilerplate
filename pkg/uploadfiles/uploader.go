package uploadfiles

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Uploader struct {
	client *s3.Client
	bucket string
}

type Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	Region          string
}

func NewUploader(cfg Config) (*Uploader, error) {
	creds := credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")
	cfgAWS, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(creds),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfgAWS, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
	})

	return &Uploader{
		client: client,
		bucket: cfg.BucketName,
	}, nil
}

func (u *Uploader) Upload(ctx context.Context, file multipart.File, header *multipart.FileHeader, folder string) (string, error) {
	const maxFileSize = 3 * 1024 * 1024
	if header.Size > maxFileSize {
		return "", fmt.Errorf("file size exceeds 3MB limit")
	}

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		_, err := io.Copy(pw, file)
		if err != nil {
			pw.CloseWithError(err)
		}
	}()

	ext := filepath.Ext(header.Filename)
	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("%s/%d%s", folder, timestamp, ext)

	_, err := u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(filename),
		Body:        pr,
		ContentType: aws.String(header.Header.Get("Content-Type")),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload file: %w", err)
	}

	publicURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(*u.client.Options().BaseEndpoint, "/"), filename)

	return publicURL, nil
}

func (u *Uploader) Delete(ctx context.Context, fileURL string) error {
	parts := strings.Split(fileURL, "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid file URL")
	}

	key := strings.Join(parts[len(parts)-2:], "/")

	_, err := u.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}
