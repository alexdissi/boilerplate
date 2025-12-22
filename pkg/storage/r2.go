package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	AccountID       string `json:"account_id"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	BucketName      string `json:"bucket_name"`
	Endpoint        string `json:"endpoint"`
}

type r2Storage struct {
	client *s3.Client
	bucket string
}

type R2Config struct {
	AccountID       string `json:"account_id"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	BucketName      string `json:"bucket_name"`
	Endpoint        string `json:"endpoint"`
}

func (c *R2Config) Validate() error {
	if c.AccountID == "" || c.AccessKeyID == "" || c.AccessKeySecret == "" || c.BucketName == "" || c.Endpoint == "" {
		return fmt.Errorf("missing required R2 configuration")
	}
	return nil
}

func NewR2Storage(config R2Config) (Storage, error) {
	if config.AccountID == "" || config.AccessKeyID == "" || config.AccessKeySecret == "" || config.BucketName == "" || config.Endpoint == "" {
		return nil, fmt.Errorf("missing required R2 configuration")
	}

	cfg, err := awsConfig.LoadDefaultConfig(context.TODO(),
		awsConfig.WithRegion("auto"),
		awsConfig.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     config.AccessKeyID,
				SecretAccessKey: config.AccessKeySecret,
			}, nil
		})),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(config.Endpoint)
	})

	return &r2Storage{
		client: client,
		bucket: config.BucketName,
	}, nil
}

func (c *r2Storage) Download(ctx context.Context, objectKey string) (io.ReadCloser, error) {
	if objectKey == "" {
		return nil, fmt.Errorf("object key cannot be empty")
	}

	result, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object: %w", err)
	}

	return result.Body, nil
}

func (c *r2Storage) Delete(ctx context.Context, objectKey string) error {
	if objectKey == "" {
		return fmt.Errorf("object key cannot be empty")
	}

	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}

	return nil
}
