package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Santosh-1511/container-scanner/internal/analyzer"
	"github.com/Santosh-1511/container-scanner/internal/docker"
	"github.com/Santosh-1511/container-scanner/internal/report"
	"github.com/Santosh-1511/container-scanner/pkg/models"
)

// parsing a package string into name and version
func parsePackageString(pkgStr string) models.Package {
	parts := strings.Split(pkgStr, " ")
	if len(parts) >= 2 {
		return models.Package{
			Name:    parts[0],
			Version: parts[1],
		}
	}
	return models.Package{
		Name:    parts[0],
		Version: parts[1],
	}
}

func main() {
	ctx := context.Background()

	//creating a new Docker Client
	dockerClient, err := docker.NewDockerClient()
	if err != nil {
		log.Fatalf("Failed to create Docker client: %v", err)
	}

	//checking for image name

	if len(os.Args) < 2 {
		log.Fatalf("Please provide an image name. Example: go run main.go ubuntu:latest")
	}

	imageName := os.Args[1]

	//initializing report generator
	reportGen := report.NewReportGenerator(imageName)

	//pulling image
	log.Printf("Pulling image: %s", imageName)
	if err := dockerClient.PullImage(ctx, imageName); err != nil {
		log.Fatalf("Failed to pull image: %v", err)
	}
	// getting image info
	imageInfo, err := dockerClient.GetImageInfo(ctx, imageName)
	if err != nil {
		log.Fatalf("Failed to get image info: %v", err)

	}

	fmt.Printf("\nImage Details:\n")
	fmt.Printf("ID: %s\n", imageInfo.ID)
	fmt.Printf("Created: %s\n", imageInfo.Created)
	fmt.Printf("Size: %.2f MB\n", float64(imageInfo.Size)/1024/1024)

	// Creating Vulnerability DB
	vulnDB := analyzer.NewSimpleVulnDB()

	// List packages
	log.Println("\nListing Packages...\nScanning Packages for vulnerabilities...")
	packages, err := dockerClient.ListPackages(ctx, imageName)
	if err != nil {
		log.Fatalf("Failed to list packages: %v", err)
	}
	// scanning each package for vulnerabilitiies
	for _, pkgStr := range packages {
		pkg := parsePackageString(pkgStr)
		vulns, err := vulnDB.CheckPackage(ctx, pkg)
		if err != nil {
			log.Printf("Error checking package %s: %v", pkg.Name, err)
			continue
		}
		if len(vulns) > 0 {
			reportGen.AddFinding(pkg.Name, pkg.Version, vulns)
		}
	}

	// total package count
	reportGen.SetPackageCounts(len(packages))

	//printing summary to console
	fmt.Println(reportGen.GetSummary())

	// Saving Json report
	reportFile := fmt.Sprintf("scan-report-%s.json", time.Now().Format("20060102-150405"))
	if err := reportGen.SaveJSON(reportFile); err != nil {
		log.Printf("Warning: Failed to save Json report: %v", err)
	} else {
		fmt.Printf("\nDetailed report saved to: %s\n", reportFile)
	}
}
