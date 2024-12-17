package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Santosh-1511/container-scanner/pkg/models"
)

type ScanReport struct {
	ImageName          string    `json:"imageName"`
	ScanTime           time.Time `json:"scanTime"`
	TotalPackages      int       `json:"totalPackages"`
	VulnerablePackages int       `jsin:"vulnerablePackages"`
	Findings           []Finding `json:"findings"`
}

type Finding struct {
	PackageName     string                 `json:"packageName"`
	CurrentVersion  string                 `json:"currentVersion"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
}

type ReportGenerator struct {
	report ScanReport
}

func NewReportGenerator(imageName string) *ReportGenerator {
	return &ReportGenerator{
		report: ScanReport{
			ImageName: imageName,
			ScanTime:  time.Now(),
			Findings:  make([]Finding, 0),
		},
	}
}

func (g *ReportGenerator) AddFinding(pkgName, version string, vulns []models.Vulnerability) {
	if len(vulns) > 0 {
		g.report.Findings = append(g.report.Findings, Finding{
			PackageName:     pkgName,
			CurrentVersion:  version,
			Vulnerabilities: vulns,
		})
	}
}

func (g *ReportGenerator) SetPackageCounts(total int) {
	g.report.TotalPackages = total
	g.report.VulnerablePackages = len(g.report.Findings)
}

func (g *ReportGenerator) SaveJSON(filename string) error {
	data, err := json.MarshalIndent(g.report, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)

	}
	return os.WriteFile(filename, data, 0644)
}

func (g *ReportGenerator) GetSummary() string {
	summary := fmt.Sprintf("\nScan Summary fir %s\n", g.report.ImageName)
	summary += fmt.Sprintf("Scan completed at: %s\n", g.report.ScanTime.Format(time.RFC3339))
	summary += fmt.Sprintf("Total packages found: %d\n", g.report.TotalPackages)
	summary += fmt.Sprintf("Vulnerable packages found: %d\n\n", g.report.VulnerablePackages)

	if len(g.report.Findings) > 0 {
		summary += "Vulnerable Packages:\n"
		for _, finding := range g.report.Findings {
			summary += fmt.Sprintf("\n %s (version %s)\n", finding.PackageName, finding.CurrentVersion)
			for _, vuln := range finding.Vulnerabilities {
				summary += fmt.Sprintf("%s (%s)\n", vuln.ID, vuln.Severity)
				summary += fmt.Sprintf("Description: %s\n", vuln.Description)
				summary += fmt.Sprintf("Fixed in: %s\n", vuln.FixedIn)
			}
		}
	} else {
		summary += "No vulnerabilities dound!\n"
	}

	return summary
}
