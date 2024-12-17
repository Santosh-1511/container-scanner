package analyzer

import (
	"context"

	"github.com/Santosh-1511/container-scanner/pkg/models"
)

// Interface for vulnerability checking
type VulnerabilityDatabase interface {
	//check if a package has known vulnerabilities
	CheckPackage(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error)

	//Updating the vulnerability database
	UpdateDatabase(ctx context.Context) error
}

// implementing a simple in-memory vulnerability database
type SimpleVulnDB struct {
	vulns map[string][]models.Vulnerability //map[Packagename][]Vulnerability
}

// crating new simple vulnerability database
func NewSimpleVulnDB() VulnerabilityDatabase {
	db := &SimpleVulnDB{
		vulns: make(map[string][]models.Vulnerability),
	}

	//initializing with sample vulnerabilities
	db.vulns["openssl"] = []models.Vulnerability{
		{
			ID:          "CVE-2023-0001",
			Package:     "openssl",
			Version:     "1.1.1",
			FixedIn:     "1.1.2",
			Severity:    models.High,
			Description: "Sample Open SSL vulnerability",
			References:  []string{"https://cve.mitre.org/cve-2023-0001"},
		},
	}
	db.vulns["apt"] = []models.Vulnerability{
		{
			ID:          "CVE-2023-5678",
			Package:     "apt",
			Version:     "2.7.14",
			FixedIn:     "2.7.15",
			Severity:    models.Medium,
			Description: "Potential package verification bypass in apt",
			References:  []string{"https://cve.mitre.org/cve-2023-5678"},
		},
	}
	db.vulns["bash"] = []models.Vulnerability{
		{
			ID:          "CVE-2023-9012",
			Package:     "apt",
			Version:     "5.2.21",
			FixedIn:     "5.2.22",
			Severity:    models.Critical,
			Description: "Command injection vulnerability in bash",
			References:  []string{"https://cve.mitre.org/cve-2023-9012"},
		},
	}
	return db
}

// implementing VulnerabilityDatabase interface
func (db *SimpleVulnDB) CheckPackage(ctx context.Context, pkg models.Package) ([]models.Vulnerability, error) {
	if vulns, exists := db.vulns[pkg.Name]; exists {
		return vulns, nil
	}
	return nil, nil
}

// implementing vulnerabilityDatabase interface
func (db *SimpleVulnDB) UpdateDatabase(ctx context.Context) error {
	return nil
}
