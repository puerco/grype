package models

import (
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
)

type PresenterConfig struct {
	Matches          match.Matches
	IgnoredMatches   []match.IgnoredMatch
	Packages         []pkg.Package
	Context          pkg.Context
	MetadataProvider vulnerability.MetadataProvider
	SBOM             *sbom.SBOM
	AppConfig        interface{}
	DBStatus         interface{}
	VexReport        []grype.VEXIgnoreReport
}
