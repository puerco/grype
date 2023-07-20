package openvex

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/source"
	openvex "github.com/openvex/go-vex/pkg/vex"
	vexctl "github.com/openvex/vexctl/pkg/ctl"
)

type Processor struct{}

func New() *Processor {
	return &Processor{}
}

// ReadVexDocuments reads and merges VEX documents
func (ovm *Processor) ReadVexDocuments(docs []string) (interface{}, error) {
	// Combine all VEX documents into a single VEX document
	vexdata, err := vexctl.New().MergeFiles(context.Background(), &vexctl.MergeOptions{}, docs)
	if err != nil {
		return nil, fmt.Errorf("merging vex documents: %w", err)
	}

	return vexdata, nil
}

// productIDentifiersFromContext reads the package context and returns software
// identifiers identifying the scanned image.
func productIDentifiersFromContext(pkgContext *pkg.Context) ([]string, error) {
	switch v := pkgContext.Source.Metadata.(type) {
	case source.StereoscopeImageSourceMetadata:
		// TODO(puerco): We can create a wider definition here. This effectively
		// adds the multiarch image and the image of the OS running grype. We
		// could generate more identifiers to match better.
		return identifiersFromDigests(v.RepoDigests), nil
	default:
		// Fail for now
		return nil, errors.New("source type not supported for VEX")
	}
}

func identifiersFromDigests(digests []string) []string {
	identifiers := []string{}

	for _, d := range digests {
		// The first identifier is the original image reference:
		identifiers = append(identifiers, d)

		// Now, parse the digest
		parts := strings.SplitN(d, "@", 2)
		if len(parts) != 2 {
			continue
		}

		name := ""
		repoURL := ""
		digestString := strings.TrimPrefix(parts[1], "sha256:")
		subparts := strings.Split(parts[0], "/")
		switch len(subparts) {
		case 1:
			name = subparts[0]
			repoURL = ""
		default:
			name = subparts[(len(subparts) - 1)]
			repoURL = strings.Join(subparts[0:len(subparts)-1], "/")
		}

		if name == "" {
			continue
		}
		qMap := map[string]string{}
		// Add
		if repoURL != "" {
			qMap["repository_url"] = repoURL
		}
		qs := packageurl.QualifiersFromMap(qMap)
		identifiers = append(identifiers, packageurl.NewPackageURL(
			"oci", "", name, fmt.Sprintf("sha256%%3A%s", digestString), qs, "",
		).String())

		// TODO(puerco): Should also pass the digests only? They could be listed
		// in the openvex document an foks may choose to vex on the hash.
	}
	return identifiers
}

// subcomponentIdentifiersFromMatch returns the list of identifiers from the
// package where grype did the match.
func subcomponentIdentifiersFromMatch(m *match.Match) []string {
	ret := []string{}
	if m.Package.PURL != "" {
		ret = append(ret, m.Package.PURL)
	}

	// TODO(puerco):Implement CPE matching in openvex/go-vex
	/*
		for _, c := range m.Package.CPEs {
			ret = append(ret, c.String())
		}
	*/
	return ret
}

// FilterMatches takes a set of scanning results and moves any results marked in
// the VEX data as fixed or not_affected to the ignored list.
func (ovm *Processor) FilterMatches(
	docRaw interface{}, pkgContext *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	doc, ok := docRaw.(*openvex.VEX)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as openvex")
	}

	remainingMatches := match.NewMatches()

	products, err := productIDentifiersFromContext(pkgContext)
	if err != nil {
		return nil, nil, fmt.Errorf("reading product identifiers from context: %w", err)
	}

	// Now, let's go through grype's matches
	sorted := matches.Sorted()
	for i := range sorted {
		var statement *openvex.Statement
		subcmp := subcomponentIdentifiersFromMatch(&sorted[i])

		// Range through the product's different names
		for _, product := range products {
			if matchingStatements := doc.Matches(sorted[i].Vulnerability.ID, product, subcmp); len(matchingStatements) != 0 {
				statement = &matchingStatements[0]
				break
			}
		}

		// No data about this match's component. Next.
		if statement == nil {
			remainingMatches.Add(sorted[i])
			continue
		}

		// Filtering only applies to not_affected and fixed statuses
		if statement.Status != openvex.StatusNotAffected && statement.Status != openvex.StatusFixed {
			remainingMatches.Add(sorted[i])
			continue
		}

		ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
			Match: sorted[i],
			AppliedIgnoreRules: []match.IgnoreRule{
				{
					Vulnerability: sorted[i].Vulnerability.ID,
					Namespace:     "vex",
					FixState:      string(statement.Status),
					Package: match.IgnoreRulePackage{
						Name:     sorted[i].Package.Name,
						Version:  sorted[i].Package.Version,
						Language: sorted[i].Package.Language.String(),
						Type:     string(sorted[i].Package.Type),
						Location: "",
					},
				},
			},
		})
	}
	return &remainingMatches, ignoredMatches, nil
}
