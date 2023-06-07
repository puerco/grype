package grype

import (
	"fmt"
	"os"
	"time"

	"github.com/anchore/grype/grype/match"
	openvex "github.com/openvex/go-vex/pkg/vex"
)

type VexMatcher struct {
	Options VexMatcherOptions
	impl    vexMatcherImplementation
}

type VEXIgnoreReport struct {
	Vulnerability string
	Author        string
	DocumentID    string
	Statement     openvex.Statement
}

func NewVexMatcher() *VexMatcher {
	return &VexMatcher{
		Options: VexMatcherOptions{
			IgnoreProduct: true,
		},
		impl: &openvexMatcher{},
	}
}

type VexMatcherOptions struct {
	IgnoreProduct bool
}

func (vm *VexMatcher) FindMatches(remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error) {
	doc, err := vm.impl.ParseVexDoc("/tmp/vex")
	if err != nil {
		return nil, nil, fmt.Errorf("parsing vex document: %w", err)
	}

	newMatches, err := vm.impl.FilterMatches(doc, remainingMatches)
	if err != nil {
		return nil, nil, fmt.Errorf("checking matches against VEX data: %w", err)
	}

	return newMatches, ignoredMatches, nil
}

type vexMatcherImplementation interface {
	ParseVexDoc(string) (*openvex.VEX, error)
	FilterMatches(*openvex.VEX, *match.Matches) (*match.Matches, error)
	UpdateIgnoredMatches(*match.Matches, []match.IgnoredMatch) []match.IgnoredMatch
}

type openvexMatcher struct{}

func (ovm *openvexMatcher) ParseVexDoc(path string) (*openvex.VEX, error) {
	return &openvex.VEX{
		Metadata: openvex.Metadata{},
		Statements: []openvex.Statement{
			{
				Vulnerability: "CVE-2023-1255",
				Timestamp:     &time.Time{},
				Products:      []string{"pkg:oci/alpine@sha256%3A02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11"},
				Subcomponents: []string{
					"pkg:apk/alpine/libcrypto3@3.0.8-r3?arch=x86_64&upstream=openssl&distro=alpine-3.17.3",
					"pkg:apk/alpine/libssl3@3.0.8-r3?arch=x86_64&upstream=openssl&distro=alpine-3.17.3",
				},
				Status:          "not_affected",
				StatusNotes:     "This is obvfiously a demo and fake VEX data",
				Justification:   openvex.InlineMitigationsAlreadyExist,
				ImpactStatement: "This image includes a hack in the amd64 variant to limit reads when decrypting AES-XTS",
			},
		},
	}, nil
	/*
		doc, err := openvex.OpenJSON(path)
		if err != nil {
			return nil, fmt.Errorf("opening openvex document: %s", err)
		}

		return doc, nil*/
}

// FilterMatches takes a VEX document and a Matches object and returns the filtered
// list by discarding matches in OpenVEX
func (ovm *openvexMatcher) FilterMatches(doc *openvex.VEX, matches *match.Matches) (*match.Matches, error) {
	remainingMatches := match.NewMatches()
	report := []VEXIgnoreReport{}
	// ignoredMatches := []match.IgnoredMatch{}
	outfile, err := os.Create("/tmp/output.txt")
	if err != nil {
		return nil, fmt.Errorf("unable to open output file: %w", err)
	}
	defer outfile.Close()

	// Build a catalog of matches in the openvex doc
	vulnCatalog := map[string]map[string]openvex.Statement{}
	for _, s := range doc.Statements {
		// TODO(puerco): Implement
		// Here we need to match the image to the product purl in the
		// vex statement, unless options.IgnoreProduct is set.

		// Cycle subcomponents
		for _, identifier := range s.Subcomponents {
			/// if we already have a statement for this vulnerability...
			if _, ok := vulnCatalog[s.Vulnerability]; !ok {
				vulnCatalog[s.Vulnerability] = map[string]openvex.Statement{}
			}

			if _, ok := vulnCatalog[s.Vulnerability][identifier]; !ok {
				vulnCatalog[s.Vulnerability][identifier] = s
				continue
			}

			// but is newer...
			if s.Timestamp.Before(*vulnCatalog[s.Vulnerability][identifier].Timestamp) {
				// ... discard
				continue
			}

			// .. otherwise replace as it is the latest vex statement
			vulnCatalog[s.Vulnerability][identifier] = s
		}
	}

	fmt.Fprintln(outfile, "VEX Debug Data")
	fmt.Fprintf(outfile, "Processing %d matches\n", len(matches.Sorted()))

	// Now, let's go through grype's matches
	for _, m := range matches.Sorted() {
		fmt.Fprintf(outfile, "%s → %s\n", m.Vulnerability.ID, m.Package.PURL)

		// If the vex doc does not have data for this vulnerability, continue
		if _, ok := vulnCatalog[m.Vulnerability.ID]; !ok {
			remainingMatches.Add(m)
			continue
		}

		/// search in the vuln's statements for data about this component:
		var statement *openvex.Statement
		for compPurl, ts := range vulnCatalog[m.Vulnerability.ID] {
			if m.Package.PURL == "" {
				continue
			}

			match, err := purlGlobsPurl(compPurl, m.Package.PURL)
			if err != nil {
				return nil, fmt.Errorf("matching purls: %w", err)
			}

			if match {
				statement = &ts
				break
			}
		}

		// No data about this match's component. Next.
		if statement == nil {
			remainingMatches.Add(m)
			continue
		}

		// For now, we don't care about statements other than not_affected or fixed
		if statement.Status != openvex.StatusNotAffected && statement.Status != openvex.StatusFixed {
			remainingMatches.Add(m)
			continue
		}

		// OK, this is a match that needs to be turned off according to the
		// VEX data, skip it and a record in the report
		report = append(report, VEXIgnoreReport{
			Vulnerability: m.Vulnerability.ID,
			Author:        doc.Author,
			DocumentID:    doc.ID,
			Statement:     *statement,
		})
	}

	fmt.Fprintf(outfile, "%+v", report)

	return &remainingMatches, nil // errors.New("Fallamos adredede mano")
}

func (ovm *openvexMatcher) UpdateIgnoredMatches(newMatches *match.Matches, oldIgnored []match.IgnoredMatch) []match.IgnoredMatch {
	return oldIgnored
}

// purlGlobsPurl takes two purls and returns true if one contains other
func purlGlobsPurl(one, other string) (bool, error) {
	// TODO(puerco) implement beyond this lazy matching
	return one == other, nil
}
