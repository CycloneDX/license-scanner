// SPDX-License-Identifier: Apache-2.0

package debugger

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"

	"github.com/IBM/license-scanner/licenses"
	"github.com/IBM/license-scanner/normalizer"
)

// TODO: Commit to history, but if this is not being used anywhere, we should delete it.
func printNumberedCharacterString(label string, stringToPrint string) {
	fmt.Println(label)

	// Replace newlines and tabs with characters
	lf := `␊`  // \u240A
	ff := `␌`  // \u240D
	tab := `␉` // \u2409

	stringToPrint = strings.ReplaceAll(stringToPrint, "\n", lf)
	stringToPrint = strings.ReplaceAll(stringToPrint, "\r", ff)
	stringToPrint = strings.ReplaceAll(stringToPrint, "\t", tab)

	fmt.Print("|")
	for _, v := range stringToPrint {
		fmt.Print(v)
		fmt.Print(" |")
	}
	fmt.Println()

	fmt.Print("|")
	for _, v := range stringToPrint {
		fmt.Printf("%02d|", v)
	}
	fmt.Println()
	fmt.Println()
}

// TODO: Commit to history, but if this is not being used anywhere, we should delete it.
func printIndexMap(label string, indexMap []int) {
	normalizedOutput := "|"
	originalOutput := "|"

	for normalizedIndex, originalIndex := range indexMap {
		normalizedOutput = fmt.Sprintf("%02d|", normalizedIndex)
		originalOutput = fmt.Sprintf("%02d|", originalIndex)
	}

	fmt.Println(label)
	fmt.Printf("%v< normalized\n", normalizedOutput)
	fmt.Printf("%v< original\n\n", originalOutput)
}

func DebugLicenseMatchFailure(license licenses.License, normalizedText string) ([]string, error) {
	var results []string
	for _, pattern := range license.PrimaryPatterns {

		normalizedPattern := normalizer.NewNormalizationData(pattern.Text, true)
		if err := normalizedPattern.NormalizeText(); err != nil {
			return nil, err
		}

		result := cmp.Diff(normalizedPattern.NormalizedText, normalizedText)
		results = append(results, result)
	}

	return results, nil
}
