package tlsquery

import "testing"

func TestChainInfo_Leaf(t *testing.T) {
	t.Run("valid chain returns leaf", func(t *testing.T) {
		chain := &ChainInfo{
			Certificates: []CertInfo{
				{CommonName: "leaf.example.com", Type: "leaf"},
				{CommonName: "intermediate", Type: "intermediate"},
			},
		}

		leaf, err := chain.Leaf()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if leaf.CommonName != "leaf.example.com" {
			t.Errorf("expected leaf.example.com, got %s", leaf.CommonName)
		}
	})

	t.Run("empty chain returns error", func(t *testing.T) {
		chain := &ChainInfo{Certificates: []CertInfo{}}

		_, err := chain.Leaf()
		if err == nil {
			t.Error("expected error for empty chain")
		}
	})

	t.Run("nil chain returns error", func(t *testing.T) {
		var chain *ChainInfo

		_, err := chain.Leaf()
		if err == nil {
			t.Error("expected error for nil chain")
		}
	})
}

func TestChainInfo_WithoutPEM(t *testing.T) {
	chain := &ChainInfo{
		InputName:  "example.com:443",
		InputLabel: "target",
		Certificates: []CertInfo{
			{CommonName: "test", PEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"},
		},
	}

	result := chain.WithoutPEM()

	if result.Certificates[0].PEM != "" {
		t.Error("PEM should be empty after WithoutPEM")
	}
	if chain.Certificates[0].PEM == "" {
		t.Error("original chain should not be modified")
	}
	if result.InputName != "example.com:443" {
		t.Errorf("expected InputName to be preserved, got %q", result.InputName)
	}
	if result.InputLabel != "target" {
		t.Errorf("expected InputLabel to be preserved, got %q", result.InputLabel)
	}
}

func TestChainInfo_ChainNames(t *testing.T) {
	chain := &ChainInfo{
		Certificates: []CertInfo{
			{CommonName: "leaf.example.com"},
			{CommonName: "Intermediate CA"},
			{CommonName: "Root CA"},
		},
	}

	names := chain.ChainNames()

	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
	if names[0] != "leaf.example.com" {
		t.Errorf("expected leaf.example.com, got %s", names[0])
	}
	if names[2] != "Root CA" {
		t.Errorf("expected Root CA, got %s", names[2])
	}
}
