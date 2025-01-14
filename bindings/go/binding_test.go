package tree_sitter_ssh_client_config_test

import (
	"testing"

	tree_sitter "github.com/smacker/go-tree-sitter"
	"github.com/tree-sitter/tree-sitter-ssh_client_config"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_ssh_client_config.Language())
	if language == nil {
		t.Errorf("Error loading SshClientConfig grammar")
	}
}
