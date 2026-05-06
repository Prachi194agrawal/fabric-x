/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x/tools/fxconfig/internal/validation"
)

func TestPolicyDSLChecker_Check(t *testing.T) {
	t.Parallel()

	checker := validation.PolicyDSLChecker{}

	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"valid OR", "OR('Org1MSP.member')", false},
		{"valid AND", "AND('Org1MSP.member', 'Org2MSP.member')", false},
		{"invalid expression", "NOT_A_POLICY", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checker.Check(tt.expr)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOSFileChecker_Exists(t *testing.T) {
	t.Parallel()

	checker := validation.OSFileChecker{}

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "key.pem")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid file", tmpFile, false},
		{"empty path", "", true},
		{"non-existent", filepath.Join(tmpDir, "missing.pem"), true},
		{"directory given", tmpDir, true},
		{"path traversal", "../../etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checker.Exists(tt.path)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOSFileChecker_Exists_SymlinkTraversal(t *testing.T) {
	t.Parallel()

	checker := validation.OSFileChecker{}

	safeDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("secret"), 0o600))

	symlinkPath := filepath.Join(safeDir, "link.pem")
	if err := os.Symlink(outsideFile, symlinkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation not supported")
		}
		require.NoError(t, err)
	}

	err := checker.Exists(symlinkPath)
	require.Error(t, err)
}

func TestOSDirectoryChecker_Exists(t *testing.T) {
	t.Parallel()

	checker := validation.OSDirectoryChecker{}

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "file.txt")
	require.NoError(t, os.WriteFile(tmpFile, []byte("data"), 0o600))

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid directory", tmpDir, false},
		{"empty path", "", true},
		{"non-existent", filepath.Join(tmpDir, "missing"), true},
		{"file given", tmpFile, true},
		{"path traversal", "../../etc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checker.Exists(tt.path)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOSDirectoryChecker_Exists_SymlinkTraversal(t *testing.T) {
	t.Parallel()

	checker := validation.OSDirectoryChecker{}

	safeDir := t.TempDir()
	outsideDir := t.TempDir()

	symlinkPath := filepath.Join(safeDir, "link-dir")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation not supported")
		}
		require.NoError(t, err)
	}

	err := checker.Exists(symlinkPath)
	require.Error(t, err)
}
