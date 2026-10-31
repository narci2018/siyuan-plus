// SiYuan - https://github.com/siyuan-note/siyuan
// Copyright (c) 2020-present, b3log.org
// SPDX-License-Identifier: AGPL-3.0-or-later

package model

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/siyuan-note/siyuan/kernel/util"
)

//go:embed builtin_plugins/*
var builtinPluginsFS embed.FS

func initBuiltinPlugins() {
	pluginsDir := filepath.Join(util.DataDir, "plugins")
	_ = os.MkdirAll(pluginsDir, 0755)

	_ = fs.WalkDir(builtinPluginsFS, "builtin_plugins", func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == "builtin_plugins" {
			return nil
		}
		relPath, err := filepath.Rel("builtin_plugins", path)
		if err != nil {
			return nil
		}
		targetPath := filepath.Join(pluginsDir, relPath)
		if d.IsDir() {
			_ = os.MkdirAll(targetPath, 0755)
		} else {
			info, statErr := os.Stat(targetPath)
			if statErr != nil || info.Size() == 0 {
				data, readErr := builtinPluginsFS.ReadFile(path)
				if readErr == nil {
					_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
					_ = os.WriteFile(targetPath, data, 0644)
				}
			}
		}
		return nil
	})
}
