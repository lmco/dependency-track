/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.filestorage.local;

import com.github.luben.zstd.Zstd;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.api.FileStorageProvider;
import org.eclipse.microprofile.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ProxySelector;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * @since 5.0.0
 */
public final class LocalFileStorageProvider implements FileStorageProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(LocalFileStorageProvider.class);
    static final String NAME = "local";

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public FileStorage create(Config config, ProxySelector proxySelector) {
        // Storage compares resolved file paths against these directories,
        // so they must be absolute and normalized, e.g. without "..".
        final Path directoryPath = config.getValue("dt.file-storage.local.directory", Path.class)
                .toAbsolutePath()
                .normalize();
        requireUsableDirectory(directoryPath);

        final Optional<Path> retainedBomDirectoryPath = config.getOptionalValue(
                        "dt.file-storage.local.retained-bom-directory", Path.class)
                .map(path -> path.toAbsolutePath().normalize());
        retainedBomDirectoryPath.ifPresent(path -> {
            requireUsableDirectory(path);
            requireSeparateDirectories(directoryPath, path);
        });

        final int compressionLevel = config.getOptionalValue("dt.file-storage.local.compression-level", int.class)
                .orElse(5);
        if (compressionLevel < Zstd.minCompressionLevel() || compressionLevel > Zstd.maxCompressionLevel()) {
            throw new IllegalStateException("Invalid compression level: must be between %d and %d, but is %d"
                    .formatted(Zstd.minCompressionLevel(), Zstd.maxCompressionLevel(), compressionLevel));
        }

        LOGGER.debug("Files will be stored in {}", directoryPath);
        retainedBomDirectoryPath.ifPresent(path -> LOGGER.debug("Retained BOMs will be stored in {}", path));
        return new LocalFileStorage(directoryPath, retainedBomDirectoryPath.orElse(directoryPath), compressionLevel);
    }

    private static void requireUsableDirectory(Path directoryPath) {
        try {
            Files.createDirectories(directoryPath);
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to create directory for file storage at %s".formatted(directoryPath), e);
        }

        final boolean canRead = directoryPath.toFile().canRead();
        final boolean canWrite = directoryPath.toFile().canWrite();
        if (!canRead || !canWrite) {
            throw new IllegalStateException("Insufficient permissions for directory %s (canRead=%s, canWrite=%s)"
                    .formatted(directoryPath, canRead, canWrite));
        }
    }

    private static void requireSeparateDirectories(Path directoryPath, Path retainedBomDirectoryPath) {
        final Path realDirectoryPath;
        final Path realRetainedBomDirectoryPath;
        final boolean sameFileStore;
        try {
            realDirectoryPath = directoryPath.toRealPath();
            realRetainedBomDirectoryPath = retainedBomDirectoryPath.toRealPath();
            sameFileStore =
                    Files.getFileStore(realDirectoryPath).equals(Files.getFileStore(realRetainedBomDirectoryPath));
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to inspect directories %s and %s".formatted(directoryPath, retainedBomDirectoryPath), e);
        }

        if (realRetainedBomDirectoryPath.startsWith(realDirectoryPath)
                || realDirectoryPath.startsWith(realRetainedBomDirectoryPath)) {
            throw new IllegalStateException("""
                    dt.file-storage.local.retained-bom-directory (%s) must not be the same as, \
                    be inside, or contain dt.file-storage.local.directory (%s)""".formatted(realRetainedBomDirectoryPath, realDirectoryPath));
        }

        if (sameFileStore) {
            LOGGER.warn("""
                    Retained BOMs ({}) are on the same filesystem as other files ({}); \
                    Make sure the volume for retained BOMs is mounted""", realRetainedBomDirectoryPath, realDirectoryPath);
        }
    }
}
