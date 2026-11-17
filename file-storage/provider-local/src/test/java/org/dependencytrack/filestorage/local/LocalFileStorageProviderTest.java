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

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.filestorage.api.FileStorage;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ProxySelector;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assumptions.assumeThat;

class LocalFileStorageProviderTest {

    private static final String SEPARATE_DIRECTORIES_MESSAGE = """
            dt.file-storage.local.retained-bom-directory (%s) must not be the same as, \
            be inside, or contain dt.file-storage.local.directory (%s)""";

    @TempDir
    private Path tempDirPath;

    @Test
    void createShouldThrowWhenRetainedBomDirectoryIsLinkToDirectory() throws Exception {
        final Path directoryPath = Files.createDirectory(tempDirPath.resolve("storage"));
        final Path linkPath = Files.createSymbolicLink(tempDirPath.resolve("link"), directoryPath);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(directoryPath, linkPath))
                .withMessage(SEPARATE_DIRECTORIES_MESSAGE, directoryPath.toRealPath(), directoryPath.toRealPath());
    }

    @Test
    void createShouldThrowWhenRetainedBomDirectoryIsInsideDirectory() throws Exception {
        final Path directoryPath = tempDirPath.resolve("storage");
        final Path retainedBomDirectoryPath = directoryPath.resolve("retained");

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(directoryPath, retainedBomDirectoryPath))
                .withMessage(
                        SEPARATE_DIRECTORIES_MESSAGE,
                        retainedBomDirectoryPath.toRealPath(),
                        directoryPath.toRealPath());
    }

    @Test
    void createShouldThrowWhenDirectoryIsInsideRetainedBomDirectory() throws Exception {
        final Path retainedBomDirectoryPath = tempDirPath.resolve("retained");
        final Path directoryPath = retainedBomDirectoryPath.resolve("storage");

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(directoryPath, retainedBomDirectoryPath))
                .withMessage(
                        SEPARATE_DIRECTORIES_MESSAGE,
                        retainedBomDirectoryPath.toRealPath(),
                        directoryPath.toRealPath());
    }

    @Test
    void createShouldThrowWhenRetainedBomDirectoryIsNotWritable() throws Exception {
        final Path directoryPath = tempDirPath.resolve("storage");
        final Path retainedBomDirectoryPath = Files.createDirectory(tempDirPath.resolve("retained"));
        Files.setPosixFilePermissions(retainedBomDirectoryPath, PosixFilePermissions.fromString("r-x------"));
        assumeThat(Files.isWritable(retainedBomDirectoryPath))
                .as("Directory is still writable, e.g. because the test runs as root")
                .isFalse();

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> createStorage(directoryPath, retainedBomDirectoryPath))
                .withMessage(
                        "Insufficient permissions for directory %s (canRead=true, canWrite=false)",
                        retainedBomDirectoryPath);
    }

    private static FileStorage createStorage(Path directoryPath, Path retainedBomDirectoryPath) {
        final Config config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.of(
                        "dt.file-storage.local.directory",
                        directoryPath.toAbsolutePath().toString(),
                        "dt.file-storage.local.retained-bom-directory",
                        retainedBomDirectoryPath.toAbsolutePath().toString()))
                .build();
        return new LocalFileStorageProvider().create(config, ProxySelector.getDefault());
    }
}
