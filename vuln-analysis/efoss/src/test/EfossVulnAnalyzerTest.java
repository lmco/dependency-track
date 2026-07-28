package org.dependencytrack.vulnanalysis.efoss;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.google.protobuf.util.JsonFormat;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.memory.MemoryCacheProvider;
import org.dependencytrack.plugin.api.MutableServiceRegistry;
import org.dependencytrack.plugin.api.config.ConfigRegistry;
import org.dependencytrack.plugin.testing.MockConfigRegistry;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.util.ArrayList;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class EfossVulnAnalyzerTest {
    
    private CacheManager cacheManager;
    private EfossVulnAnalyzerFactory analyzerFactory;
    private VulnAnalyzer analyzer;

    private final String API_URL = "https://api.efoss.us.lmco.com/public-api/graphql";
    private final String CREDENTIALS = "foo@example.com:test-api-token";

    @BeforeEach
    void beforeEach(WireMockRuntimeInfo wmRuntimeInfo) {
        final var cacheProvider = new MemoryCacheProvider(new SmallRyeConfigBuilder().build());
        cacheManager = cacheProvider.create();

        analyzerFactory = new EfossVulnAnalyzerFactory();

        final var configRegistry = new MockConfigRegistry(
                analyzerFactory.runtimeConfigSpec(),
                new EfossVulnAnalyzerConfigV1()
                        .withEnabled(true)
                        .withApiUsername("foo@example.com")
                        .withApiToken("test-api-token"));

        analyzerFactory.init(
                new MutableServiceRegistry()
                        .register(ConfigRegistry.class, configRegistry)
                        .register(CacheManager.class, cacheManager)
                        .register(HttpClient.class, HttpClient.newHttpClient()));

        analyzer = analyzerFactory.create();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (analyzerFactory != null) {
            analyzerFactory.close();
        }
        if (cacheManager != null) {
            cacheManager.close();
        }
    }

    @Test
    void shouldAnalyzeWithNoEfossEntries() throws Exception {
        stubFor(post(urlPathEqualTo("https://api.efoss.us.lmco.com/public-api/graphql"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("efoss-no-entries-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldAnalyzeWithOneEfossEntry() throws Exception {
        stubFor(post(urlPathEqualTo("https://api.efoss.us.lmco.com/public-api/graphql"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("efoss-singular-entry-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThatJson(JsonFormat.printer().print(vdr)).isEqualTo(/* language=JSON */ """
                {
                  "data": {
                    "fossComponentRecords": [
                      {
                        "id": "maven:net.logstash.logback:logstash-logback-encoder:8.1",
                        "group": "net.logstash.logback",
                        "licenseIds": [
                          "Apache-2.0"
                        ],
                        "licenses": [
                          {
                            "licenseId": "Apache-2.0",
                            "licenseName": "Apache License 2.0"
                          }
                        ],
                        "purl": "pkg:maven/net.logstash.logback/logstash-logback-encoder@8.1",
                        "useCaseRisk": {
                          "distribution": "MED",
                          "use": "LOW",
                          "internalCombining": "LOW"
                        }
                      }
                    ]
                  }
                }
                """);

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldAnalyzeWithMultipleEfossEntries() throws Exception {
        stubFor(post(urlPathEqualTo("https://api.efoss.us.lmco.com/public-api/graphql"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("efoss-multiple-entries-response.json")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("jackson-databind")
                                .setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThatJson(JsonFormat.printer().print(vdr)).isEqualTo(/* language=JSON */ """
                {
                  "data": {
                    "fossComponentRecords": [
                      {
                        "id": "maven:net.logstash.logback:logstash-logback-encoder:8.1",
                        "group": "net.logstash.logback",
                        "licenseIds": [
                          "Apache-2.0"
                        ],
                        "licenses": [
                          {
                            "licenseId": "Apache-2.0",
                            "licenseName": "Apache License 2.0"
                          }
                        ],
                        "purl": "pkg:maven/net.logstash.logback/logstash-logback-encoder@8.1",
                        "useCaseRisk": {
                          "distribution": "MED",
                          "use": "LOW",
                          "internalCombining": "LOW"
                        }
                      },
                      {
                        "id": "maven:io.prometheus:simpleclient_tracer_otel:0.16.0",
                        "group": "io.prometheus",
                        "licenseIds": [
                          "Apache-2.0",
                          "CC0-1.0",
                          "CC-BY-SA-3.0",
                          "CUSTOM-Public-Domain"
                        ],
                        "licenses": [
                          {
                            "licenseId": "Apache-2.0",
                            "licenseName": "Apache License 2.0"
                          },
                          {
                            "licenseId": "CC0-1.0",
                            "licenseName": "Creative Commons Zero v1.0 Universal"
                          },
                          {
                            "licenseId": "CC-BY-SA-3.0",
                            "licenseName": "Creative Commons Attribution Share Alike 3.0 Unported"
                          },
                          {
                            "licenseId": "CUSTOM-Public-Domain",
                            "licenseName": "Public Domain"
                          }
                        ],
                        "purl": "pkg:maven/io.prometheus/simpleclient_tracer_otel@0.16.0",
                        "useCaseRisk": {
                          "distribution": "HIGH",
                          "use": "HIGH",
                          "internalCombining": "HIGH"
                        }
                      },
                      {
                        "id": "maven:org.glassfish.jersey.inject:jersey-hk2:4.0.2",
                        "group": "org.glassfish.jersey.inject",
                        "licenseIds": [
                          "Apache-2.0",
                          "BSD-3-Clause",
                          "CC0-1.0",
                          "Classpath-exception-2.0",
                          "CUSTOM-Public-Domain",
                          "EPL-2.0",
                          "GPL-1.0-or-later",
                          "GPL-2.0-only",
                          "GPL-2.0-or-later",
                          "MIT",
                          "W3C"
                        ],
                        "licenses": [
                          {
                            "licenseId": "Apache-2.0",
                            "licenseName": "Apache License 2.0"
                          },
                          {
                            "licenseId": "BSD-3-Clause",
                            "licenseName": "BSD 3-Clause \"New\" or \"Revised\" License"
                          },
                          {
                            "licenseId": "CC0-1.0",
                            "licenseName": "Creative Commons Zero v1.0 Universal"
                          },
                          {
                            "licenseId": "CUSTOM-Public-Domain",
                            "licenseName": "Public Domain"
                          },
                          {
                            "licenseId": "EPL-2.0",
                            "licenseName": "Eclipse Public License 2.0"
                          },
                          {
                            "licenseId": "GPL-1.0-or-later",
                            "licenseName": "GNU General Public License v1.0 or later"
                          },
                          {
                            "licenseId": "GPL-2.0-only",
                            "licenseName": "GNU General Public License v2.0 only"
                          },
                          {
                            "licenseId": "GPL-2.0-or-later",
                            "licenseName": "GNU General Public License v2.0 or later"
                          },
                          {
                            "licenseId": "MIT",
                            "licenseName": "MIT License"
                          },
                          {
                            "licenseId": "W3C",
                            "licenseName": "W3C Software Notice and License (2002-12-31)"
                          }
                        ],
                        "purl": "pkg:maven/org.glassfish.jersey.inject/jersey-hk2@4.0.2",
                        "useCaseRisk": {
                          "distribution": "HIGH",
                          "use": "HIGH",
                          "internalCombining": "HIGH"
                        }
                      }
                    ]
                  }
                }
                """);

        final Bom secondVdr = analyzer.analyze(bom);
        assertThat(secondVdr).isEqualTo(vdr);

        verify(1, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldNotAnalyzeComponentWithoutBomRef() throws Exception {
        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.acme/acme-lib@1.0.0")
                                .build())
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(0, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldBatchRequestsWithUpTo50Components() throws Exception {
        stubFor(post(urlPathEqualTo("https://api.efoss.us.lmco.com/public-api/graphql"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"data\":[]}")));

        final var components = new ArrayList<Component>(150);
        for (int i = 0; i < 150; i++) {
            components.add(
                    Component.newBuilder()
                            .setBomRef(String.valueOf(i))
                            .setName("acme-lib")
                            .setPurl("pkg:maven/com.acme/acme-lib@1.0." + i)
                            .build());
        }

        final var bom = Bom.newBuilder()
                .addAllComponents(components)
                .build();

        final Bom vdr = analyzer.analyze(bom);
        assertThat(vdr).isEqualTo(Bom.getDefaultInstance());

        verify(3, postRequestedFor(anyUrl()));
    }

    @Test
    void shouldSendCorrectHeaders() throws Exception {
        stubFor(post(urlPathEqualTo("https://api.efoss.us.lmco.com/public-api/graphql"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"data\":[]}")));

        final var bom = Bom.newBuilder()
                .addComponents(
                        Component.newBuilder()
                                .setBomRef("1")
                                .setName("acme-lib")
                                .setPurl("pkg:maven/com.acme/acme-lib@1.0.0")
                                .build())
                .build();

        analyzer.analyze(bom);

        verify(1, postRequestedFor(anyUrl())
                .withHeader("Authorization", equalTo("Basic " + Base64.getEncoder().encodeToString(CREDENTIALS.getBytes(StandardCharsets.UTF_8))))
                .withHeader("Content-Type", equalTo("application/json")));
    }

}
