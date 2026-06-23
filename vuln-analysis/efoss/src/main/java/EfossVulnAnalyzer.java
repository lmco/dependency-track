package org.dependencytrack.vulnanalysis.efoss;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import graphql.ExecutionResult;
import graphql.GraphQL;
import graphql.schema.GraphQLSchema;
import graphql.schema.StaticDataFetcher;
import graphql.schema.idl.RuntimeWiring;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.TypeDefinitionRegistry;

import static graphql.schema.idl.RuntimeWiring.newRuntimeWiring;


final class EfossVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(EfossVulnAnalyzer.class);
    private final String API_BASE_URL = "api.efoss.us.lmco.com/public-api/graphql";

    private final HttpClient httpClient;
    private final String apiUsername;
    private final String apiToken;
    private final ArrayList<EfossRequestObject> requestObjects = new ArrayList();
    private final String fullUrl;

    EfossVulnAnalyzer(
            HttpClient httpClient,
            String apiUsername,
            String apiToken) {
        this.httpClient = httpClient;
        this.apiUsername = apiUsername;
        this.apiToken = apiToken;

        StringBuilder builder = new StringBuilder("https://");
        builder.append(apiUsername);
        builder.append(":");
        builder.append(apiToken);
        builder.append("@");
        builder.append(API_BASE_URL);
        this.fullUrl = builder.toString();
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {

        for (final Component component : bom.getComponentsList()) {
            EfossRequestObject temp = new EfossRequestObject(component);
            requestObjects.add(temp);
        }

        // TODO: Decide if we like this endpoint or if we want to use getFossComponentRecordsByPurl
        // or if we want to use one as a backup in case the other fails for some reason
        StringBuilder builder = new StringBuilder("{fossComponentRecords(ids: [");
        for(Iterator<EfossRequestObject> itr = requestObjects.iterator(); itr.hasNext();) {
            EfossRequestObject current = itr.next();
            builder.append("\"");
            builder.append(current.getEfossId());
            if(itr.hasNext())
                builder.append("\", ");
            else
                builder.append("\"]) {id group licenseIds licenses {licenseId licenseName} purl useCaseRisk { distribution use internalCombining }}}");
        }
        String schema = builder.toString();

        final var request = HttpRequest.newBuilder()
                .uri(java.net.URI.create(fullUrl))
                .header("Accept", "application/json")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofByteArray(schema.getBytes()))
                .build();

        LOGGER.info("REQUEST IS {}", request);

        final HttpResponse<byte[]> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException("eFOSS API request to %s failed".formatted(API_BASE_URL), e);
        }

        LOGGER.info("RESPONSE IS {}", response);

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            // TODO: Do some stuff
        }

        throw new IllegalStateException(
                "eFOSS API request to %s failed with status %d".formatted(API_BASE_URL, response.statusCode()));
    }
    
}