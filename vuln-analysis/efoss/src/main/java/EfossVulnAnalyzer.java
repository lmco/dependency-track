package org.dependencytrack.vulnanalysis.efoss;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Base64;
import java.util.List;
import java.nio.charset.StandardCharsets;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Component;
import org.cyclonedx.proto.v1_7.LicenseChoice;
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
    private final String API_URL = "https://api.efoss.us.lmco.com/public-api/graphql";

    private final HttpClient httpClient;
    private final String apiUsername;
    private final String apiToken;
    private final HashMap<String, Component> componentMap = new HashMap();

    EfossVulnAnalyzer(
            HttpClient httpClient,
            String apiUsername,
            String apiToken) {
        this.httpClient = httpClient;
        this.apiUsername = apiUsername;
        this.apiToken = apiToken;
    }

    @Override
    public Bom analyze(Bom bom) throws InterruptedException {
        for (final Component component : bom.getComponentsList()) {
            componentMap.put(getEfossId(component), component);
            // break;
        }

        LOGGER.info("SIZE IS {}", componentMap.size());

        // TODO: Decide if we like this endpoint or if we want to use getFossComponentRecordsByPurl
        // or if we want to use one as a backup in case the other fails for some reason
        StringBuilder builder = new StringBuilder("{\"query\": \"query { fossComponentRecords(ids: [");
        for(Iterator<Component> itr = componentMap.values().iterator(); itr.hasNext();) {
            Component current = itr.next();
            builder.append("\\\"");
            builder.append(getEfossId(current));
            if(itr.hasNext())
                builder.append("\\\", ");
            else
                builder.append("\\\"]) {id group licenseIds licenses {licenseId licenseName} purl useCaseRisk { distribution use internalCombining }}}\"}");
        }
        String schema = builder.toString();

        String credentials = apiUsername + ":" + apiToken;
        String encodedCredentials = Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        // LOGGER.info("SCHEMA IS {}", schema);
 
        HttpRequest request = HttpRequest.newBuilder()
            .uri(java.net.URI.create(API_URL))
            .header("authorization", "Basic " + encodedCredentials)
            .header("content-type", "application/json")
            .method("POST", HttpRequest.BodyPublishers.ofString(schema))
            .build();


        final HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            // LOGGER.info("RESPONSE BODY {}", response.body());
        } catch (IOException e) {
            throw new UncheckedIOException("eFOSS API request to %s failed".formatted(API_URL), e);
        }

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return assembleVdr(response.body());
        }

        throw new IllegalStateException(
                "eFOSS API request to %s failed with status %d".formatted(API_URL, response.statusCode()));
    }

    private String getEfossId(Component component){
        // TODO: Rely on purl as a backup to the pieces of the component
        try {
            PackageURL purl = new PackageURL(component.getPurl());
            StringBuilder builder = new StringBuilder(purl.getType());
            builder.append(":");
            builder.append(component.getGroup());
            builder.append(":");
            builder.append(purl.getName());
            builder.append(":");
            builder.append(purl.getVersion());
            return builder.toString();
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Encountered invalid PURL", e);
            return "ErrorId";
        }
    }

    private Bom assembleVdr(String responseBody){
        Gson gson = new Gson();
        Response response = gson.fromJson(responseBody, Response.class);

        for(FossComponentRecords currentRecord : response.data.fossComponentRecords) {
            List<Component> matchList = componentMap.values().stream().filter(comp -> currentRecord.id.equals(getEfossId(comp))).toList();
            Component match = matchList.get(0);

            List<LicenseChoice> testingList = match.getLicensesList();

            for(LicenseChoice heremst : testingList){
                org.cyclonedx.proto.v1_7.License idkman = heremst.getLicense();
            }
            
            ArrayList<LicenseChoice> choiceList = new ArrayList();
            for(License currentLicense : currentRecord.licenses){
                org.cyclonedx.proto.v1_7.License tempLicense = org.cyclonedx.proto.v1_7.License.newBuilder()
                                                                    // .setId(currentLicense.id) TODO REVERT
                                                                    .setId("EPL-2.0")
                                                                    // .setName(currentLicense.name)
                                                                    .setName("Eclipse Public License 2.0")
                                                                    .build();

                LicenseChoice tempChoice = LicenseChoice.newBuilder()
                                            .setLicense(tempLicense)
                                            .build();

                choiceList.add(tempChoice);
            }

            for(LicenseChoice choice : choiceList){
                match = Component.newBuilder(match)
                                .clearLicenses()
                                .addLicenses(choice)
                                .build();
            }

            componentMap.put(currentRecord.id, match);
        }
        
        return Bom.newBuilder()
            .addAllComponents(componentMap.values())
            .build();
    }

    final class Response {
        Data data;
    }

    class Data {
        @SerializedName("fossComponentRecords")
        List<FossComponentRecords> fossComponentRecords;
    }

    final class FossComponentRecords {
        String id;
        String group;
        List<String> licenseIds;
        List<License> licenses;
        String purl;
        UseCaseRisk useCaseRisk;
    }

    final class License {
        String licenseId;
        String licenseName;
    }

    final class UseCaseRisk {
        String distribution;
        String use;
        String internalCombining;
    }
    
}