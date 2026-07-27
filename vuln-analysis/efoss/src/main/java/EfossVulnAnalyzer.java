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
import java.util.Set;
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
    private final HashMap<String, Component> workingMap = new HashMap();
    private final ArrayList<Component> finalComps = new ArrayList();

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
        LOGGER.info("OVERALL SIZE IS {}", bom.getComponentsList().size());
        for (int x = 0; x<bom.getComponentsList().size(); x++) {
            Component component = bom.getComponentsList().get(x);
            workingMap.put(getEfossId(component), component);
            // LOGGER.info("X IS {} AND SIZE IS {} AND EFOSSID IS {}", x, workingMap.size(), getEfossId(component));
            // LOGGER.info("CONDITIONS ARE {} AND {}", workingMap.size() == 50, x == bom.getComponentsList().size()-1);

            if(workingMap.size() == 50 || x == bom.getComponentsList().size()-1){ // 50 is the eFOSS limit
                LOGGER.info("MAP SIZE AS WE START IS {} AND X IS {}", workingMap.size(), x);
                // TODO: Decide if we like this endpoint or if we want to use getFossComponentRecordsByPurl
                // or if we want to use one as a backup in case the other fails for some reason
                // TODO: Also investigate the daily exports
                StringBuilder builder = new StringBuilder("{\"query\": \"query { fossComponentRecords(ids: [");
                for(Iterator<Component> itr = workingMap.values().iterator(); itr.hasNext();) {
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
        
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(java.net.URI.create(API_URL))
                    .header("authorization", "Basic " + encodedCredentials)
                    .header("content-type", "application/json")
                    .method("POST", HttpRequest.BodyPublishers.ofString(schema))
                    .build();


                final HttpResponse<String> response;
                try {
                    response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    LOGGER.info("RECEIVED RESPONSE");
                } catch (IOException e) {
                    throw new UncheckedIOException("eFOSS API request to %s failed".formatted(API_URL), e);
                }

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    extractLicenses(response.body());
                    workingMap.clear();
                } else{
                    throw new IllegalStateException(
                        "eFOSS API request to %s failed with status %d".formatted(API_URL, response.statusCode()));
                }
            }
        }
        LOGGER.info("ABOUT TO RETURN");
        return Bom.newBuilder()
            .addAllComponents(finalComps)
            .build();
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
            return builder.toString().toLowerCase();
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Encountered invalid PURL", e);
            return "ErrorId";
        }
    }

    private void extractLicenses(String responseBody){
        Gson gson = new Gson();
        Response response = gson.fromJson(responseBody, Response.class);
        HashMap<String, Component> noMatchMap = new HashMap();

        List<FossComponentRecords> fossComponentRecords = response.data.fossComponentRecords;
        for(final String currentKeyId : workingMap.keySet()) {

            List<FossComponentRecords> matchList = fossComponentRecords.stream().filter(record -> record.id.toLowerCase().equals(currentKeyId)).toList();
            if(matchList.size() > 0){ // Items not already in eFOSS will not have a match
                LOGGER.info("MATCHLIST SIZE IS {}", matchList.size());
                ArrayList<LicenseChoice> choiceList = new ArrayList();
                for(License currentLicense : matchList.get(0).licenses){

                    org.cyclonedx.proto.v1_7.License tempLicense = org.cyclonedx.proto.v1_7.License.newBuilder()
                        // .setId(currentLicense.licenseId)
                        // .setName(currentLicense.licenseName)
                        .setId("EPL-2.0")
                        .setName("Eclipse Public License 2.0")
                        .build();

                    LicenseChoice tempChoice = LicenseChoice.newBuilder()
                                            .setLicense(tempLicense)
                                            .build();

                    choiceList.add(tempChoice);
                }

                // Proto Components must be edited via recreation unless we want to edit the protos themselves
                // Rebuild once to clear licenses
                if(currentKeyId.equals("maven:org.slf4j:slf4j-api:2.0.17")){
                    Component DEBUG = workingMap.get(currentKeyId);
                    LOGGER.info("SLF4J LICENSE SIZE IS {}", DEBUG.getLicensesCount());
                    List<LicenseChoice> stupidList = DEBUG.getLicensesList();
                    LicenseChoice stupidChoice = stupidList.get(0);
                    org.cyclonedx.proto.v1_7.License stupidLice = stupidChoice.getLicense();
                    LOGGER.info("SLF4J LICENSE 0 IS {}", stupidLice.getName());
                }
                Component matchedComp = Component.newBuilder(workingMap.get(currentKeyId))
                        .clearLicenses()
                        .build();
                if(currentKeyId.equals("maven:org.slf4j:slf4j-api:2.0.17")){
                    LOGGER.info("CLEARED SLF4J LICENSE SIZE IS {}", matchedComp.getLicensesCount());
                }
                // Rebuild in a loop to add licenses. Method is deceiving name wise as
                // the actual proto implementation only has one License per LicenseChoice.
                for(LicenseChoice choice : choiceList){
                    matchedComp = Component.newBuilder(matchedComp)
                        .addLicenses(choice)
                        .build();
                }
                if(currentKeyId.equals("maven:org.slf4j:slf4j-api:2.0.17")){
                    LOGGER.info("POST LICENSE SIZE IS {}", matchedComp.getLicensesCount());
                    org.cyclonedx.proto.v1_7.License stupidLice = matchedComp.getLicensesList().get(0).getLicense();
                    LOGGER.info("POST LICENSE 0 IS {}", stupidLice.getName());
                }
                workingMap.put(currentKeyId, matchedComp);

            } else {
                LOGGER.info("NO EFOSS MATCH FOR {}", currentKeyId);
                // Clear licenses of all the components that didn't have a corresponding eFOSS entry
                Component compToClear = Component.newBuilder(workingMap.get(currentKeyId))
                    .clearLicenses()
                    .build();

                finalComps.add(compToClear);
            }
        }
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