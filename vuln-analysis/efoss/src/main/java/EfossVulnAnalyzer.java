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
import com.github.packageurl.PackageURLBuilder;

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

    EfossVulnAnalyzer(
            HttpClient httpClient,
            String apiUsername,
            String apiToken) {
        this.httpClient = httpClient;
        this.apiUsername = apiUsername;
        this.apiToken = apiToken;
    }

    @Override // TODO: Investigate the daily exports
    public Bom analyze(Bom bom) throws InterruptedException {
        final ArrayList<Component> finalComps = new ArrayList();
        List<Component> notFound = callGetComponentRecordsByPurl(bom.getComponentsList(), finalComps);
        callFossComponentRecords(notFound, finalComps);

        return Bom.newBuilder()
            .addAllComponents(finalComps)
            .build();
    }

    private ArrayList<Component> callGetComponentRecordsByPurl(List<Component> compsToQuery, ArrayList<Component> finalComps) throws InterruptedException {
        final HashMap<String, Component> workingMap = new HashMap();
        final ArrayList<Component> notFound = new ArrayList();

        for (int x = 0; x<compsToQuery.size(); x++) {
            Component component = compsToQuery.get(x);
            try {
                PackageURL compPurl = new PackageURL(component.getPurl());
                // eFOSS doesn't support qualifiers, so rebuild the PURL
                PackageURL rebuiltPurl = PackageURLBuilder.aPackageURL()
                                            .withType(compPurl.getType())
                                            .withNamespace(compPurl.getNamespace())
                                            .withName(compPurl.getName())
                                            .withVersion(compPurl.getVersion())
                                            .withSubpath(compPurl.getSubpath())
                                            .build();
                workingMap.put(rebuiltPurl.toString(), component);
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
                return new ArrayList<>();
            }

            if(workingMap.size() == 50 || x == compsToQuery.size()-1){ // 50 is the eFOSS limit
                StringBuilder builder = new StringBuilder("{\"query\": \"query { getFossComponentRecordsByPurl(componentsPurl: [");
                for(Iterator<String> itr = workingMap.keySet().iterator(); itr.hasNext();) {
                    String current = itr.next();
                    builder.append("\\\"");
                    builder.append(current);
                    if(itr.hasNext())
                        builder.append("\\\", ");
                    else
                        builder.append("\\\"]) {id purl licenses {licenseId licenseName} useCaseRisk { distribution use internalCombining }}}\"}");
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
                } catch (IOException e) {
                    throw new UncheckedIOException("eFOSS API request to %s failed".formatted(API_URL), e);
                }

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    extractLicensesPurl(response.body(), workingMap, finalComps, notFound);
                    workingMap.clear();
                } else{
                    throw new IllegalStateException(
                        "eFOSS API request to %s failed with status %d".formatted(API_URL, response.statusCode()));
                }
            }
        }

        return notFound;
    }

    private void callFossComponentRecords(List<Component> compsToQuery, ArrayList<Component> finalComps) throws InterruptedException {
        final HashMap<String, Component> workingMap = new HashMap();

        for (int x = 0; x<compsToQuery.size(); x++) {
            Component component = compsToQuery.get(x);
            workingMap.put(getEfossId(component), component);

            if(workingMap.size() == 50 || x == compsToQuery.size()-1){ // 50 is the eFOSS limit
                StringBuilder builder = new StringBuilder("{\"query\": \"query { fossComponentRecords(ids: [");
                for(Iterator<String> itr = workingMap.keySet().iterator(); itr.hasNext();) {
                    String current = itr.next();
                    builder.append("\\\"");
                    builder.append(current);
                    if(itr.hasNext())
                        builder.append("\\\", ");
                    else
                        builder.append("\\\"]) {id licenses {licenseId licenseName} useCaseRisk { distribution use internalCombining }}}\"}");
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
                } catch (IOException e) {
                    throw new UncheckedIOException("eFOSS API request to %s failed".formatted(API_URL), e);
                }

                if (response.statusCode() >= 200 && response.statusCode() < 300) {
                    extractLicensesRecords(response.body(), workingMap, finalComps);
                    workingMap.clear();
                } else{
                    throw new IllegalStateException(
                        "eFOSS API request to %s failed with status %d".formatted(API_URL, response.statusCode()));
                }
            }
        }
    }

    private String getEfossId(Component component){
        try {
            PackageURL purl = new PackageURL(component.getPurl());
            StringBuilder builder = new StringBuilder(purl.getType());
            builder.append(":");
            builder.append(component.getGroup());
            builder.append(":");
            builder.append(component.getName());
            builder.append(":");
            builder.append(component.getVersion());
            return builder.toString().toLowerCase();
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Encountered invalid PURL", e);
            return "ErrorId";
        }
    }

    private void extractLicensesPurl(String responseBody, HashMap<String, Component> workingMap, ArrayList<Component> finalComps, ArrayList<Component> notFound){
        Gson gson = new Gson();
        Response response = gson.fromJson(responseBody, Response.class);
        HashMap<String, Component> noMatchMap = new HashMap();

        List<FossComponentRecords> fossComponentRecords = response.data.fossComponentRecords;
        for(final String currentKeyId : workingMap.keySet()) {

            List<FossComponentRecords> matchList = fossComponentRecords.stream().filter(record -> record.purl.toLowerCase().equals(currentKeyId)).toList();
            if(matchList.size() > 0){ // Items not already in eFOSS will not have a match

                ArrayList<LicenseChoice> choiceList = new ArrayList();
                for(License currentLicense : matchList.get(0).licenses){

                    org.cyclonedx.proto.v1_7.License tempLicense = org.cyclonedx.proto.v1_7.License.newBuilder()
                        .setId(currentLicense.licenseId)
                        .setName(currentLicense.licenseName)
                        // .setId("EPL-2.0")
                        // .setName("Eclipse Public License 2.0")
                        .build();

                    LicenseChoice tempChoice = LicenseChoice.newBuilder()
                                            .setLicense(tempLicense)
                                            .build();

                    choiceList.add(tempChoice);
                }

                // Proto Components must be edited via recreation unless we want to edit the protos themselves
                // Rebuild once to clear licenses
                Component matchedComp = Component.newBuilder(workingMap.get(currentKeyId))
                        .clearLicenses()
                        .build();

                // Rebuild in a loop to add licenses. Method is deceiving name wise as
                // the actual proto implementation only has one License per LicenseChoice.
                for(LicenseChoice choice : choiceList){
                    matchedComp = Component.newBuilder(matchedComp)
                        .addLicenses(choice)
                        .build();
                }

                finalComps.add(matchedComp);

            } else {
                notFound.add(workingMap.get(currentKeyId));
            }
        }
    }

    private void extractLicensesRecords(String responseBody, HashMap<String, Component> workingMap, ArrayList<Component> finalComps){
        Gson gson = new Gson();
        Response response = gson.fromJson(responseBody, Response.class);
        HashMap<String, Component> noMatchMap = new HashMap();

        List<FossComponentRecords> fossComponentRecords = response.data.fossComponentRecords;
        for(final String currentKeyId : workingMap.keySet()) {

            List<FossComponentRecords> matchList = fossComponentRecords.stream().filter(record -> record.id.toLowerCase().equals(currentKeyId)).toList();
            if(matchList.size() > 0){ // Items not already in eFOSS will not have a match

                ArrayList<LicenseChoice> choiceList = new ArrayList();
                for(License currentLicense : matchList.get(0).licenses){

                    org.cyclonedx.proto.v1_7.License tempLicense = org.cyclonedx.proto.v1_7.License.newBuilder()
                        .setId(currentLicense.licenseId)
                        .setName(currentLicense.licenseName)
                        // .setId("EPL-2.0")
                        // .setName("Eclipse Public License 2.0")
                        .build();

                    LicenseChoice tempChoice = LicenseChoice.newBuilder()
                                            .setLicense(tempLicense)
                                            .build();

                    choiceList.add(tempChoice);
                }

                // Proto Components must be edited via recreation unless we want to edit the protos themselves
                // Rebuild once to clear licenses
                Component matchedComp = Component.newBuilder(workingMap.get(currentKeyId))
                        .clearLicenses()
                        .build();

                // Rebuild in a loop to add licenses. Method is deceiving name wise as
                // the actual proto implementation only has one License per LicenseChoice.
                for(LicenseChoice choice : choiceList){
                    matchedComp = Component.newBuilder(matchedComp)
                        .addLicenses(choice)
                        .build();
                }

                finalComps.add(matchedComp);

            } else {
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
        @SerializedName(value="fossComponentRecords", alternate={"getFossComponentRecordsByPurl"})
        List<FossComponentRecords> fossComponentRecords;
    }

    final class FossComponentRecords {
        String id;
        String purl;
        List<License> licenses;
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