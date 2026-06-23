package org.dependencytrack.vulnanalysis.efoss;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.proto.v1_7.Component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class EfossRequestObject {

    private static final Logger LOGGER = LoggerFactory.getLogger(EfossRequestObject.class);

    private PackageURL purl;
    private String efossID;
    // private LicenseChoice licenseChoice = new LicenseChoice();

    EfossRequestObject(Component component) {
        try {
            this.purl = new PackageURL(component.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Encountered invalid PURL", e);
        }
        
        StringBuilder builder = new StringBuilder(purl.getType());
        builder.append(component.getGroup());
        builder.append(purl.getName());
        builder.append(purl.getVersion());
        this.efossID = builder.toString();
    }

    public String getEfossId(){
        return efossID;
    }
}