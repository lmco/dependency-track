package org.dependencytrack.vulnanalysis.efoss;

import org.dependencytrack.plugin.testing.AbstractExtensionFactoryTest;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;

public class EfossAnalyzerFactoryTest extends AbstractExtensionFactoryTest<VulnAnalyzer, EfossVulnAnalyzerFactory> {
    
    EfossAnalyzerFactoryTest() {
        super(EfossVulnAnalyzerFactory.class);
    }

}
