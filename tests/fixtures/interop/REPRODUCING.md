# Reproducing the external Redirect captures

These recipes reproduce the producer path and wire shape, not the exact
committed bytes. Shibboleth generates a fresh key, message ID, timestamp,
session index, encrypted identifier, port, and signature on every run.
SimpleSAMLphp uses the committed test key, but the committed message values
are deliberately fixed by the capture script.

Never use the fixture keys outside tests.

## Shibboleth IdP 5.2.3

The capture used the official IdP integration suite at commit
`948a900d78e58b41fbeedf6b2557e3ce17229d69`. Its POM was changed from the
development snapshots to the following release versions:

```diff
-        <version>17.2.3-SNAPSHOT</version>
+        <version>17.2.3</version>
@@
-        <idp.version>5.2.3-SNAPSHOT</idp.version>
+        <idp.version>5.2.3</idp.version>
@@
-        <opensaml.version>5.2.3-SNAPSHOT</opensaml.version>
+        <opensaml.version>5.2.3</opensaml.version>
```

The build used this Maven settings file:

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <profiles>
    <profile>
      <id>shibboleth-repositories</id>
      <repositories>
        <repository>
          <id>shibboleth-releases</id>
          <url>https://build.shibboleth.net/maven/releases/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
        <repository>
          <id>shibboleth-snapshots</id>
          <url>https://build.shibboleth.net/maven/snapshots/</url>
          <releases><enabled>false</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>shibboleth-releases</id>
          <url>https://build.shibboleth.net/maven/releases/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>shibboleth-snapshots</id>
          <url>https://build.shibboleth.net/maven/snapshots/</url>
          <releases><enabled>false</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>shibboleth-repositories</activeProfile>
  </activeProfiles>
</settings>
```

The resolved testbed was snapshot `5.2.3-20260617.132935-11`. Its POM names
the development parent `17.2.3-SNAPSHOT`; the release parent POM was therefore
also placed at that coordinate in the isolated Maven repository:

```bash
mkdir -p "$M2_REPOSITORY/net/shibboleth/parent/17.2.3-SNAPSHOT"
curl --fail --location \
  https://build.shibboleth.net/maven/releases/net/shibboleth/parent/17.2.3/parent-17.2.3.pom \
  --output "$M2_REPOSITORY/net/shibboleth/parent/17.2.3-SNAPSHOT/parent-17.2.3-SNAPSHOT.pom"
```

The disabled `testSLO` method in
`SAML2SSORedirectIntegrationTest.java` was replaced by the capture below.
The listed imports and constructor were added to the same class. No IdP,
OpenSAML, or testbed implementation source was changed.

```java
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.logging.Level;

import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.Point;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.logging.LoggingPreferences;
import org.openqa.selenium.support.ui.WebDriverWait;

public SAML2SSORedirectIntegrationTest() {
    hostname = "localhost";
}

@Override
public void startBrowser() {
    final LoggingPreferences logging = new LoggingPreferences();
    logging.enable(LogType.PERFORMANCE, Level.ALL);

    final ChromeOptions options = new ChromeOptions();
    options.setAcceptInsecureCerts(true);
    options.addArguments("--headless=new");
    options.setCapability("goog:loggingPrefs", logging);

    driver = new ChromeDriver(options);
    driver.manage().window().setPosition(new Point(0, 0));
    driver.manage().window().setSize(new Dimension(1024, 768));
    setUpImplicitWait();
}

@Test
public void captureIdPInitiatedSLO() throws Exception {
    startBrowser();
    enableLogout();
    startServer();

    startFlow();
    waitForLoginPage();
    login();
    waitForAttributeReleasePage();
    releaseAllAttributes();
    rememberConsent();
    submitForm();
    waitForResponsePage();
    validateResponse();

    driver.get(getBaseURL() + "/idp/profile/Logout");
    new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(d -> d.findElement(By.id("logout_propagate")).isDisplayed());
    driver.findElement(By.id("logout_propagate")).click();
    new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(d -> !d.findElements(By.cssSelector("iframe[id^='sender_']")).isEmpty());
    Thread.sleep(3_000);

    final String output = driver.manage().logs().get(LogType.PERFORMANCE).getAll().stream()
            .map(LogEntry::getMessage)
            .reduce("", (left, right) -> left + right + System.lineSeparator());
    Files.writeString(Path.of("/tmp/saml-rs-interop/shibboleth-performance.jsonl"), output);

    final Path captureDirectory = Path.of("/tmp/saml-rs-interop/shibboleth-capture");
    Files.createDirectories(captureDirectory);
    Files.copy(pathToIdPHome.resolve("credentials/idp-signing.crt"),
            captureDirectory.resolve("idp-signing.crt"), StandardCopyOption.REPLACE_EXISTING);
    Files.copy(pathToIdPHome.resolve("credentials/idp-signing.key"),
            captureDirectory.resolve("idp-signing.key"), StandardCopyOption.REPLACE_EXISTING);
}
```

With Temurin `17.0.19+10`, Maven `3.9.16`, and Chrome
`150.0.7871.129`, the exact invocation was:

```bash
JAVA_HOME="$TEMURIN_17_HOME" "$MAVEN_3_9_16_HOME/bin/mvn" \
  -ntp \
  -s "$CAPTURE_ROOT/maven-settings.xml" \
  -Dmaven.repo.local="$M2_REPOSITORY" \
  -Dserver.address=localhost \
  '-Dtest=net.shibboleth.idp.integration.tests.saml2.SAML2SSORedirectIntegrationTest#captureIdPInitiatedSLO' \
  test
```

The build reported one successful TestNG test. The SLO URL was selected from
Chrome's JSON-lines performance log and reduced to its exact query string:

```bash
node -e 'const fs=require("fs"); for(const line of fs.readFileSync(process.argv[1],"utf8").trim().split("\n")){const u=new URL(JSON.parse(line).message.params?.request?.url||"https://invalid"); if(u.pathname.endsWith("/sp/SAML2/Redirect/SLO")&&u.searchParams.has("SAMLRequest")){fs.writeFileSync(process.argv[2],u.search.slice(1)+"\n");}}' \
  /tmp/saml-rs-interop/shibboleth-performance.jsonl \
  /tmp/saml-rs-interop/shibboleth-capture/logout-request.query
```

The run used the official product distribution and testbed; the Java change
only drove the browser and copied emitted data.

## SimpleSAMLphp 2.5.2

The official full archive was downloaded and verified:

```bash
curl --fail --location \
  https://github.com/simplesamlphp/simplesamlphp/releases/download/v2.5.2/simplesamlphp-2.5.2-full.tar.gz \
  --output simplesamlphp-2.5.2-full.tar.gz
printf '%s  %s\n' \
  1394883cc15fb532b9cbac899377caac72163aaab964c0c67a793a69142a8902 \
  simplesamlphp-2.5.2-full.tar.gz | sha256sum --check
tar -xzf simplesamlphp-2.5.2-full.tar.gz
```

The capture script had SHA-256
`5daa64da0e3175dccc44b5872ede1bcdbc1b54cd043386643ff7c8baed22af4c`
and contained:

```php
<?php

declare(strict_types=1);

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Constants;
use SAML2\HTTPRedirect;
use SAML2\XML\saml\NameID;
use SimpleSAML\Configuration;
use SimpleSAML\Module\saml\Message;

require '/var/simplesamlphp/vendor/autoload.php';

Configuration::loadFromArray(
    [
        'certdir' => '/fixtures',
        'logging.level' => 'error',
    ],
    'public fixture generation config',
    'simplesaml',
);

$spMetadata = Configuration::loadFromArray(
    [
        'entityid' => 'https://sp.example.test/saml2',
        'privatekey' => 'sp-signing-key.pem',
        'certificate' => 'sp-signing-cert.pem',
        'sign.logout' => true,
        'signature.algorithm' => XMLSecurityKey::RSA_SHA256,
    ],
    'configured SimpleSAMLphp SP',
);
$idpMetadata = Configuration::loadFromArray(
    [
        'entityid' => 'https://idp.example.test/metadata',
        'sign.logout' => true,
    ],
    'remote IdP metadata',
);

$request = Message::buildLogoutRequest($spMetadata, $idpMetadata);
$request->setId('_simplesamlphp-sp-redirect-logout-request');
$request->setIssueInstant(strtotime('2026-07-24T06:05:00Z'));
$request->setDestination('https://idp.example.test/slo/redirect');
$request->setRelayState('simplesamlphp-sp-state');

$nameId = new NameID();
$nameId->setFormat(Constants::NAMEID_PERSISTENT);
$nameId->setValue('bob@example.test');
$request->setNameId($nameId);
$request->setSessionIndexes([
    '_simplesamlphp-session-20260724',
    '_simplesamlphp-session-secondary',
]);

$binding = new HTTPRedirect();
echo $binding->getRedirectURL($request), PHP_EOL;
```

The fixture directory mounted at `/fixtures` contained the committed
`sp-signing-key.pem` and `sp-signing-cert.pem`. The full product release was
mounted read-only and the script was run in the pinned PHP image:

```bash
docker run --rm \
  --mount "type=bind,src=$SIMPLESAMLPHP_ROOT,dst=/var/simplesamlphp,readonly" \
  --mount "type=bind,src=$FIXTURE_DIRECTORY,dst=/fixtures,readonly" \
  --mount "type=bind,src=$CAPTURE_SCRIPT,dst=/fixture.php,readonly" \
  php@sha256:2a3f699b6cb31e5638c5432e4d37d4047853ba6351a692c91e0a073af00a55cc \
  php /fixture.php
```

The part after `?` in the single emitted URL is the committed
`logout-request.query`.
