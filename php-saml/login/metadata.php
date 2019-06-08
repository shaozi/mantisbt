<?php
 
/**
 *  SAML Metadata view
 *  After you configured settings with SP information, access this page to get the
 *  metadata xml file and send it to your IDP to get their information to complete
 *  settings.
 */

require_once '../../vendor/autoload.php';

require_once './settings.php' ;

try {
    $settings = new OneLogin\Saml2\Settings($settingsInfo, true);
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);
    if (empty($errors)) {
        header('Content-Type: text/xml');
        echo $metadata;
    } else {
        throw new OneLogin\Saml2\Error(
            'Invalid SP metadata: '.implode(', ', $errors),
            OneLogin\Saml2\Error::METADATA_SP_INVALID
        );
    }
} catch (Exception $e) {
    echo $e->getMessage();
}
