<?php
/**
 *  SAML Handler
 */

require_once '../../core.php';

require_once '../../vendor/autoload.php';

require_once './settings.php';

$auth = new OneLogin\Saml2\Auth($settingsInfo);

if (isset($_GET['sso'])) {
    $auth->login();
    # If AuthNRequest ID need to be saved in order to later validate it, do instead
    # $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
    # $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
    # header('Pragma: no-cache');
    # header('Cache-Control: no-cache, must-revalidate');
    # header('Location: ' . $ssoBuiltUrl);
    # exit();
} else if (isset($_GET['slo'])) {
    $returnTo = null;
    $parameters = array();
    $nameId = null;
    $sessionIndex = null;
    $nameIdFormat = null;

    if (isset($_SESSION['samlNameId'])) {
        $nameId = $_SESSION['samlNameId'];
    }
    if (isset($_SESSION['samlSessionIndex'])) {
        $sessionIndex = $_SESSION['samlSessionIndex'];
    }
    if (isset($_SESSION['samlNameIdFormat'])) {
        $nameIdFormat = $_SESSION['samlNameIdFormat'];
    }

    $auth->logout($returnTo, $parameters, $nameId, $sessionIndex, false, $nameIdFormat);

    # If LogoutRequest ID need to be saved in order to later validate it, do instead
    # $sloBuiltUrl = $auth->logout(null, $paramters, $nameId, $sessionIndex, true);
    # $_SESSION['LogoutRequestID'] = $auth->getLastRequestID();
    # header('Pragma: no-cache');
    # header('Cache-Control: no-cache, must-revalidate');
    # header('Location: ' . $sloBuiltUrl);
    # exit();
} else if (isset($_GET['acs'])) {
    if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
        $requestID = $_SESSION['AuthNRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processResponse($requestID);

    $errors = $auth->getErrors();

    if (!empty($errors)) {
        echo '<p>', implode(', ', $errors), '</p>';
    }

    if (!$auth->isAuthenticated()) {
        echo "<p>Not authenticated</p>";
        exit();
    }

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();
    unset($_SESSION['AuthNRequestID']);
    if (isset($_POST['RelayState']) && OneLogin\Saml2\Utils::getSelfURL() != $_POST['RelayState']) {
        $auth->redirectTo($_POST['RelayState']);
    }
} else if (isset($_GET['sls'])) {
    if (isset($_SESSION) && isset($_SESSION['LogoutRequestID'])) {
        $requestID = $_SESSION['LogoutRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processSLO(false, $requestID);
    $errors = $auth->getErrors();
    if (empty($errors)) {
        header('Location: ?sso');
        #echo '<p>Sucessfully logged out</p>';
    } else {
        echo '<p>', implode(', ', $errors), '</p>';
    }
}

if (isset($_SESSION['samlUserdata'])) {
    $user_email = '';

    $user_firstname = '';
    $user_lastname = '';
    if (!empty($_SESSION['samlUserdata'])) {
        $attributes = $_SESSION['samlUserdata'];
        foreach ($attributes as $attributeName => $attributeValues) {
            switch ($attributeName) {
                case 'email':
                    $user_email = $attributeValues[0];
                    break;
                case 'firstname':
                    $user_firstname = $attributeValues[0];
                    break;
                case 'lastname':
                    $user_lastname = $attributeValues[0];
                    break;
                default:
                    error_log('Attribute Name: ' . htmlentities($attributeName));
                    foreach ($attributeValues as $attributeValue) {
                        error_log('Value: ' . htmlentities($attributeValue));
                    }
            }
        }
        $user_realname = $user_firstname . ' ' . $user_lastname;
        # this is the username
        $p_username = $_SESSION['samlNameId'];
        $t_user_id = user_get_id_by_name($p_username);
        if (false === $t_user_id) {
            # attempt to create the user
            $t_cookie_string = user_create($p_username, '', $user_email, 20, false, true, $user_realname);
            if (false === $t_cookie_string) {
                return false;
            }
            # ok, we created the user, get the row again
            $t_user_id = user_get_id_by_name($p_username);
            if (false === $t_user_id) {
                return false;
            }
            error_log("new user $p_username is created");
        } else {
            // update user real name if user already exists
            if ($user_realname) {
                user_set_realname($t_user_id, $user_realname);
            }
            if ($user_email) {
                user_set_email($t_user_id, $user_email);
            }
        }
        # check for disabled account
        if (!user_is_enabled($t_user_id)) {
            return false;
        }
        auth_set_cookies($t_user_id, $p_perm_login);
        auth_set_tokens($t_user_id);
        header('Location: /my_view_page.php');
    } else {
        error_log("You don't have any attribute");
    }

    echo '<p><a href="?slo" >Logout</a></p>';
} else {
    echo '<p><a href="?sso" >Login</a></p>';
    #echo '<p><a href="?sso2" >Login and access to attrs.php page</a></p>';
}
