<?php
//* File obtained from https://github.com/imsamuka/whmcs-azuracast
//* Licensed under GPL-2. Any changes should be available publicly
//
// NOTE: As of writing, AzuraCast doesn't have a Single Sign-On (SSO) feature.
// So, AdminLink return a post-form with username|password

if (!defined("WHMCS"))
    exit("This file cannot be accessed directly.");

require_once __DIR__ . "/vendor/autoload.php";

use WHMCS\Database\Capsule;
use \AzuraCast\Api\Client;
use \AzuraCast\Api\Dto\UserDto;
use \AzuraCast\Api\Dto\StationDto;
use \AzuraCast\Api\Dto\RoleDto;

define("STATION_ID_FIELD", "Station ID");
define("USER_ID_FIELD", "User ID");
define("ROLE_ID_FIELD", "Role ID");

function azuracast_MetaData()
{
    return [
        "DisplayName" => "AzuraCast",
        "APIVersion" => "1.1",
        "RequiresServer" => true,
        "ListAccountsUniqueIdentifierDisplayName" => "Domain",
        "ListAccountsUniqueIdentifierField" => "domain",
    ];
}

function azuracast_ConfigOptions()
{
    return [
        "Station to Clone" => [
            "Type" => "text",
            "Size" => "4",
            "Default" => "1",
            "Description" => "Enter the 'Station ID' of the station that will be cloned for each user.",
        ],
        "Station Name Template" => [
            "Type" => "text",
            "Size" => "50",
            "Default" => "{user_name} Radio",
            "Description" => "The template used in the name of the Station for each user. \"{user_name}\" is replaced by the user firstname",
        ],
    ];
}

function azuracast_ClientLink($params)
{
    // return ('<form action="' . get_host($params) . '/login" method="post" target="_blank">')
    //     . ('<input type="hidden" name="username" value="' . $params["username"] . '">')
    //     . ('<input type="hidden" name="password" value="' . $params["password"] . '">')
    //     . '<input type="submit" value="Login to AzuraCast Panel"/></form>';
    return get_host($params) . "/login";
}

function azuracast_AdminLink($params)
{
    $has_login = $params["serverusername"] && $params["serverpassword"];

    return ('<form target="_blank" action="' . get_host($params) . '/login"')
        . ('method="' . ($has_login ? "post" : "get") . '">')
        . (!$has_login ? "" : '<input type="hidden" name="username" value="' . $params["serverusername"] . '">')
        . (!$has_login ? "" : '<input type="hidden" name="password" value="' . $params["serverpassword"] . '">')
        . '<input type="submit" value="Login to AzuraCast Panel"/></form>';
}

function azuracast_CreateAccount($params)
{
    // Admin Configurable
    $default_station_id = to_id($params["configoption1"]);
    $station_name_template = $params["configoption2"] ?? "{user_name} Station";
    $station_permissions = [
        // "administer all",
        // "manage station podcasts",
        // "manage station web hooks",
        // "manage station automation",
        // "manage station media",
        // "manage station streamers",
        // "manage station mounts",
        // "manage station remotes",
        // "manage station broadcasting",
        // "manage station profile",
        "view station logs",
        "view station reports",
        "view station management"
    ];

    // User data
    $name = $params["clientsdetails"]["firstname"];
    $email = $params["clientsdetails"]["email"];
    $password = $params["password"];


    if (!valid_id($default_station_id))
        return ["status" => "error", "description" => "default station_id is invalid"];
    if (is_null($email))
        return ["status" => "error", "description" => "account email is null"];
    if (is_null($name))
        return ["status" => "error", "description" => "account firstname is null"];

    $api = get_api($params);
    $station_name = str_replace("{user_name}", $name, $station_name_template);

    $station_id = to_id($params["model"]->serviceProperties->get(STATION_ID_FIELD));
    $role_id = to_id($params["model"]->serviceProperties->get(ROLE_ID_FIELD));
    $user_id = to_id($params["model"]->serviceProperties->get(USER_ID_FIELD));

    try {
        // Create station
        if (valid_id($station_id)) {
            try {
                $station_dto = $api->station($station_id)->get();
            } catch (\Exception $e) {
                logModuleCall('azuracast', __FUNCTION__, $params, "station_id of user didn't exist in the server.");
                $station_id = null;
            }
        }
        if (!$station_id) {
            $station_dto = clone_station($api, $default_station_id, $station_name);
            $station_id = $station_dto->getId();
            $params["model"]->serviceProperties->save([STATION_ID_FIELD => $station_id]);
        }


        // Create role
        if (valid_id($role_id)) {
            try {
                $role_dto = $api->admin()->roles()->get($role_id);
            } catch (\Exception $e) {
                logModuleCall('azuracast', __FUNCTION__, $params, "role_id of user didn't exist in the server.");
                $role_id = null;
            }
        }
        if (!$role_id) {
            $role_dto = $api->admin()->roles()->create($station_name, [], [
                $station_id => $station_permissions
            ]);
            $role_id = $role_dto->getId();
            $params["model"]->serviceProperties->save([ROLE_ID_FIELD => $role_id]);
        }


        // Create user
        if (valid_id($user_id)) {
            try {
                $user_dto = $api->admin()->users()->get($user_id);
            } catch (\Exception $e) {
                logModuleCall('azuracast', __FUNCTION__, $params, "user_id of user didn't exist in the server.");
                $user_id = null;
            }
        }
        if (!$user_id) {
            $roles = [strval($role_dto->getId())];
            $user_dto = search_user_by_email($api, $email);
            if ($user_dto) {
                change_roles($api, $user_dto, $roles);
            } else {
                $user_dto = $api->admin()->users()->create($email, $password, $name, "", "", $roles, []);
            }
            $user_id = $user_dto->getId();
            $params["model"]->serviceProperties->save([USER_ID_FIELD => $user_id]);
        }

    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
        return ["status" => "error", "description" => $e->getMessage()];
    }
    return "success";
}

function azuracast_TerminateAccount($params)
{
    $api = get_api($params);

    try {
        $user_id = to_id($params["model"]->serviceProperties->get(USER_ID_FIELD));
        if (valid_id($user_id)) {
            $api->admin()->users()->delete($user_id);
            $params["model"]->serviceProperties->save([USER_ID_FIELD => null]);
        }
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
    }

    try {
        $role_id = to_id($params["model"]->serviceProperties->get(ROLE_ID_FIELD));
        if (valid_id($role_id)) {
            $api->admin()->roles()->delete($role_id);
            $params["model"]->serviceProperties->save([ROLE_ID_FIELD => null]);
        }
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
    }

    try {
        $station_id = to_id($params["model"]->serviceProperties->get(STATION_ID_FIELD));
        if (valid_id($station_id)) {
            $api->request("DELETE", "admin/station/" . strval($station_id), []);
            $params["model"]->serviceProperties->save([STATION_ID_FIELD => null]);
        }
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
    }

    return "success";
}

function azuracast_SuspendAccount($params)
{
    $api = get_api($params);
    $user_id = to_id($params["model"]->serviceProperties->get(USER_ID_FIELD));
    $station_id = to_id($params["model"]->serviceProperties->get(STATION_ID_FIELD));
    $role_id = to_id($params["model"]->serviceProperties->get(ROLE_ID_FIELD));
    try {
        $status = $api->station($station_id)->status();

        // remove only the $role_id
        {
            $user_dto = $api->admin()->users()->get($user_id);
            $roles = array_map(function ($role) {
                return strval($role->getId());
            }, $user_dto->getRoles());

            $i = array_search($role_id, $roles);
            if ($i != false)
                array_splice($roles, $i, 1);

            change_roles($api, $user_dto, $roles, true);
        }

        if ($status->getFrontendRunning())
            $api->station($station_id)->frontend("stop");
        if ($status->getBackendRunning())
            $api->station($station_id)->backend("stop");
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
        return ["status" => "error", "description" => $e->getMessage()];
    }
    return "success";
}

function azuracast_UnsuspendAccount($params)
{
    $api = get_api($params);
    $user_id = to_id($params["model"]->serviceProperties->get(USER_ID_FIELD));
    $station_id = to_id($params["model"]->serviceProperties->get(STATION_ID_FIELD));
    $role_id = to_id($params["model"]->serviceProperties->get(ROLE_ID_FIELD));
    try {
        $status = $api->station($station_id)->status();
        $user_dto = $api->admin()->users()->get($user_id);
        change_roles($api, $user_dto, [strval($role_id)]);

        if (!$status->getFrontendRunning())
            try {
                $api->station($station_id)->frontend("start");
            } catch (\Throwable $th) {
            }

        if (!$status->getBackendRunning())
            try {
                $api->station($station_id)->backend("start");
            } catch (\Throwable $th) {
            }


    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
        return ["status" => "error", "description" => $e->getMessage()];
    }
    return "success";
}

function azuracast_ChangePassword($params)
{
    $api = get_api($params);
    $user_id = to_id($params["model"]->serviceProperties->get(USER_ID_FIELD));
    if (!valid_id($user_id))
        return ["status" => "error", "description" => "user_id is not valid"];
    try {
        change_password($api, $user_id, $params["password"]);
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
        return ["status" => "error", "description" => $e->getMessage()];
    }
    return "success";
}

function azuracast_TestConnection($params)
{
    try {
        if (!$params["serverusername"])
            throw new Exception("No Email given (in the username field)");

        $api = get_api($params);
        $users = $api->admin()->users()->list();
        foreach ($users as $user_dto) {
            $api_keys = $user_dto->getApiKeys();
            foreach ($api_keys as $api_key) {
                if (str_starts_with($params["serveraccesshash"], $api_key->getId()))
                    break;
                $api_key = null;
            }
            if ($api_key != null)
                break;
            $user_dto = null;
        }
        if ($user_dto == null)
            throw new Exception("No user have the api_key used???");
        if ($user_dto->getEmail() != $params["serverusername"])
            throw new Exception("Username/Email given doesn't match with the API Key owner");

        return ["success" => true, "error" => ""];
    } catch (Exception $e) {
        logError(__FUNCTION__, $params, $e);
        return ["success" => false, "error" => $e->getMessage()];
    }
}

function azuracast_UsageUpdate($params)
{
    $api = get_api($params);

    try {
        $stats = $api->request("GET", "admin/server/stats");
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
        return;
    }

    $bwusage = 0;

    foreach ($stats["network"] as $interface) {
        if ($interface["interface_name"] == "lo")
            continue;
        $bwusage += $interface["transmitted"]["speed"]["bytes"];
    }

    try {
        Capsule::table("tblhosting")
            ->where("server", $params["serverid"])
            // ->where("domain", $params["domain"])
            ->update([
                "diskusage" => intval($stats["disk"]["bytes"]["used"]) / 1_000_000,
                "disklimit" => intval($stats["disk"]["bytes"]["total"]) / 1_000_000,
                "bwusage" => $bwusage / 1_000_000,
                "lastupdate" => Capsule::raw("now()"),
            ]);
    } catch (\Exception $e) {
        logError(__FUNCTION__, $params, $e);
    }
}

function azuracast_AdminServicesTabFields(array $params)
{
    $api = get_api($params);
    $return = [];

    $user_id = to_id($params["model"]->serviceProperties->get(USER_ID_FIELD));
    $station_id = to_id($params["model"]->serviceProperties->get(STATION_ID_FIELD));
    $role_id = to_id($params["model"]->serviceProperties->get(ROLE_ID_FIELD));

    $role_dto = null;
    try {
        if (valid_id($user_id)) {
            $user_dto = $api->admin()->users()->get($user_id);
            $roles = $user_dto->getRoles();
            $roles_str = [];

            foreach ($roles as $role) {
                $selected = valid_id($role_id) && $role_id == $role->getId();
                $name = $role->getName();
                $id = $role->getId();

                $stations = join(array_keys($role->getPermissions()->getStation()), ",");

                $roles_str[] = "<b>{$name}</b> (id {$id})"
                    . ($stations ? " (station id {$stations})" : "")
                    . ($selected ? " - <b>Role Selected</b>" : "");

                if ($selected)
                    $role_dto = $role;
            }

            $return["Roles"] = join($roles_str, "<br>");

            if (valid_id($role_id) && !$role_dto)
                $return["Station Permissions"] = "<b>The user doesn't have the selected role.</b>"
                    . " It may be because the account is suspended.";
            else
                $return["Station Permissions"] = "<b>No 'Role ID' or 'Station ID' configured.</b>";
        } else {
            $return["Configuration"] = "<b>No 'User ID' configured.</b>"
                . "Use the <b>Search Account</b> button if this user already exists in the server"
                . " or click to <b>Create</b> a new account.";
        }


        if ($role_dto) {
            /** @var string[] */
            $permissions = $role_dto->getPermissions()->getStation()[$station_id];

            $return["Station Permissions"] = ($permissions ? join($permissions, ", ")
                : (
                    valid_id($station_id)
                    ? "<b>No permissions for the 'Station ID' in the selected Role</b>"
                    : "<b>No 'Station ID' configured</b>"
                )
            );
        }

        if (valid_id($user_id) && valid_id($station_id)) {

            $playing = $api->station($station_id)->nowPlaying();
            $station_name = $playing->getStation()->getName();

            $return["Station/Role Name"] = '<input type="hidden" name="azuracast_old_station_name" '
                . 'value="' . htmlspecialchars($station_name) . '" />'
                . '<input type="text" name="azuracast_new_station_name"'
                . 'value="' . htmlspecialchars($station_name) . '" />';

            $status = $api->station($station_id)->status();
            $return["Station Status"] = (
                "Backend: " . ($status->getBackendRunning() ? "<b>Running</b>" : "<b>Offline</b>")
                . " | Frontend: " . ($status->getFrontendRunning() ? "<b>Running</b>" : "<b>Offline</b>")
            );


            $return["Public URL"] = $playing->getStation()->getListenUrl();

            $listeners = $playing->getListeners();
            $return["Listeners"] = (
                ("Total: " . $listeners->getTotal())
                . (" | Unique: " . $listeners->getUnique())
                . (" | Current: " . $listeners->getCurrent())
            );


            $playlists = $api->request("GET", "station/{$station_id}/playlists");

            $plays_str = array_map(function ($playlist) {
                $name = $playlist["name"];
                $enabled = $playlist["is_enabled"] ? "Enabled" : "Disabled";
                $files = $playlist["num_songs"];
                $size = intval(ceil($playlist["total_length"] / 60));

                return "<b>{$name}</b>  -  Status: <b>{$enabled}</b> | Files: {$files} | Duration: {$size} minutes";
            }, $playlists);

            $return["Playlists"] = empty($playlists) ? "None" : join($plays_str, "<br>");

            $return["Streamer"] = (
                !$playing->getLive()->getIsLive()
                ? "Offline" : $playing->getLive()->getStreamerName()
            );
        }


    } catch (Exception $e) {
        logError(__FUNCTION__, $params, $e);
        $return["Error"] = "Failed to create full Admin Panel!";
        $return["Error Message"] = $e->getMessage();
    }

    return $return;
}

function azuracast_AdminServicesTabFieldsSave($params)
{
    $api = get_api($params);

    $station_id = to_id($params["model"]->serviceProperties->get(STATION_ID_FIELD));
    $role_id = to_id($params["model"]->serviceProperties->get(ROLE_ID_FIELD));

    $old_station_name = isset($_REQUEST['azuracast_old_station_name'])
        ? $_REQUEST['azuracast_old_station_name']
        : '';

    $new_station_name = isset($_REQUEST['azuracast_new_station_name'])
        ? $_REQUEST['azuracast_new_station_name']
        : '';

    if (!$new_station_name || $old_station_name == $new_station_name)
        return;


    // Rename station if necessary
    if (valid_id($station_id))
        try {
            $station_dto = $api->station($station_id)->get();
            if ($new_station_name != $station_dto->getName())
                rename_station($api, $station_id, $new_station_name);

        } catch (\Exception $e) {
            logError(__FUNCTION__, $params, $e);
        }

    // rename role if necessary
    if (valid_id($role_id))
        try {
            $role_dto = $api->admin()->roles()->get($role_id);
            if ($role_dto && $new_station_name != $role_dto->getName())
                rename_role($api, $role_dto, $new_station_name);

        } catch (\Exception $e) {
            logError(__FUNCTION__, $params, $e);
        }
}

function azuracast_AdminCustomButtonArray()
{
    return [
        "Search Account" => "useAccountWithEmail",
    ];
}

function azuracast_useAccountWithEmail($params)
{
    $api = get_api($params);
    $user_dto = search_user_by_email($api, $params["clientsdetails"]["email"]);

    if ($user_dto) {
        $params["model"]->serviceProperties->save([USER_ID_FIELD => $user_dto->getId()]);
    }

    return "success";
}

// **************************** HELPER FUNCTIONS ******************************


/**
 * @return string http[s]://serverhostname[:serverport]
 */
function get_host($params)
{
    return (
        ($params["serversecure"] ? "https://" : "http://")
        . $params["serverhostname"] // includes domain or ip
        . ($params["serverport"] ? ":" . $params["serverport"] : "")
    );
}


/**
 * @return Client
 */
function get_api($params)
{
    return Client::create(get_host($params), $params["serveraccesshash"]);
}


/**
 * @param Client $api
 * @param string $email
 *
 * @return ?UserDto
 */
function search_user_by_email($api, $email)
{
    try {
        $users = $api->admin()->users()->list();
        foreach ($users as $user_dto) {
            if ($email == $user_dto->getEmail())
                return $user_dto;
        }
    } catch (\Throwable $th) {
    }
    return null;
}

/**
 * @param Client $api
 * @param UserDto $user_dto
 * @param string[] $new_roles Roles to add to the user
 * @param bool $delete Delete all roles the user had previously
 *
 * @throws Exception
 */
function change_roles($api, $user_dto, $new_roles = [], $delete = false)
{
    $roles = array_merge(
        $new_roles,
        $delete ? [] : array_map(function ($role) {
            return strval($role->getId());
        }, $user_dto->getRoles())
    );
    $api->admin()->users()->update(
        $user_dto->getId(),
        $user_dto->getEmail(),
        $user_dto->getAuthPassword(),
        $user_dto->getName(),
        $user_dto->getLocale(),
        $user_dto->getTheme(),
        $roles,
        $user_dto->getApiKeys()
    );
}

/**
 * @param Client $api
 * @param int $user_id
 * @param string $password
 *
 * @throws Exception
 */
function change_password($api, $user_id, $password)
{
    $api->request("PUT", "admin/user/" . $user_id, [
        "json" => ["new_password" => $password]
    ]);
}


/**
 * @param Client $api
 * @param int $station_id
 * @param string $new_name
 *
 * @throws Exception
 */
function rename_station($api, $station_id, $new_name)
{
    $api->request("PUT", "admin/station/" . $station_id, [
        "json" => ["name" => $new_name]
    ]);
}

/**
 * @param Client $api
 * @param RoleDto $role_dto
 * @param string $new_name
 *
 * @throws Exception
 */
function rename_role($api, $role_dto, $new_name)
{
    $api->admin()->roles()->update(
        $role_dto->getId(),
        $new_name,
        $role_dto->getPermissions()->getGlobal(),
        $role_dto->getPermissions()->getStation()
    );
}

/**
 * @param Client $api
 * @param int $station_id
 * @param string $clone_name
 * @param string $clone_desc
 * @param string[] $clone_opts
 *
 * @throws Exception
 *
 * @return StationDto
 */
function clone_station(
    $api,
    $station_id,
    $clone_name,
    $clone_desc = "",
    $clone_opts = ["mounts", "streamers"]
) {
    $api->request(
        "POST",
        "admin/station/" . strval($station_id) . "/clone",
        [
            "json" => [
                "name" => $clone_name,
                "description" => $clone_desc,
                "clone" => $clone_opts
            ]
        ]
    );

    $station_list = array_reverse($api->stations());
    foreach ($station_list as $station_dto) {
        if ($station_dto->getName() == $clone_name) {
            return $station_dto;
        }
    }
    throw new Exception("Station cloned was not found in the station list");
}


/**
 * @param string $function The value of __FUNCTION__
 * @param array $params
 * @param Exception $e
 */
function logError($function, $params, $e)
{
    logModuleCall(
        'azuracast',
        $function,
        $params,
        $e->getMessage(),
        $e->getTraceAsString()
    );
}

/**
 * @param int|string|null $id
 * @return ?int
 */
function to_id($id)
{
    return is_int($id) ? $id : ($id == "" || $id == null ? null : intval($id));
}

/**
 * @param mixed $id
 * @return bool
 */
function valid_id($id)
{
    return is_int($id);
}
