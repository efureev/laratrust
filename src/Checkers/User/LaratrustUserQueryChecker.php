<?php

namespace Laratrust\Checkers\User;

use Laratrust\Helper;
use Illuminate\Support\Facades\Config;

class LaratrustUserQueryChecker extends LaratrustUserChecker
{
    /**
     * Checks if the user has a role by its name.
     *
     * @param  string|bool   $team      Team name.
     * @return array
     */
    public function getCurrentUserRoles($team = null)
    {
        if (config('laratrust.use_teams') === false) {
            return $this->user->roles->pluck(Helper::getRoleKeyAttributeName())->toArray();
        }

        if ($team === null && config('laratrust.teams_strict_check') === false) {
            return $this->user->roles->pluck(Helper::getRoleKeyAttributeName())->toArray();
        }

        if ($team === null) {
            return $this->user
                ->roles()
                ->wherePivot(config('laratrust.foreign_keys.team'), null)
                ->pluck(Helper::getRoleKeyAttributeName())
                ->toArray();
        }

        $teamId = Helper::fetchTeam($team);

        return $this->user
            ->roles()
            ->wherePivot(config('laratrust.foreign_keys.team'), $teamId)
            ->pluck(Helper::getRoleKeyAttributeName())
            ->toArray();
    }

    /**
     * Checks if the user has a role by its name.
     *
     * @param  string|array  $name       Role name or array of role names.
     * @param  string|bool   $team      Team name or requiredAll roles.
     * @param  bool          $requireAll All roles in the array are required.
     * @return bool
     */
    public function currentUserHasRole($name, $teams = null, $requireAll = false)
    {
        if (empty($name)) {
            return true;
        }

        $name = Helper::standardize($name);
        $rolesNames = is_array($name) ? $name : [$name];
        [$teams, $requireAll] = Helper::assignRealValuesTo($teams, $requireAll, 'is_bool');
        $useTeams = Config::get('laratrust.use_teams');
        $teamStrictCheck = Config::get('laratrust.teams_strict_check');

        $rolesCount = $this->user->roles()
            ->whereIn(Helper::getRoleKeyAttributeName(), $rolesNames)
            ->when($useTeams && ($teamStrictCheck || ! $teams || $teams !== '0'), function ($query) use ($teams) {
                $teamIds = Helper::fetchTeams($teams);

                return $query->whereIn(Config::get('laratrust.foreign_keys.team'), $teamIds);
            })
            ->count();

        return $requireAll ? $rolesCount == count($rolesNames) : $rolesCount > 0;
    }

    /**
     * Check if user has a permission by its name.
     *
     * @param  string|array  $permission Permission string or array of permissions.
     * @param  string|bool  $team      Team name or requiredAll roles.
     * @param  bool  $requireAll All roles in the array are required.
     * @return bool
     */
    public function currentUserHasPermission($permission, $teams = null, $requireAll = false)
    {
        if (empty($permission)) {
            return true;
        }

        $permission = Helper::standardize($permission);
        $permissionsNames = is_array($permission) ? $permission : [$permission];
        [$teams, $requireAll] = Helper::assignRealValuesTo($teams, $requireAll, 'is_bool');
        $useTeams = Config::get('laratrust.use_teams');
        $teamStrictCheck = Config::get('laratrust.teams_strict_check');

        $permAttrName = Helper::getPermissionKeyAttributeName();

        list($permissionsWildcard, $permissionsNoWildcard) =
            Helper::getPermissionWithAndWithoutWildcards($permissionsNames);

        $rolesPermissionsCount = $this->user->roles()
            ->withCount(['permissions' =>
                function ($query) use ($permissionsNoWildcard, $permissionsWildcard, $permAttrName) {
                    $query->whereIn($permAttrName, $permissionsNoWildcard);
                    foreach ($permissionsWildcard as $permission) {
                        $query->orWhere($permAttrName, 'like', $permission);
                    }
                }
            ])
            ->when($useTeams && ($teamStrictCheck || ! $teams), function ($query) use ($teams) {
                $teamIds = Helper::fetchTeams($teams);

                return $query->whereIn(Config::get('laratrust.foreign_keys.team'), $teamIds);
            })
            ->pluck('permissions_count')
            ->sum();

        $directPermissionsCount = $this->user->permissions()
            ->whereIn($permAttrName, $permissionsNoWildcard)
            ->when($permissionsWildcard, function ($query) use ($permissionsWildcard, $permAttrName) {
                foreach ($permissionsWildcard as $permission) {
                    $query->orWhere($permAttrName, 'like', $permission);
                }

                return $query;
            })
            ->when($useTeams && ($teamStrictCheck || ! $teams), function ($query) use ($teams) {
                $teamIds = Helper::fetchTeams($teams);

                return $query->whereIn(Config::get('laratrust.foreign_keys.team'), $teamIds);
            })
            ->count();

        return $requireAll
            ? $rolesPermissionsCount + $directPermissionsCount >= count($permissionsNames)
            : $rolesPermissionsCount + $directPermissionsCount > 0;
    }

    public function currentUserFlushCache()
    {
    }
}
